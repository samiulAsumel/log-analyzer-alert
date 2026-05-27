#!/usr/bin/env bash
# modules/detect_threats.sh — Cross-Log Threat Detector  v1.0.0
# Sourced by log_analyzer.sh.
# Cross-correlates findings from all modules to detect coordinated attacks.
# Assigns composite threat level: low / medium / high / critical.
# set -euo pipefail is inherited.

module_detect_threats() {
    log "INFO" "THREATS" "Cross-correlating findings for threat detection"

    [[ ${#ALL_FINDINGS[@]} -eq 0 ]] && {
        log "INFO" "THREATS" "No findings to correlate"
        return 0
    }

    # ── Build per-IP lists from existing findings ─────────────────────────
    # Extract IPs mentioned in findings
    local all_findings_text
    all_findings_text=$(printf '%s\n' "${ALL_FINDINGS[@]:-}")

    local auth_ips nginx_ips
    auth_ips=$(echo "$all_findings_text" \
        | grep -Ei "^CRITICAL\|AUTH\|Brute-force|^HIGH\|AUTH\|Repeated SSH" \
        | grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' \
        | sort -u)
    nginx_ips=$(echo "$all_findings_text" \
        | grep -Ei "^HIGH\|NGINX\|404 storm|^HIGH\|NGINX\|High request rate" \
        | grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' \
        | sort -u)

    # ── Correlation 1: Same IP in both auth + nginx logs ──────────────────
    if [[ -n "$auth_ips" && -n "$nginx_ips" ]]; then
        while IFS= read -r ip; do
            if echo "$nginx_ips" | grep -qF "$ip"; then
                add_finding "CRITICAL" "THREATS" \
                    "Persistent attacker detected: ${ip}" \
                    "IP ${ip} appears in BOTH SSH brute-force AND web scanner findings — coordinated attack likely"
            fi
        done <<< "$auth_ips"
    fi

    # ── Correlation 2: Multiple services failing simultaneously ────────────
    # Check: auth HIGH/CRITICAL + nginx HIGH/CRITICAL + system HIGH/CRITICAL
    local auth_critical nginx_critical sys_critical
    auth_critical=$(echo "$all_findings_text" | grep -cE "^(CRITICAL|HIGH)\|AUTH\|" 2>/dev/null; true)
    nginx_critical=$(echo "$all_findings_text" | grep -cE "^(CRITICAL|HIGH)\|NGINX\|" 2>/dev/null; true)
    sys_critical=$(echo "$all_findings_text" | grep -cE "^(CRITICAL|HIGH)\|SYSTEM\|" 2>/dev/null; true)

    local multi_service_fail=$(( (auth_critical > 0 ? 1 : 0) + (nginx_critical > 0 ? 1 : 0) + (sys_critical > 0 ? 1 : 0) ))
    if (( multi_service_fail >= 3 )); then
        add_finding "CRITICAL" "THREATS" \
            "Multi-service failure — possible intrusion or infrastructure attack" \
            "Simultaneous HIGH/CRITICAL findings in: AUTH + NGINX + SYSTEM — investigate immediately"
    elif (( multi_service_fail == 2 )); then
        add_finding "HIGH" "THREATS" \
            "Multiple service anomalies detected simultaneously" \
            "High/critical findings across $(( multi_service_fail )) service categories — possible attack or cascade failure"
    fi

    # ── Correlation 3: OOM + App crash = likely application overload ───────
    local oom_found app_crit_found
    oom_found=$(echo "$all_findings_text" | grep -cEi "\|SYSTEM\|Out-of-Memory" 2>/dev/null; true)
    app_crit_found=$(echo "$all_findings_text" | grep -cEi "\|APP\|CRITICAL" 2>/dev/null; true)
    if (( oom_found > 0 && app_crit_found > 0 )); then
        add_finding "CRITICAL" "THREATS" \
            "Application overload: OOM + App crash detected together" \
            "System ran out of memory while app reported critical errors — possible memory leak or traffic storm"
    fi

    # ── Correlation 4: Brute-force escalation pattern ─────────────────────
    # Auth failures + new user creation = possible successful compromise
    local brute_found new_user_found
    brute_found=$(echo "$all_findings_text" | grep -cEi "\|AUTH\|Brute-force" 2>/dev/null; true)
    new_user_found=$(echo "$all_findings_text" | grep -cEi "\|AUTH\|New user" 2>/dev/null; true)
    if (( brute_found > 0 && new_user_found > 0 )); then
        add_finding "CRITICAL" "THREATS" \
            "Possible account compromise: brute-force followed by user creation" \
            "SSH brute-force AND new user account creation detected in same interval — verify account legitimacy"
    fi

    # ── Correlation 5: Disk full + DB error = data integrity risk ─────────
    local disk_found db_found
    disk_found=$(echo "$all_findings_text" | grep -cEi "\|SYSTEM\|Disk full" 2>/dev/null; true)
    db_found=$(echo "$all_findings_text" | grep -cEi "\|MYSQL\|" 2>/dev/null; true)
    if (( disk_found > 0 && db_found > 0 )); then
        add_finding "CRITICAL" "THREATS" \
            "Disk full + Database errors: DATA INTEGRITY RISK" \
            "Server disk full while database is logging errors — immediate disk cleanup required to prevent data loss"
    fi

    # ── Correlation 6: Nginx scanner + Auth failures = reconnaissance ─────
    local scanner_found
    scanner_found=$(echo "$all_findings_text" | grep -cEi "\|NGINX\|scanner\|\|NGINX\|404 storm" 2>/dev/null; true)
    if (( scanner_found > 0 && auth_critical > 0 )); then
        add_finding "HIGH" "THREATS" \
            "Active reconnaissance detected" \
            "Web scanning AND SSH brute-force from this interval — target is actively being probed"
    fi

    # ── Composite threat score ────────────────────────────────────────────
    local threat_score=$(( CRITICAL_COUNT * 4 + HIGH_COUNT * 2 + MEDIUM_COUNT ))
    local threat_level
    if   (( threat_score >= 12 )); then threat_level="CRITICAL"
    elif (( threat_score >= 6  )); then threat_level="HIGH"
    elif (( threat_score >= 3  )); then threat_level="MEDIUM"
    elif (( threat_score >= 1  )); then threat_level="LOW"
    else threat_level="CLEAN"
    fi

    log "INFO" "THREATS" "Composite threat score: ${threat_score} → level: ${threat_level}"

    if [[ "$threat_level" == "CLEAN" ]]; then
        log "OK" "THREATS" "No correlated threats detected"
    fi

    # ── External IPs appearing across multiple log sources ────────────────
    # Scan all NEW log lines for repeated suspicious IPs across log files
    _cross_log_ip_scan

    log "INFO" "THREATS" "Threat detection complete"
}

# ── Cross-log IP scanning ─────────────────────────────────────────────────────
_cross_log_ip_scan() {
    local ip_freq_file
    ip_freq_file=$(mktemp /tmp/la_threat_ips_XXXXXX)
    trap '[[ -n "${ip_freq_file:-}" ]] && rm -f "$ip_freq_file"' RETURN

    local logs_to_scan=(
        "${AUTH_LOG:-/var/log/secure}"
        "${NGINX_ACCESS:-/var/log/nginx/access.log}"
        "${SYSLOG:-/var/log/messages}"
    )

    local found_ips=()
    for logfile in "${logs_to_scan[@]}"; do
        [[ -f "$logfile" ]] || continue
        # Extract recent lines (last 500 per file for cross-correlation)
        tail -500 "$logfile" 2>/dev/null \
            | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' \
            | grep -vE '^(127\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|0\.0\.0\.0|255\.)' \
            >> "$ip_freq_file" || true
    done

    # Find external IPs appearing 10+ times across all logs combined
    local suspicious_ips
    suspicious_ips=$(sort "$ip_freq_file" | uniq -c | sort -rn \
        | awk '$1 >= 10 {print $1, $2}' | head -10)

    if [[ -n "$suspicious_ips" ]]; then
        local ip_list
        ip_list=$(echo "$suspicious_ips" | awk '{printf "%s(%d) ", $2, $1}')
        add_finding "MEDIUM" "THREATS" \
            "Frequently appearing external IP(s) across multiple logs" \
            "IPs: ${ip_list} — review access patterns"
    fi
}
