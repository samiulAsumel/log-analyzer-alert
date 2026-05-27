#!/usr/bin/env bash
# modules/analyze_auth.sh — SSH / Auth Log Analyzer  v1.0.0
# Sourced by log_analyzer.sh.
# Detects: brute-force SSH, invalid users, root login, sudo escalations.
# set -euo pipefail is inherited.

module_analyze_auth() {
    local logfile="${AUTH_LOG:-/var/log/secure}"
    log "INFO" "AUTH" "Analyzing: ${logfile}"

    # Read only new lines since last run
    local new_lines
    new_lines=$(read_new_lines "$logfile" 2>/dev/null) || {
        log "WARN" "AUTH" "Could not read ${logfile}"
        return 0
    }

    [[ -z "$new_lines" ]] && { log "INFO" "AUTH" "No new auth log entries"; return 0; }

    local tmp_file
    tmp_file=$(mktemp /tmp/la_auth_XXXXXX)
    echo "$new_lines" > "$tmp_file"
    trap '[[ -n "${tmp_file:-}" ]] && rm -f "$tmp_file"' RETURN

    # ── Failed password attempts: count per IP ─────────────────────────────
    # Log line: "Failed password for [invalid user] USER from IP port PORT ssh2"
    local failed_ip_counts
    failed_ip_counts=$(grep -iE "Failed password" "$tmp_file" \
        | grep -oE 'from [0-9a-f:.]+' \
        | awk '{print $2}' \
        | sort | uniq -c | sort -rn)

    if [[ -n "$failed_ip_counts" ]]; then
        while IFS= read -r line; do
            local count ip
            count=$(echo "$line" | awk '{print $1}')
            ip=$(echo "$line" | awk '{print $2}')

            [[ -z "$ip" ]] && continue

            # Skip whitelisted IPs
            local whitelisted=false
            for wip in ${WHITELIST_IPS:-127.0.0.1 ::1}; do
                [[ "$ip" == "$wip" ]] && { whitelisted=true; break; }
            done
            $whitelisted && continue

            if (( count >= MAX_FAILED_LOGINS )); then
                add_finding "CRITICAL" "AUTH" \
                    "Brute-force SSH from ${ip}" \
                    "${count} failed logins in last ${CHECK_INTERVAL} min"

                # Optional auto-block
                if [[ "${AUTO_BLOCK_IP:-false}" == "true" ]] && ! ${DRY_RUN:-false}; then
                    _block_ip "$ip"
                fi
            elif (( count >= 3 )); then
                add_finding "HIGH" "AUTH" \
                    "Repeated SSH failures from ${ip}" \
                    "${count} failed attempts"
            fi
        done <<< "$failed_ip_counts"
    fi

    # ── Invalid user attempts ──────────────────────────────────────────────
    local invalid_count
    invalid_count=$(grep -cE "Invalid user" "$tmp_file" 2>/dev/null; true)
    if (( invalid_count > 0 )); then
        local top_users
        top_users=$(grep -E "Invalid user" "$tmp_file" \
            | grep -oE "Invalid user \S+" \
            | sort | uniq -c | sort -rn | head -5 \
            | awk '{printf "%s×%s ", $1, $2}')
        add_finding "HIGH" "AUTH" \
            "Invalid user login attempts detected" \
            "${invalid_count} attempts — top users: ${top_users}"
    fi

    # ── Root login ─────────────────────────────────────────────────────────
    local root_logins
    root_logins=$(grep -cE "Accepted .+ for root from" "$tmp_file" 2>/dev/null; true)
    if (( root_logins > 0 )); then
        local root_ips
        root_ips=$(grep -E "Accepted .+ for root from" "$tmp_file" \
            | grep -oE 'from [0-9a-f:.]+' | awk '{print $2}' | sort -u | tr '\n' ' ')
        add_finding "CRITICAL" "AUTH" \
            "Root SSH login detected" \
            "${root_logins} successful root login(s) from: ${root_ips}"
    fi

    # ── Failed root login attempts ─────────────────────────────────────────
    local root_fail
    root_fail=$(grep -cE "Failed .+ for root from" "$tmp_file" 2>/dev/null; true)
    if (( root_fail > 0 )); then
        add_finding "HIGH" "AUTH" \
            "Root SSH brute-force" \
            "${root_fail} failed root login attempt(s)"
    fi

    # ── Sudo privilege escalations ─────────────────────────────────────────
    local sudo_events
    sudo_events=$(grep -E "sudo:.+COMMAND=" "$tmp_file" | wc -l; true)
    if (( sudo_events > 0 )); then
        local sudo_users
        sudo_users=$(grep -E "sudo:.+COMMAND=" "$tmp_file" \
            | grep -oE '^\S+ \S+ \S+' | awk '{print $3}' \
            | sort -u | tr '\n' ' ')
        add_finding "LOW" "AUTH" \
            "Sudo privilege escalations" \
            "${sudo_events} sudo command(s) by: ${sudo_users}"
    fi

    # ── Sudo authentication failures ──────────────────────────────────────
    local sudo_fail
    sudo_fail=$(grep -cE "sudo:.*authentication failure" "$tmp_file" 2>/dev/null; true)
    if (( sudo_fail > 0 )); then
        add_finding "MEDIUM" "AUTH" \
            "Sudo authentication failures" \
            "${sudo_fail} failed sudo attempt(s)"
    fi

    # ── New user/group creation ────────────────────────────────────────────
    local new_users
    new_users=$(grep -cE "new user:|new group:|useradd" "$tmp_file" 2>/dev/null; true)
    if (( new_users > 0 )); then
        local user_names
        user_names=$(grep -E "new user:" "$tmp_file" \
            | grep -oE "name=\S+" | sed 's/name=//' | tr '\n' ' ')
        add_finding "MEDIUM" "AUTH" \
            "New user/group created" \
            "${new_users} account change(s): ${user_names}"
    fi

    # ── PAM/authentication failures (non-SSH) ────────────────────────────
    local pam_fail
    pam_fail=$(grep -cE "authentication failure" "$tmp_file" 2>/dev/null; true)
    if (( pam_fail > 5 )); then
        add_finding "MEDIUM" "AUTH" \
            "PAM authentication failures" \
            "${pam_fail} auth failure(s) in log segment"
    fi

    log "INFO" "AUTH" "Auth analysis complete"
}

# ── IP blocking helper ────────────────────────────────────────────────────────
_block_ip() {
    local ip="$1"
    local block_log="${BLOCK_LOG:-/var/lib/loganalyzer/blocked_ips.log}"

    # Check if already blocked
    if grep -q "^${ip} " "$block_log" 2>/dev/null; then
        log "INFO" "AUTH" "IP ${ip} already blocked — skipping"
        return 0
    fi

    # firewalld
    if command -v firewall-cmd &>/dev/null; then
        firewall-cmd --permanent --zone="${BLOCK_ZONE:-public}" \
            --add-rich-rule="rule family='ipv4' source address='${ip}' reject" &>/dev/null \
        && firewall-cmd --reload &>/dev/null \
        && {
            echo "${ip} $(date '+%Y-%m-%d %H:%M:%S') firewalld" >> "$block_log"
            log "OK" "AUTH" "Blocked IP ${ip} via firewalld (zone: ${BLOCK_ZONE:-public})"
        }
        return 0
    fi

    # hosts.deny fallback
    if [[ "${HOSTS_DENY:-false}" == "true" ]]; then
        echo "ALL: ${ip}" >> /etc/hosts.deny
        echo "${ip} $(date '+%Y-%m-%d %H:%M:%S') hosts.deny" >> "$block_log"
        log "OK" "AUTH" "Blocked IP ${ip} via /etc/hosts.deny"
        return 0
    fi

    log "WARN" "AUTH" "Cannot block ${ip}: firewalld not found and HOSTS_DENY=false"
}
