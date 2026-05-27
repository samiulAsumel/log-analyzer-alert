#!/usr/bin/env bash
# modules/analyze_nginx.sh — Nginx Access & Error Log Analyzer  v1.0.0
# Sourced by log_analyzer.sh.
# Detects: 5xx spikes, 404 storms (scanners), slow responses, DDoS patterns,
#          suspicious user-agents, error-level entries.
# set -euo pipefail is inherited.

module_analyze_nginx() {
    log "INFO" "NGINX" "Analyzing nginx logs"
    _nginx_access
    _nginx_error
    log "INFO" "NGINX" "Nginx analysis complete"
}

# ── Access log analysis ────────────────────────────────────────────────────────
_nginx_access() {
    local logfile="${NGINX_ACCESS:-/var/log/nginx/access.log}"
    [[ -f "$logfile" ]] || { log "WARN" "NGINX" "Access log not found: ${logfile}"; return 0; }

    local new_lines
    new_lines=$(read_new_lines "$logfile" 2>/dev/null) || {
        log "WARN" "NGINX" "Could not read ${logfile}"; return 0
    }
    [[ -z "$new_lines" ]] && { log "INFO" "NGINX" "No new access log entries"; return 0; }

    local tmp_file
    tmp_file=$(mktemp /tmp/la_nginx_access_XXXXXX)
    echo "$new_lines" > "$tmp_file"
    trap '[[ -n "${tmp_file:-}" ]] && rm -f "$tmp_file"' RETURN

    local total_reqs
    total_reqs=$(wc -l < "$tmp_file")
    log "INFO" "NGINX" "Analyzing ${total_reqs} new access log line(s)"

    # ── 5xx error rate ─────────────────────────────────────────────────────
    # Standard nginx log format: IP - - [date] "METHOD /path HTTP/x.x" STATUS size
    local count_5xx
    count_5xx=$(awk '$9 ~ /^5[0-9][0-9]$/' "$tmp_file" | wc -l; true)
    if (( count_5xx >= MAX_5XX_COUNT )); then
        local top_5xx_urls
        top_5xx_urls=$(awk '$9 ~ /^5[0-9][0-9]$/ {print $9, $7}' "$tmp_file" \
            | sort | uniq -c | sort -rn | head -5 \
            | awk '{printf "%s %s×%d; ", $2, $3, $1}')
        add_finding "CRITICAL" "NGINX" \
            "5xx error spike (${count_5xx} errors in ${CHECK_INTERVAL} min)" \
            "Top: ${top_5xx_urls}"
    elif (( count_5xx > 0 )); then
        add_finding "MEDIUM" "NGINX" \
            "5xx errors detected" \
            "${count_5xx} server error(s) in last ${CHECK_INTERVAL} min"
    fi

    # ── 404 storm — per IP ─────────────────────────────────────────────────
    local ip_404_counts
    ip_404_counts=$(awk '$9 == "404" {print $1}' "$tmp_file" \
        | sort | uniq -c | sort -rn)

    if [[ -n "$ip_404_counts" ]]; then
        while IFS= read -r line; do
            local cnt ip
            cnt=$(echo "$line" | awk '{print $1}')
            ip=$(echo "$line"  | awk '{print $2}')
            [[ -z "$ip" ]] && continue

            # Skip whitelisted
            local wl=false
            for wip in ${WHITELIST_IPS:-127.0.0.1 ::1}; do
                [[ "$ip" == "$wip" ]] && { wl=true; break; }
            done
            $wl && continue

            if (( cnt >= MAX_404_PER_IP )); then
                local top_paths
                top_paths=$(awk -v ip="$ip" '$1==ip && $9=="404" {print $7}' "$tmp_file" \
                    | sort | uniq -c | sort -rn | head -3 \
                    | awk '{printf "%s(%d); ", $2, $1}')
                add_finding "HIGH" "NGINX" \
                    "404 storm / directory scanner: ${ip}" \
                    "${cnt} 404s — paths: ${top_paths}"
            fi
        done <<< "$ip_404_counts"
    fi

    # ── High request rate per IP (DDoS/flood indicator) ───────────────────
    local top_ips
    top_ips=$(awk '{print $1}' "$tmp_file" \
        | sort | uniq -c | sort -rn | head -3)
    local ddos_threshold=$(( total_reqs / 3 ))   # single IP >33% of traffic
    if [[ -n "$top_ips" ]]; then
        while IFS= read -r line; do
            local cnt ip
            cnt=$(echo "$line" | awk '{print $1}')
            ip=$(echo "$line"  | awk '{print $2}')
            [[ -z "$ip" ]] && continue
            if (( cnt > ddos_threshold && cnt > 100 )); then
                add_finding "HIGH" "NGINX" \
                    "High request rate from single IP: ${ip}" \
                    "${cnt} requests (${cnt}/${total_reqs} = $(( cnt * 100 / total_reqs ))% of traffic)"
            fi
        done <<< "$top_ips"
    fi

    # ── Slow requests (from $request_time if present in log format) ───────
    # Nginx must log $request_time as the last numeric field.
    # We look for lines where last field looks like a decimal > threshold seconds.
    local slow_thresh_s
    slow_thresh_s=$(echo "scale=3; ${MAX_RESPONSE_MS:-5000}/1000" | bc -l 2>/dev/null || echo "5.000")
    local slow_count
    slow_count=$(awk -v t="$slow_thresh_s" \
        'NF>0 && $NF+0 > t+0 && $NF ~ /^[0-9]+\.[0-9]+$/' "$tmp_file" | wc -l; true)
    if (( slow_count > 0 )); then
        local worst
        worst=$(awk '$NF ~ /^[0-9]+\.[0-9]+$/ {print $NF, $7}' "$tmp_file" \
            | sort -rn | head -3 | awk '{printf "%ss %s; ", $1, $2}')
        add_finding "MEDIUM" "NGINX" \
            "Slow requests detected" \
            "${slow_count} request(s) > ${MAX_RESPONSE_MS:-5000}ms — worst: ${worst}"
    fi

    # ── Suspicious user-agents ─────────────────────────────────────────────
    local bad_ua_count
    bad_ua_count=$(grep -cEi \
        'sqlmap|nikto|nmap|masscan|zgrab|python-requests/2\.[01]|Go-http-client/1\.1|curl/[0-6]\.|wget/1\.[01][0-9]\.|dirbuster|gobuster|wfuzz|hydra|burpsuite|nessus|openvas|acunetix' \
        "$tmp_file" 2>/dev/null; true)
    if (( bad_ua_count > 0 )); then
        local bad_uas
        bad_uas=$(grep -Eo '"[^"]*"' "$tmp_file" | sort | uniq -c | sort -rn | head -3 \
            | awk '{$1=$1; print}' | tr '\n' ' ')
        add_finding "HIGH" "NGINX" \
            "Suspicious scanner user-agent detected" \
            "${bad_ua_count} request(s) with scanner/exploit tool UA"
    fi

    # ── POST flood ────────────────────────────────────────────────────────
    local post_count
    post_count=$(awk '$6 == "\"POST"' "$tmp_file" | wc -l; true)
    local post_thresh=$(( total_reqs / 2 ))
    if (( post_count > 200 && post_count > post_thresh )); then
        add_finding "MEDIUM" "NGINX" \
            "Unusual POST request volume" \
            "${post_count} POST requests ($(( post_count * 100 / (total_reqs + 1) ))% of traffic)"
    fi
}

# ── Error log analysis ─────────────────────────────────────────────────────────
_nginx_error() {
    local logfile="${NGINX_ERROR:-/var/log/nginx/error.log}"
    [[ -f "$logfile" ]] || { log "WARN" "NGINX" "Error log not found: ${logfile}"; return 0; }

    local new_lines
    new_lines=$(read_new_lines "$logfile" 2>/dev/null) || {
        log "WARN" "NGINX" "Could not read ${logfile}"; return 0
    }
    [[ -z "$new_lines" ]] && return 0

    local tmp_file
    tmp_file=$(mktemp /tmp/la_nginx_err_XXXXXX)
    echo "$new_lines" > "$tmp_file"
    trap '[[ -n "${tmp_file:-}" ]] && rm -f "$tmp_file"' RETURN

    # Nginx error levels: debug info notice warn error crit alert emerg
    local crit_count
    crit_count=$(grep -cEi '\[crit\]|\[alert\]|\[emerg\]' "$tmp_file" 2>/dev/null; true)
    if (( crit_count > 0 )); then
        local crit_sample
        crit_sample=$(grep -Ei '\[crit\]|\[alert\]|\[emerg\]' "$tmp_file" \
            | tail -3 | cut -c1-160 | tr '\n' '|')
        add_finding "HIGH" "NGINX" \
            "Nginx critical/alert/emerg errors" \
            "${crit_count} error(s) — ${crit_sample}"
    fi

    local err_count
    err_count=$(grep -cEi '\[error\]' "$tmp_file" 2>/dev/null; true)
    if (( err_count > 10 )); then
        local top_errors
        top_errors=$(grep -Ei '\[error\]' "$tmp_file" \
            | grep -oE '\[error\].*' | sort | uniq -c | sort -rn | head -3 \
            | awk '{$1=$1; print}' | tr '\n' ' | ')
        add_finding "MEDIUM" "NGINX" \
            "Nginx error log spike" \
            "${err_count} [error] entries — top: ${top_errors}"
    fi

    # Upstream errors (backend down)
    local upstream_err
    upstream_err=$(grep -cEi "upstream.*failed|upstream.*timed out|connect\(\) failed" \
        "$tmp_file" 2>/dev/null; true)
    if (( upstream_err > 0 )); then
        local up_hosts
        up_hosts=$(grep -Ei "upstream.*failed|upstream.*timed out" "$tmp_file" \
            | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+' \
            | sort -u | head -5 | tr '\n' ' ')
        add_finding "HIGH" "NGINX" \
            "Upstream backend failures" \
            "${upstream_err} upstream failure(s) — backends: ${up_hosts}"
    fi
}
