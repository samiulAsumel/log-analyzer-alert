#!/usr/bin/env bash
# modules/analyze_mysql.sh — MySQL / MariaDB Log Analyzer  v1.0.0
# Sourced by log_analyzer.sh.
# Detects: slow queries, connection limits, replication errors, table corruption.
# set -euo pipefail is inherited.

module_analyze_mysql() {
    log "INFO" "MYSQL" "Analyzing MySQL/MariaDB logs"
    _mysql_error_log
    _mysql_slow_log
    log "INFO" "MYSQL" "MySQL analysis complete"
}

# ── Error log ─────────────────────────────────────────────────────────────────
_mysql_error_log() {
    local logfile="${MYSQL_ERROR:-/var/log/mysql/error.log}"
    [[ -f "$logfile" ]] || { log "WARN" "MYSQL" "Error log not found: ${logfile}"; return 0; }

    local new_lines
    new_lines=$(read_new_lines "$logfile" 2>/dev/null) || {
        log "WARN" "MYSQL" "Could not read ${logfile}"; return 0
    }
    [[ -z "$new_lines" ]] && { log "INFO" "MYSQL" "No new MySQL error log entries"; return 0; }

    local tmp_file
    tmp_file=$(mktemp /tmp/la_mysql_err_XXXXXX)
    echo "$new_lines" > "$tmp_file"
    trap '[[ -n "${tmp_file:-}" ]] && rm -f "$tmp_file"' RETURN

    # ── Replication errors ─────────────────────────────────────────────────
    local repl_errors
    repl_errors=$(grep -cEi "Slave.*error|Replication.*error|Error_code|Got fatal error.*from master|Relay log read failure" \
        "$tmp_file" 2>/dev/null; true)
    if (( repl_errors > 0 )); then
        local repl_msg
        repl_msg=$(grep -Ei "Slave.*error|Replication.*error|Got fatal error" "$tmp_file" \
            | tail -2 | cut -c1-200 | tr '\n' '|')
        add_finding "CRITICAL" "MYSQL" \
            "MySQL replication error(s)" \
            "${repl_errors} error(s) — ${repl_msg}"
    fi

    # ── Table corruption ───────────────────────────────────────────────────
    local corruption
    corruption=$(grep -cEi "table.*corrupt|Incorrect key file|Can't open file.*errno|crashed.*needs repair|Table.*marked as crashed" \
        "$tmp_file" 2>/dev/null; true)
    if (( corruption > 0 )); then
        local corrupt_tables
        corrupt_tables=$(grep -Ei "corrupt|crashed" "$tmp_file" \
            | grep -oE "'\S+'" | sort -u | head -5 | tr '\n' ' ')
        add_finding "CRITICAL" "MYSQL" \
            "Table corruption detected" \
            "${corruption} event(s) — tables: ${corrupt_tables}"
    fi

    # ── Connection limit ───────────────────────────────────────────────────
    local conn_limit
    conn_limit=$(grep -cEi "Too many connections|max_connections|Connection limit reached" \
        "$tmp_file" 2>/dev/null; true)
    if (( conn_limit > 0 )); then
        # Try to get current connection count
        local conn_info
        conn_info="check: SHOW STATUS LIKE 'Threads_connected';"
        add_finding "HIGH" "MYSQL" \
            "MySQL connection limit hit" \
            "${conn_limit} event(s) — ${conn_info}"
    fi

    # ── InnoDB errors ─────────────────────────────────────────────────────
    local innodb_err
    innodb_err=$(grep -cEi "InnoDB: Fatal error|InnoDB: Error|InnoDB: Unable|innodb_force_recovery" \
        "$tmp_file" 2>/dev/null; true)
    if (( innodb_err > 0 )); then
        local innodb_msg
        innodb_msg=$(grep -Ei "InnoDB: Fatal|InnoDB: Error" "$tmp_file" \
            | tail -2 | cut -c1-160 | tr '\n' '|')
        add_finding "CRITICAL" "MYSQL" \
            "InnoDB fatal error" \
            "${innodb_err} InnoDB error(s) — ${innodb_msg}"
    fi

    # ── Disk space ────────────────────────────────────────────────────────
    local disk_err
    disk_err=$(grep -cEi "No space left on device|can't create.*file.*errno 28|write.*Errcode.*28" \
        "$tmp_file" 2>/dev/null; true)
    if (( disk_err > 0 )); then
        add_finding "CRITICAL" "MYSQL" \
            "MySQL disk space error" \
            "${disk_err} write failure(s) — disk may be full"
    fi

    # ── Aborted connections ────────────────────────────────────────────────
    local aborted
    aborted=$(grep -cEi "Aborted connection|Got an error reading communication packets|Got timeout reading communication packets" \
        "$tmp_file" 2>/dev/null; true)
    if (( aborted > 20 )); then
        add_finding "MEDIUM" "MYSQL" \
            "High aborted connection count" \
            "${aborted} aborted connection(s) — check app connection pool"
    fi

    # ── General warnings/errors ────────────────────────────────────────────
    local gen_errors
    gen_errors=$(grep -cEi "\[ERROR\]|\[FATAL\]" "$tmp_file" 2>/dev/null; true)
    if (( gen_errors > 5 )); then
        local top_errs
        top_errs=$(grep -Ei "\[ERROR\]|\[FATAL\]" "$tmp_file" \
            | awk -F'\[ERROR\]|\[FATAL\]' '{print $2}' \
            | sort | uniq -c | sort -rn | head -3 \
            | awk '{$1=$1; print}' | tr '\n' '|')
        add_finding "MEDIUM" "MYSQL" \
            "MySQL error log spike" \
            "${gen_errors} error/fatal entries — ${top_errs}"
    fi
}

# ── Slow query log ────────────────────────────────────────────────────────────
_mysql_slow_log() {
    local logfile="${MYSQL_SLOW:-/var/log/mysql/slow.log}"
    [[ -f "$logfile" ]] || { log "INFO" "MYSQL" "Slow query log not found: ${logfile} (optional)"; return 0; }

    local new_lines
    new_lines=$(read_new_lines "$logfile" 2>/dev/null) || {
        log "WARN" "MYSQL" "Could not read ${logfile}"; return 0
    }
    [[ -z "$new_lines" ]] && return 0

    local tmp_file
    tmp_file=$(mktemp /tmp/la_mysql_slow_XXXXXX)
    echo "$new_lines" > "$tmp_file"
    trap '[[ -n "${tmp_file:-}" ]] && rm -f "$tmp_file"' RETURN

    # Count slow query entries (each starts with "# Time:" or "# User@Host:")
    local slow_count
    slow_count=$(grep -c "^# User@Host:" "$tmp_file" 2>/dev/null; true)

    if (( slow_count >= MAX_SLOW_QUERIES )); then
        # Find worst query times
        local worst_times
        worst_times=$(grep "^# Query_time:" "$tmp_file" \
            | awk '{print $3}' | sort -rn | head -5 \
            | tr '\n' 's ')
        add_finding "HIGH" "MYSQL" \
            "Slow query threshold exceeded" \
            "${slow_count} slow queries (threshold: ${MAX_SLOW_QUERIES}) — worst: ${worst_times}"
    elif (( slow_count > 0 )); then
        local avg_time
        avg_time=$(grep "^# Query_time:" "$tmp_file" \
            | awk '{sum+=$3; c++} END {if(c>0) printf "%.3fs", sum/c; else print "n/a"}')
        add_finding "LOW" "MYSQL" \
            "Slow queries recorded" \
            "${slow_count} slow query entry(s) — avg time: ${avg_time}"
    fi

    # Full-table scans in slow log
    local full_scans
    full_scans=$(grep -c "^# Rows_examined:" "$tmp_file" 2>/dev/null; true)
    if (( full_scans > 0 )); then
        local max_rows
        max_rows=$(grep "^# Rows_examined:" "$tmp_file" \
            | awk '{print $3}' | sort -rn | head -1)
        if (( ${max_rows:-0} > 1000000 )); then
            add_finding "MEDIUM" "MYSQL" \
                "Full table scan detected in slow log" \
                "Max rows examined: ${max_rows} — add/review indexes"
        fi
    fi
}
