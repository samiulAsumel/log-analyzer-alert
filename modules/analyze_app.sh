#!/usr/bin/env bash
# modules/analyze_app.sh — Custom Application Log Analyzer  v1.0.0
# Sourced by log_analyzer.sh.
# Detects: exception spikes, error rate, API failures, response time degradation.
# Configure APP_LOG and APP_NAME in config.conf.
# set -euo pipefail is inherited.

module_analyze_app() {
    local logfile="${APP_LOG:-/var/log/myapp/application.log}"
    local appname="${APP_NAME:-app}"
    log "INFO" "APP" "Analyzing ${appname}: ${logfile}"

    [[ -f "$logfile" ]] || {
        log "WARN" "APP" "App log not found: ${logfile} — skipping"
        return 0
    }

    local new_lines
    new_lines=$(read_new_lines "$logfile" 2>/dev/null) || {
        log "WARN" "APP" "Could not read ${logfile}"; return 0
    }
    [[ -z "$new_lines" ]] && { log "INFO" "APP" "No new app log entries"; return 0; }

    local tmp_file
    tmp_file=$(mktemp /tmp/la_app_XXXXXX)
    echo "$new_lines" > "$tmp_file"
    trap '[[ -n "${tmp_file:-}" ]] && rm -f "$tmp_file"' RETURN

    local total_lines
    total_lines=$(wc -l < "$tmp_file")
    log "INFO" "APP" "Analyzing ${total_lines} new app log line(s)"

    # ── Exceptions / stack traces ─────────────────────────────────────────
    local exc_count
    exc_count=$(grep -cEi "Exception|Traceback|stack trace|FATAL|Error:|NullPointerException|RuntimeException|AttributeError|TypeError|ValueError|KeyError|IndexError" \
        "$tmp_file" 2>/dev/null; true)
    if (( exc_count > 0 )); then
        local top_exc
        top_exc=$(grep -Ei "Exception|Error:|Traceback" "$tmp_file" \
            | grep -oE '[A-Z][a-zA-Z]+Exception|[A-Z][a-zA-Z]+Error' \
            | sort | uniq -c | sort -rn | head -5 \
            | awk '{printf "%s×%d; ", $2, $1}')
        if (( exc_count >= MAX_UNIQUE_ERRORS )); then
            add_finding "HIGH" "APP" \
                "${appname}: Exception spike (${exc_count})" \
                "Threshold: ${MAX_UNIQUE_ERRORS} — top types: ${top_exc}"
        else
            add_finding "MEDIUM" "APP" \
                "${appname}: Exceptions detected (${exc_count})" \
                "Top types: ${top_exc}"
        fi
    fi

    # ── CRITICAL / FATAL log entries ──────────────────────────────────────
    local critical_count
    critical_count=$(grep -cEi "\[CRITICAL\]|\[FATAL\]|CRITICAL:|FATAL:" \
        "$tmp_file" 2>/dev/null; true)
    if (( critical_count > 0 )); then
        local crit_sample
        crit_sample=$(grep -Ei "\[CRITICAL\]|\[FATAL\]|CRITICAL:|FATAL:" "$tmp_file" \
            | tail -3 | cut -c1-200 | tr '\n' '|')
        add_finding "CRITICAL" "APP" \
            "${appname}: CRITICAL/FATAL entries detected" \
            "${critical_count} entry(s) — ${crit_sample}"
    fi

    # ── ERROR level entries ────────────────────────────────────────────────
    local error_count
    error_count=$(grep -cEi "\[ERROR\]|ERROR:" "$tmp_file" 2>/dev/null; true)
    if (( error_count > 0 )); then
        local error_rate=$(( error_count * 100 / (total_lines + 1) ))
        if (( error_rate >= 20 )); then
            add_finding "HIGH" "APP" \
                "${appname}: High error rate (${error_rate}%)" \
                "${error_count} ERROR entries in ${total_lines} total lines"
        elif (( error_count > 10 )); then
            local top_errs
            top_errs=$(grep -Ei "\[ERROR\]|ERROR:" "$tmp_file" \
                | cut -c1-100 | sort | uniq -c | sort -rn | head -3 \
                | awk '{$1=$1; print}' | tr '\n' '|')
            add_finding "MEDIUM" "APP" \
                "${appname}: Error entries detected" \
                "${error_count} ERROR entries — ${top_errs}"
        fi
    fi

    # ── Database connection errors ─────────────────────────────────────────
    local db_err
    db_err=$(grep -cEi "database.*connection|connection.*refused|SQLSTATE|deadlock|lock wait timeout|db.*error" \
        "$tmp_file" 2>/dev/null; true)
    if (( db_err > 0 )); then
        add_finding "HIGH" "APP" \
            "${appname}: Database connection errors" \
            "${db_err} DB error(s) — may indicate DB outage or pool exhaustion"
    fi

    # ── API error codes ────────────────────────────────────────────────────
    local api_errors
    api_errors=$(grep -cEi '"status":\s*(5[0-9][0-9]|4[0-9][0-9])|http_status.*[45][0-9][0-9]|status_code.*[45][0-9][0-9]' \
        "$tmp_file" 2>/dev/null; true)
    if (( api_errors > 20 )); then
        add_finding "HIGH" "APP" \
            "${appname}: API error response spike" \
            "${api_errors} API 4xx/5xx responses detected in logs"
    fi

    # ── Memory warnings ────────────────────────────────────────────────────
    local mem_warn
    mem_warn=$(grep -cEi "OutOfMemory|memory.*exhausted|heap.*space|GC overhead|cannot allocate.*memory" \
        "$tmp_file" 2>/dev/null; true)
    if (( mem_warn > 0 )); then
        add_finding "HIGH" "APP" \
            "${appname}: Memory exhaustion warnings" \
            "${mem_warn} memory warning(s)"
    fi

    # ── Timeout patterns ──────────────────────────────────────────────────
    local timeout_count
    timeout_count=$(grep -cEi "timeout|timed out|deadline exceeded|read timed out" \
        "$tmp_file" 2>/dev/null; true)
    if (( timeout_count > 10 )); then
        add_finding "MEDIUM" "APP" \
            "${appname}: Timeout spike" \
            "${timeout_count} timeout event(s) — check dependent services"
    fi

    # ── Disk / file errors ─────────────────────────────────────────────────
    local disk_err
    disk_err=$(grep -cEi "No space left|file.*not found|permission denied|disk full" \
        "$tmp_file" 2>/dev/null; true)
    if (( disk_err > 0 )); then
        add_finding "HIGH" "APP" \
            "${appname}: Disk/file system errors" \
            "${disk_err} filesystem error(s) in app log"
    fi

    # ── Custom CRITICAL_PATTERNS from config ──────────────────────────────
    if [[ -n "${CRITICAL_PATTERNS:-}" ]]; then
        local custom_crit
        custom_crit=$(grep -cEi "${CRITICAL_PATTERNS}" "$tmp_file" 2>/dev/null; true)
        if (( custom_crit > 0 )); then
            local crit_lines
            crit_lines=$(grep -Ei "${CRITICAL_PATTERNS}" "$tmp_file" \
                | tail -3 | cut -c1-160 | tr '\n' '|')
            add_finding "CRITICAL" "APP" \
                "${appname}: Custom critical pattern match" \
                "${custom_crit} match(es) for pattern [${CRITICAL_PATTERNS:0:60}…] — ${crit_lines}"
        fi
    fi

    log "INFO" "APP" "App log analysis complete"
}
