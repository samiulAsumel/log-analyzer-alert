#!/usr/bin/env bash
# scripts/health_check.sh — Operational Health Check  v2.0.0
# Verifies the log analyzer installation is healthy and running.
# Returns 0 = healthy, 1 = warning, 2 = critical.
# Suitable for use as a nagios/icinga/monitoring check.
# Usage: bash health_check.sh [--json] [--quiet]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
CONFIG_FILE="${ROOT_DIR}/config.conf"

JSON_OUT=false; QUIET=false
for _arg in "$@"; do
    case "$_arg" in
        --json)  JSON_OUT=true  ;;
        --quiet) QUIET=true     ;;
    esac
done

# ── Load config if available ──────────────────────────────────────────────────
if [[ -f "$CONFIG_FILE" ]]; then
    # shellcheck source=../config.conf
    source "$CONFIG_FILE"
elif [[ -f /etc/loganalyzer/config.conf ]]; then
    source /etc/loganalyzer/config.conf
fi

STATE_DIR="${STATE_DIR:-/var/lib/loganalyzer}"
LOG_DIR="${LOG_DIR:-/var/log/loganalyzer}"
LOG_FILE="${LOG_FILE:-${LOG_DIR}/analyzer.log}"
FINDINGS_DIR="${FINDINGS_DIR:-${STATE_DIR}/findings}"
CHECK_INTERVAL="${CHECK_INTERVAL:-15}"

# ── Check results array ───────────────────────────────────────────────────────
declare -a CHECKS=()
declare -a WARNINGS=()
declare -a CRITICALS=()
OVERALL=0   # 0=OK, 1=WARN, 2=CRIT

_check_ok()   { CHECKS+=("OK: $*"); }
_check_warn() { CHECKS+=("WARN: $*"); WARNINGS+=("$*"); [[ $OVERALL -lt 1 ]] && OVERALL=1; }
_check_crit() { CHECKS+=("CRIT: $*"); CRITICALS+=("$*"); OVERALL=2; }

# ── 1. State directories exist ────────────────────────────────────────────────
[[ -d "$STATE_DIR" ]] \
    && _check_ok "State dir exists: ${STATE_DIR}" \
    || _check_crit "State dir missing: ${STATE_DIR} (run install.sh)"

[[ -d "$FINDINGS_DIR" ]] \
    && _check_ok "Findings dir exists: ${FINDINGS_DIR}" \
    || _check_warn "Findings dir missing: ${FINDINGS_DIR}"

# ── 2. Log file exists and is writable ───────────────────────────────────────
if [[ -f "$LOG_FILE" ]]; then
    _check_ok "Log file exists: ${LOG_FILE}"
elif [[ -d "$LOG_DIR" ]]; then
    _check_warn "Log file not yet created (first run pending?): ${LOG_FILE}"
else
    _check_crit "Log directory missing: ${LOG_DIR}"
fi

# ── 3. Recent run check (was it run in the last 2× interval?) ────────────────
STALE_THRESHOLD=$(( CHECK_INTERVAL * 2 * 60 ))
LATEST_FINDINGS=$(find "$FINDINGS_DIR" -name "*.findings" 2>/dev/null | sort -r | head -1)
if [[ -n "$LATEST_FINDINGS" ]]; then
    LAST_RUN=$(stat -c '%Y' "$LATEST_FINDINGS" 2>/dev/null || echo 0)
    NOW=$(date +%s)
    AGE=$(( NOW - LAST_RUN ))
    if (( AGE > STALE_THRESHOLD )); then
        _check_warn "Last run was ${AGE}s ago (expected every $((CHECK_INTERVAL * 60))s) — cron may be down"
    else
        _check_ok "Last run ${AGE}s ago (threshold: ${STALE_THRESHOLD}s)"
    fi
else
    _check_warn "No findings files found — analyzer may not have run yet"
fi

# ── 4. Lock file check ────────────────────────────────────────────────────────
LOCK_FILE="${STATE_DIR}/analyzer.lock"
if [[ -f "$LOCK_FILE" ]]; then
    LOCK_PID=$(cat "$LOCK_FILE" 2>/dev/null || echo 0)
    if kill -0 "$LOCK_PID" 2>/dev/null; then
        _check_ok "Lock held by running process PID ${LOCK_PID}"
    else
        _check_warn "Stale lock file found (PID ${LOCK_PID} not running) — will be cleaned on next run"
    fi
else
    _check_ok "No active lock (not currently running)"
fi

# ── 5. Cron job check ────────────────────────────────────────────────────────
if [[ -f /etc/cron.d/loganalyzer ]]; then
    _check_ok "Cron job installed: /etc/cron.d/loganalyzer"
elif systemctl is-active --quiet loganalyzer.timer 2>/dev/null; then
    _check_ok "Systemd timer active: loganalyzer.timer"
else
    _check_warn "No cron job or systemd timer found — analyzer may not run automatically"
fi

# ── 6. Disk space for logs ────────────────────────────────────────────────────
if command -v df &>/dev/null; then
    LOG_PARTITION_PCT=$(df "$LOG_DIR" 2>/dev/null | awk 'NR==2{gsub(/%/,"",$5); print $5}' || echo 0)
    if (( LOG_PARTITION_PCT >= 95 )); then
        _check_crit "Log partition at ${LOG_PARTITION_PCT}% — log writes will fail"
    elif (( LOG_PARTITION_PCT >= 85 )); then
        _check_warn "Log partition at ${LOG_PARTITION_PCT}% — consider cleanup"
    else
        _check_ok "Log partition at ${LOG_PARTITION_PCT}%"
    fi
fi

# ── 7. Config file present ────────────────────────────────────────────────────
if [[ -f /etc/loganalyzer/config.conf ]]; then
    _check_ok "Config found: /etc/loganalyzer/config.conf"
elif [[ -f "$CONFIG_FILE" ]]; then
    _check_ok "Config found: ${CONFIG_FILE} (source dir — install with install.sh for production)"
else
    _check_crit "No config.conf found"
fi

# ── 8. Alert email configured ─────────────────────────────────────────────────
if [[ "${ALERT_EMAIL:-}" == "admin@company.com" || -z "${ALERT_EMAIL:-}" ]]; then
    _check_warn "ALERT_EMAIL is not configured (still using placeholder)"
else
    _check_ok "ALERT_EMAIL configured: ${ALERT_EMAIL}"
fi

# ── Output ────────────────────────────────────────────────────────────────────
STATUS_STR="OK"
[[ $OVERALL -eq 1 ]] && STATUS_STR="WARNING"
[[ $OVERALL -eq 2 ]] && STATUS_STR="CRITICAL"

if $JSON_OUT; then
    printf '{\n  "status": "%s",\n  "overall": %d,\n  "checks": [\n' "$STATUS_STR" "$OVERALL"
    local_sep=""
    for c in "${CHECKS[@]}"; do
        printf '%s    "%s"' "$local_sep" "$(echo "$c" | sed 's/"/\\"/g')"
        local_sep=",\n"
    done
    printf '\n  ],\n  "warnings": %d,\n  "criticals": %d,\n  "timestamp": "%s"\n}\n' \
        "${#WARNINGS[@]}" "${#CRITICALS[@]}" "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
else
    if ! $QUIET; then
        echo "Log Analyzer Health Check — $(date '+%Y-%m-%d %H:%M:%S')"
        echo "────────────────────────────────────"
        for c in "${CHECKS[@]}"; do
            echo "  $c"
        done
        echo "────────────────────────────────────"
    fi
    echo "Status: ${STATUS_STR} (${#WARNINGS[@]} warning(s), ${#CRITICALS[@]} critical(s))"
fi

exit "$OVERALL"
