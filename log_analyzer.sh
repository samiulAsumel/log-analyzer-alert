#!/usr/bin/env bash
# log_analyzer.sh — Automated Log Analyzer & Alert System  Orchestrator v1.0.0
# Runs every 15 min via cron. Reads only NEW log lines since last run.
# Calls all analysis modules, aggregates findings, fires alerts.
# Usage: ./log_analyzer.sh [--dry-run] [--verbose] [--force] [--module=NAME]
# Cron:  */15 * * * * /usr/local/bin/loganalyzer/log_analyzer.sh
set -euo pipefail
trap '_on_error $LINENO "$BASH_COMMAND"' ERR

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Error handler ─────────────────────────────────────────────────────────────
_on_error() {
    local line="$1" cmd="$2"
    local msg="Fatal error at line ${line}: ${cmd}"
    if declare -f log &>/dev/null; then
        log "ERROR" "ORCHESTRATOR" "$msg"
    else
        echo "[ERROR] [ORCHESTRATOR] ${msg}" >&2
    fi
    exit 1
}

# ── Source configuration ──────────────────────────────────────────────────────
CONFIG_FILE="${SCRIPT_DIR}/config.conf"
[[ -f "$CONFIG_FILE" ]] || { echo "[FATAL] config.conf not found at ${CONFIG_FILE}" >&2; exit 1; }
# shellcheck source=config.conf
source "$CONFIG_FILE"

# ── Source modules ────────────────────────────────────────────────────────────
for _mod in alert_engine analyze_auth analyze_system analyze_nginx \
            analyze_mysql analyze_app detect_threats; do
    _path="${SCRIPT_DIR}/modules/${_mod}.sh"
    [[ -f "$_path" ]] || { echo "[FATAL] Module missing: ${_path}" >&2; exit 1; }
    # shellcheck disable=SC1090
    source "$_path"
done

# ── Runtime flags ─────────────────────────────────────────────────────────────
DRY_RUN=false; VERBOSE=false; FORCE=false; ONLY_MODULE=""

for _arg in "$@"; do
    case "$_arg" in
        --dry-run)       DRY_RUN=true       ;;
        --verbose)       VERBOSE=true       ;;
        --force)         FORCE=true         ;;
        --module=*)      ONLY_MODULE="${_arg#*=}" ;;
    esac
done

# ── Colours (terminal only) ───────────────────────────────────────────────────
if [[ -t 1 ]]; then
    RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
    CYAN='\033[0;36m'; AMBER='\033[0;33m'; BOLD='\033[1m'; RESET='\033[0m'
    MAGENTA='\033[0;35m'; BLUE='\033[0;34m'
else
    RED=''; GREEN=''; YELLOW=''; CYAN=''; AMBER=''; BOLD=''; RESET=''
    MAGENTA=''; BLUE=''
fi

# ── Initialise directories ────────────────────────────────────────────────────
$DRY_RUN || {
    mkdir -p "$LOG_DIR" "$STATE_DIR" "$POSITION_DIR" "$FINDINGS_DIR" "$COOLDOWN_DIR"
    chmod 750 "$STATE_DIR" "$POSITION_DIR" "$FINDINGS_DIR" "$COOLDOWN_DIR"
}

# ── Logging ───────────────────────────────────────────────────────────────────
RUN_START=$(date +%s)
RUN_ID=$(date '+%Y%m%d_%H%M%S')
FINDING_FILE="${FINDINGS_DIR}/${RUN_ID}.findings"
HOSTNAME_DISPLAY="$(hostname -s 2>/dev/null || echo unknown)"

# Severity → colour
_sev_colour() {
    case "${1^^}" in
        CRITICAL)  echo "$RED"    ;;
        HIGH)      echo "$AMBER"  ;;
        MEDIUM)    echo "$YELLOW" ;;
        LOW)       echo "$CYAN"   ;;
        OK)        echo "$GREEN"  ;;
        *)         echo "$RESET"  ;;
    esac
}

log() {
    local level="$1" module="$2" msg="$3"
    local ts entry colour
    ts=$(date '+%Y-%m-%d %H:%M:%S')
    entry="[${ts}] [${module}] [${level}] ${msg}"
    $DRY_RUN || echo "$entry" >> "$LOG_FILE"
    if [[ -t 1 ]] || $VERBOSE; then
        colour=$(_sev_colour "$level")
        echo -e "${colour}${entry}${RESET}"
    fi
}

# ── Lock file ─────────────────────────────────────────────────────────────────
LOCK_FILE="${STATE_DIR}/analyzer.lock"

acquire_lock() {
    if [[ -f "$LOCK_FILE" ]]; then
        local old_pid
        old_pid=$(cat "$LOCK_FILE" 2>/dev/null || echo 0)
        if kill -0 "$old_pid" 2>/dev/null; then
            log "WARN" "LOCK" "Another instance running (PID ${old_pid}) — exiting"
            exit 0
        else
            log "WARN" "LOCK" "Stale lock from PID ${old_pid}, removing"
            $DRY_RUN || rm -f "$LOCK_FILE"
        fi
    fi
    $DRY_RUN || echo $$ > "$LOCK_FILE"
    log "OK" "LOCK" "Acquired lock (PID $$)"
}

release_lock() {
    $DRY_RUN || rm -f "$LOCK_FILE"
}
trap 'release_lock' EXIT

# ════════════════════════════════════════════════════════════════════════════
# POSITION TRACKING — read only new lines per log file
# State file: POSITION_DIR/<slug>  contains "INODE OFFSET"
# ════════════════════════════════════════════════════════════════════════════

# Convert log path to safe slug for state filename
_log_slug() { echo "${1//\//_}" | tr -cs 'a-zA-Z0-9_' '_'; }

# Return byte offset and inode stored for a log file
# Returns "0 0" if file not yet tracked
get_position() {
    local logfile="$1"
    local slug; slug=$(_log_slug "$logfile")
    local state="${POSITION_DIR}/${slug}"
    [[ -f "$state" ]] && cat "$state" || echo "0 0"
}

# Save new position for a log file after processing
save_position() {
    local logfile="$1" inode="$2" offset="$3"
    local slug; slug=$(_log_slug "$logfile")
    $DRY_RUN || echo "${inode} ${offset}" > "${POSITION_DIR}/${slug}"
}

# Read new bytes from logfile since last run.
# Handles log rotation: if inode changed → read from 0.
# Outputs new lines to stdout; returns 0 even if no new data.
read_new_lines() {
    local logfile="$1"
    [[ -f "$logfile" ]] || { log "WARN" "POSITION" "${logfile} not found — skipping"; return 0; }
    [[ -r "$logfile" ]] || { log "WARN" "POSITION" "${logfile} not readable — skipping"; return 0; }

    local curr_inode curr_size
    curr_inode=$(stat -c '%i' "$logfile" 2>/dev/null || echo 0)
    curr_size=$(stat -c '%s'  "$logfile" 2>/dev/null || echo 0)

    read -r saved_inode saved_offset < <(get_position "$logfile")

    if [[ "$FORCE" == "true" ]]; then
        saved_inode=0; saved_offset=0
    fi

    local read_from=0
    if [[ "$curr_inode" == "$saved_inode" && "$saved_offset" -le "$curr_size" ]]; then
        read_from="$saved_offset"
    else
        [[ "$curr_inode" != "$saved_inode" ]] && \
            log "INFO" "POSITION" "Log rotated: ${logfile} (old inode ${saved_inode} → ${curr_inode})"
        read_from=0
    fi

    if [[ "$read_from" -eq "$curr_size" ]]; then
        log "INFO" "POSITION" "No new data in ${logfile}"
        save_position "$logfile" "$curr_inode" "$curr_size"
        return 0
    fi

    local bytes_to_read=$(( curr_size - read_from ))
    log "INFO" "POSITION" "Reading ${bytes_to_read} new bytes from ${logfile} (offset ${read_from})"

    # Output new lines
    dd if="$logfile" bs=1 skip="$read_from" count="$bytes_to_read" 2>/dev/null

    # Save new position
    save_position "$logfile" "$curr_inode" "$curr_size"
}

# ════════════════════════════════════════════════════════════════════════════
# FINDINGS AGGREGATION
# ════════════════════════════════════════════════════════════════════════════

declare -a ALL_FINDINGS=()
CRITICAL_COUNT=0; HIGH_COUNT=0; MEDIUM_COUNT=0; LOW_COUNT=0

# Add a finding; format: SEVERITY|MODULE|TITLE|DETAIL
add_finding() {
    local severity="$1" module="$2" title="$3" detail="${4:-}"
    local entry="${severity}|${module}|${title}|${detail}"
    ALL_FINDINGS+=("$entry")
    $DRY_RUN || echo "$entry" >> "$FINDING_FILE"

    case "${severity^^}" in
        CRITICAL) CRITICAL_COUNT=$(( CRITICAL_COUNT + 1 )) ;;
        HIGH)     HIGH_COUNT=$(( HIGH_COUNT + 1 ))         ;;
        MEDIUM)   MEDIUM_COUNT=$(( MEDIUM_COUNT + 1 ))     ;;
        LOW)      LOW_COUNT=$(( LOW_COUNT + 1 ))           ;;
    esac

    log "${severity^^}" "$module" "${title} — ${detail}"
}

# ════════════════════════════════════════════════════════════════════════════
# LIBRARY BOUNDARY — when sourced (e.g., by tests), stop here.
# Functions defined above are available to the caller.
# ════════════════════════════════════════════════════════════════════════════
[[ "${BASH_SOURCE[0]}" != "${0}" ]] && return 0

# ════════════════════════════════════════════════════════════════════════════
# BANNER
# ════════════════════════════════════════════════════════════════════════════

if [[ -t 1 ]] || $VERBOSE; then
    echo -e "${BOLD}${AMBER}"
    cat <<'BANNER'
╔══════════════════════════════════════════════════════════════════╗
║    Automated Log Analyzer & Alert System  —  Run v1.0.0         ║
║    RHEL 9 / Rocky Linux / Ubuntu Server                         ║
╚══════════════════════════════════════════════════════════════════╝
BANNER
    echo -e "${RESET}"
fi

log "INFO" "ORCHESTRATOR" "Run ${RUN_ID} started on ${HOSTNAME_DISPLAY}"
$DRY_RUN && log "WARN" "ORCHESTRATOR" "DRY-RUN mode — no state changes, no alerts sent"

acquire_lock

# ════════════════════════════════════════════════════════════════════════════
# ROTATE OWN LOGS
# ════════════════════════════════════════════════════════════════════════════
$DRY_RUN || find "$LOG_DIR" -name "*.log" -mtime +"${LOG_MAX_DAYS}" -delete 2>/dev/null || true
$DRY_RUN || find "$FINDINGS_DIR" -name "*.findings" -mtime +7 -delete 2>/dev/null || true

# ════════════════════════════════════════════════════════════════════════════
# RUN MODULES
# ════════════════════════════════════════════════════════════════════════════

run_module() {
    local name="$1" func="$2"
    [[ -n "$ONLY_MODULE" && "$ONLY_MODULE" != "$name" ]] && return 0

    log "INFO" "ORCHESTRATOR" "▶  Module: ${name}"
    if declare -f "$func" &>/dev/null; then
        "$func"
    else
        log "WARN" "ORCHESTRATOR" "Function ${func} not found — skipping ${name}"
    fi
    log "INFO" "ORCHESTRATOR" "✔  Module done: ${name}"
}

run_module "auth"    "module_analyze_auth"
run_module "system"  "module_analyze_system"
run_module "nginx"   "module_analyze_nginx"
run_module "mysql"   "module_analyze_mysql"
run_module "app"     "module_analyze_app"
run_module "threats" "module_detect_threats"

# ════════════════════════════════════════════════════════════════════════════
# ALERT DISPATCH
# ════════════════════════════════════════════════════════════════════════════

log "INFO" "ORCHESTRATOR" "Findings this run — CRITICAL:${CRITICAL_COUNT} HIGH:${HIGH_COUNT} MEDIUM:${MEDIUM_COUNT} LOW:${LOW_COUNT}"

if (( CRITICAL_COUNT > 0 )); then
    _send_critical_alert
elif (( HIGH_COUNT > 0 )); then
    _send_high_alert
fi

# Medium/Low are batched in the daily digest — nothing to send now.

# ════════════════════════════════════════════════════════════════════════════
# SUMMARY
# ════════════════════════════════════════════════════════════════════════════

RUN_END=$(date +%s)
RUN_DURATION=$(( RUN_END - RUN_START ))

log "OK" "ORCHESTRATOR" "Run ${RUN_ID} complete in ${RUN_DURATION}s — findings saved to ${FINDING_FILE}"

if [[ -t 1 ]] || $VERBOSE; then
    echo -e "\n${BOLD}${GREEN}══════ Run Summary ══════${RESET}"
    printf "  %s%-12s%s %d\n" "$RED"    "CRITICAL"  "$RESET" "$CRITICAL_COUNT"
    printf "  %s%-12s%s %d\n" "$AMBER"  "HIGH"      "$RESET" "$HIGH_COUNT"
    printf "  %s%-12s%s %d\n" "$YELLOW" "MEDIUM"    "$RESET" "$MEDIUM_COUNT"
    printf "  %s%-12s%s %d\n" "$CYAN"   "LOW"       "$RESET" "$LOW_COUNT"
    printf "  %-12s %ds\n"    "Duration"             "$RUN_DURATION"
    echo ""
fi
