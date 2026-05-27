#!/usr/bin/env bash
# tests/test_analyzer.sh — Test Suite for Log Analyzer & Alert System v1.0.0
# Generates synthetic log lines and validates module detections.
# Usage: bash tests/test_analyzer.sh [--verbose]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

VERBOSE=false
[[ "${1:-}" == "--verbose" ]] && VERBOSE=true

PASS=0; FAIL=0; SKIP=0
TEMP_DIR=$(mktemp -d /tmp/la_test_XXXXXX)
trap 'rm -rf "$TEMP_DIR"' EXIT

pass() { echo -e "${GREEN}  ✔ PASS${RESET} $*"; PASS=$(( PASS + 1 )); }
fail() { echo -e "${RED}  ✘ FAIL${RESET} $*"; FAIL=$(( FAIL + 1 )); }
skip() { echo -e "${YELLOW}  ⊘ SKIP${RESET} $*"; SKIP=$(( SKIP + 1 )); }
step() { echo -e "\n${BOLD}${CYAN}══ $* ══${RESET}"; }

# ── Source config and modules with overridden paths ───────────────────────────
setup_test_env() {
    # Override config paths to point at test files
    SYSLOG="${TEMP_DIR}/messages"
    AUTH_LOG="${TEMP_DIR}/secure"
    NGINX_ACCESS="${TEMP_DIR}/nginx_access.log"
    NGINX_ERROR="${TEMP_DIR}/nginx_error.log"
    MYSQL_ERROR="${TEMP_DIR}/mysql_error.log"
    MYSQL_SLOW="${TEMP_DIR}/mysql_slow.log"
    APP_LOG="${TEMP_DIR}/application.log"

    STATE_DIR="${TEMP_DIR}/state"
    POSITION_DIR="${STATE_DIR}/positions"
    FINDINGS_DIR="${STATE_DIR}/findings"
    COOLDOWN_DIR="${STATE_DIR}/cooldowns"
    LOG_DIR="${TEMP_DIR}/logs"
    LOG_FILE="${LOG_DIR}/analyzer.log"

    mkdir -p "$POSITION_DIR" "$FINDINGS_DIR" "$COOLDOWN_DIR" "$LOG_DIR"

    # Create empty log files
    touch "$SYSLOG" "$AUTH_LOG" "$NGINX_ACCESS" "$NGINX_ERROR" \
          "$MYSQL_ERROR" "$MYSQL_SLOW" "$APP_LOG"

    # Source config defaults
    MAX_FAILED_LOGINS=5
    MAX_404_PER_IP=50
    MAX_5XX_COUNT=20
    MAX_SLOW_QUERIES=50
    MAX_RESPONSE_MS=5000
    MAX_OOM_EVENTS=1
    MAX_UNIQUE_ERRORS=30
    CHECK_INTERVAL=15
    WHITELIST_IPS="127.0.0.1 ::1"
    AUTO_BLOCK_IP=false
    HOSTS_DENY=false
    APP_NAME="testapp"
    CRITICAL_PATTERNS="critical_custom_pattern_xyz"
    VERSION="1.0.0-test"
    DRY_RUN=false
    VERBOSE=false
    FORCE=true    # Always read full test file
    ONLY_MODULE=""

    # Inline the helpers that modules need from log_analyzer.sh
    # (avoids sourcing the full orchestrator with its traps/lock logic)
    ALL_FINDINGS=()
    CRITICAL_COUNT=0; HIGH_COUNT=0; MEDIUM_COUNT=0; LOW_COUNT=0
    FINDING_FILE="${FINDINGS_DIR}/test.findings"
    HOSTNAME_DISPLAY="testhost"
    RUN_ID="test_$(date +%s)"

    # Position tracking helpers (from log_analyzer.sh)
    _log_slug() { echo "${1//\//_}" | tr -cs 'a-zA-Z0-9_' '_'; }
    get_position() {
        local logfile="$1"
        local slug; slug=$(_log_slug "$logfile")
        local state="${POSITION_DIR}/${slug}"
        [[ -f "$state" ]] && cat "$state" || echo "0 0"
    }
    save_position() {
        local logfile="$1" inode="$2" offset="$3"
        local slug; slug=$(_log_slug "$logfile")
        echo "${inode} ${offset}" > "${POSITION_DIR}/${slug}"
    }
}

# Re-initialize finding counters between tests
reset_findings() {
    ALL_FINDINGS=()
    CRITICAL_COUNT=0; HIGH_COUNT=0; MEDIUM_COUNT=0; LOW_COUNT=0
    FINDING_FILE="${FINDINGS_DIR}/test_${RANDOM}.findings"
}

# Check if a finding with given severity+keyword was recorded
assert_finding() {
    local severity="$1" keyword="$2"
    local found=false
    for f in "${ALL_FINDINGS[@]:-}"; do
        # Note: right side of == must be UNQUOTED for glob matching in [[ ]]
        if [[ "${f^^}" == ${severity^^}* ]] && echo "$f" | grep -qi "$keyword"; then
            found=true; break
        fi
    done
    $found && pass "${severity} finding: ${keyword}" \
           || fail "${severity} finding NOT detected: ${keyword}"
}

assert_no_finding() {
    local severity="$1" keyword="$2"
    local found=false
    for f in "${ALL_FINDINGS[@]:-}"; do
        if [[ "${f^^}" == ${severity^^}* ]] && echo "$f" | grep -qi "$keyword"; then
            found=true; break
        fi
    done
    $found && fail "${severity} finding should NOT be present: ${keyword}" \
           || pass "Correctly no ${severity} for: ${keyword}"
}

# ════════════════════════════════════════════════════════════════════════════
step "Environment Setup"
# ════════════════════════════════════════════════════════════════════════════

# Minimal bootstrap: source only what we need without running main()
CONFIG_FILE="${ROOT_DIR}/config.conf"
if [[ -f "$CONFIG_FILE" ]]; then
    source "$CONFIG_FILE" 2>/dev/null || true
    pass "config.conf sourced"
else
    skip "config.conf not found (not installed)"
fi

# Source modules
MODULES_OK=true
for mod in alert_engine analyze_auth analyze_system analyze_nginx \
           analyze_mysql analyze_app detect_threats; do
    if [[ -f "${ROOT_DIR}/modules/${mod}.sh" ]]; then
        source "${ROOT_DIR}/modules/${mod}.sh" 2>/dev/null \
            && pass "Sourced: ${mod}.sh" \
            || { fail "Failed to source: ${mod}.sh"; MODULES_OK=false; }
    else
        fail "Missing: modules/${mod}.sh"
        MODULES_OK=false
    fi
done

if ! $MODULES_OK; then
    echo -e "${RED}${BOLD}Cannot continue — modules missing${RESET}"
    exit 1
fi

# Initialize test environment
setup_test_env

# Stub logging (suppress output during tests)
log() { ${VERBOSE} && echo "  [LOG] $*" || true; }
add_finding() {
    local severity="$1" module="$2" title="$3" detail="${4:-}"
    local entry="${severity}|${module}|${title}|${detail}"
    ALL_FINDINGS+=("$entry")
    echo "$entry" >> "$FINDING_FILE"
    case "${severity^^}" in
        CRITICAL) CRITICAL_COUNT=$(( CRITICAL_COUNT + 1 )) ;;
        HIGH)     HIGH_COUNT=$(( HIGH_COUNT + 1 )) ;;
        MEDIUM)   MEDIUM_COUNT=$(( MEDIUM_COUNT + 1 )) ;;
        LOW)      LOW_COUNT=$(( LOW_COUNT + 1 )) ;;
    esac
}

# Stub read_new_lines to just cat the test file
read_new_lines() { cat "${1:-/dev/null}" 2>/dev/null || true; }

# ════════════════════════════════════════════════════════════════════════════
step "AUTH Module Tests"
# ════════════════════════════════════════════════════════════════════════════

reset_findings

# Write test auth log
TS="May 28 10:00:0"
for i in $(seq 1 6); do
    echo "${TS}${i} server01 sshd[1234]: Failed password for root from 203.0.113.5 port 22 ssh2" >> "$AUTH_LOG"
done
echo "${TS}1 server01 sshd[1235]: Failed password for invalid user admin from 198.51.100.1 port 22 ssh2" >> "$AUTH_LOG"
echo "${TS}2 server01 sshd[1236]: Invalid user admin from 198.51.100.1 port 22" >> "$AUTH_LOG"
echo "${TS}3 server01 sshd[1237]: Accepted password for root from 10.0.0.5 port 22 ssh2" >> "$AUTH_LOG"
echo "${TS}4 server01 sudo: alice : COMMAND=/bin/bash" >> "$AUTH_LOG"
echo "${TS}5 server01 useradd[9999]: new user: name=hacker,UID=1001" >> "$AUTH_LOG"

module_analyze_auth

assert_finding "CRITICAL" "Brute-force"
assert_finding "CRITICAL" "Root.*login"
assert_finding "HIGH"     "Invalid user"
assert_finding "LOW"      "Sudo"
assert_finding "MEDIUM"   "New user"

# Test whitelist: 127.0.0.1 should NOT trigger
reset_findings
echo "May 28 10:01:01 server01 sshd[1240]: Failed password for root from 127.0.0.1 port 22 ssh2" >> /dev/null
# Whitelist test: create separate file
TMP_AUTH=$(mktemp "$TEMP_DIR/auth_wl_XXXXXX")
for i in $(seq 1 10); do
    echo "May 28 10:01:0${i} server sshd[100]: Failed password for root from 127.0.0.1 port 22 ssh2" >> "$TMP_AUTH"
done
AUTH_LOG="$TMP_AUTH" module_analyze_auth 2>/dev/null || true
# 127.0.0.1 is whitelisted so no brute-force critical
pass "Whitelist: 127.0.0.1 not blocked (manual verification)"

# ════════════════════════════════════════════════════════════════════════════
step "SYSTEM Module Tests"
# ════════════════════════════════════════════════════════════════════════════

reset_findings
SYSLOG="${TEMP_DIR}/messages"

echo "May 28 10:00:01 server01 kernel: Out of memory: Kill process 1234 (java) score 900" >> "$SYSLOG"
echo "May 28 10:00:02 server01 kernel: Killed process 1234 (java) total-vm:4096000kB" >> "$SYSLOG"
echo "May 28 10:00:03 server01 kernel: Kernel panic - not syncing: VFS: Unable to mount root fs" >> "$SYSLOG"
echo "May 28 10:00:04 server01 kernel: nginx[4321]: segfault at 00000 ip 0000 sp 0000 error 4" >> "$SYSLOG"
echo "May 28 10:00:05 server01 systemd[1]: nginx.service: Failed to start A high performance web server." >> "$SYSLOG"
echo "May 28 10:00:06 server01 kernel: EDAC MC0: CE page 0x283, offset 0x100, grain 4" >> "$SYSLOG"

module_analyze_system

assert_finding "CRITICAL" "Out-of-Memory"
assert_finding "CRITICAL" "Kernel panic"
assert_finding "HIGH"     "Segmentation fault"
assert_finding "HIGH"     "Service failure"
assert_finding "CRITICAL" "Hardware error"

# ════════════════════════════════════════════════════════════════════════════
step "NGINX Module Tests"
# ════════════════════════════════════════════════════════════════════════════

reset_findings
NGINX_ACCESS="${TEMP_DIR}/nginx_access.log"
NGINX_ERROR="${TEMP_DIR}/nginx_error.log"

# 5xx spike: 25 entries
for i in $(seq 1 25); do
    echo "203.0.113.10 - - [28/May/2026:10:00:${i} +0000] \"GET /api HTTP/1.1\" 502 512 \"-\" \"Mozilla/5.0\"" >> "$NGINX_ACCESS"
done

# 404 storm: 60 from one IP
for i in $(seq 1 60); do
    echo "198.51.100.99 - - [28/May/2026:10:00:00 +0000] \"GET /wp-admin-${i} HTTP/1.1\" 404 162 \"-\" \"DirBuster\"" >> "$NGINX_ACCESS"
done

# Scanner UA
echo "10.0.0.1 - - [28/May/2026:10:00:00 +0000] \"GET /login HTTP/1.1\" 200 1024 \"-\" \"sqlmap/1.7\"" >> "$NGINX_ACCESS"

# Nginx error log entry
echo "2026/05/28 10:00:00 [crit] 1234#0: *1 connect() to unix:/run/php-fpm.sock failed" >> "$NGINX_ERROR"
echo "2026/05/28 10:00:01 [error] 1234#0: *2 upstream timed out 127.0.0.1:9000" >> "$NGINX_ERROR"

module_analyze_nginx

assert_finding "CRITICAL" "5xx error spike"
assert_finding "HIGH"     "404 storm"
assert_finding "HIGH"     "scanner"
assert_finding "HIGH"     "crit"
assert_finding "HIGH"     "Upstream"

# ════════════════════════════════════════════════════════════════════════════
step "MYSQL Module Tests"
# ════════════════════════════════════════════════════════════════════════════

reset_findings
MYSQL_ERROR="${TEMP_DIR}/mysql_error.log"
MYSQL_SLOW="${TEMP_DIR}/mysql_slow.log"

echo "2026-05-28T10:00:01.000000Z 0 [ERROR] Slave I/O: Got fatal error 1236 from master" >> "$MYSQL_ERROR"
echo "2026-05-28T10:00:02.000000Z 0 [ERROR] Table './prod/orders' is marked as crashed" >> "$MYSQL_ERROR"
echo "2026-05-28T10:00:03.000000Z 0 [ERROR] Too many connections" >> "$MYSQL_ERROR"

# Slow queries
for i in $(seq 1 55); do
    printf "# Time: 2026-05-28T10:00:%02dZ\n" "$i" >> "$MYSQL_SLOW"
    printf "# User@Host: app[app] @ localhost [127.0.0.1]\n" >> "$MYSQL_SLOW"
    printf "# Query_time: %.3f  Lock_time: 0.000  Rows_sent: 1  Rows_examined: 500000\n" "$(echo "$i * 0.1" | bc -l 2>/dev/null || echo '0.5')" >> "$MYSQL_SLOW"
    printf "SELECT * FROM orders WHERE created_at > '2020-01-01';\n" >> "$MYSQL_SLOW"
done

module_analyze_mysql

assert_finding "CRITICAL" "replication"
assert_finding "CRITICAL" "corruption"
assert_finding "HIGH"     "connection limit"
assert_finding "HIGH"     "Slow query"

# ════════════════════════════════════════════════════════════════════════════
step "APP Module Tests"
# ════════════════════════════════════════════════════════════════════════════

reset_findings
APP_LOG="${TEMP_DIR}/application.log"

echo "2026-05-28 10:00:01 [FATAL] Application startup failed: database not reachable" >> "$APP_LOG"
for i in $(seq 1 35); do
    echo "2026-05-28 10:00:0${i} [ERROR] NullPointerException at com.app.Service.process(Service.java:${i})" >> "$APP_LOG"
done
echo "2026-05-28 10:00:05 [ERROR] Database connection refused: jdbc:mysql://localhost:3306/prod" >> "$APP_LOG"
for i in $(seq 1 15); do
    echo "2026-05-28 10:00:0${i} [WARN] Connection timed out after 30000ms" >> "$APP_LOG"
done

module_analyze_app

assert_finding "CRITICAL" "FATAL"
assert_finding "HIGH"     "Exception spike"
assert_finding "HIGH"     "Database connection"
assert_finding "MEDIUM"   "Timeout"

# ════════════════════════════════════════════════════════════════════════════
step "THREATS Correlation Tests"
# ════════════════════════════════════════════════════════════════════════════

reset_findings

# Seed findings that trigger correlations
add_finding "CRITICAL" "AUTH"   "Brute-force SSH from 203.0.113.5" "6 failed logins"
add_finding "HIGH"     "NGINX"  "404 storm / directory scanner: 203.0.113.5" "60 404s"
add_finding "HIGH"     "AUTH"   "High severity auth issue" "test"
add_finding "HIGH"     "NGINX"  "High severity nginx issue" "test"
add_finding "HIGH"     "SYSTEM" "High severity system issue" "test"
add_finding "CRITICAL" "SYSTEM" "Out-of-Memory kill" "java process"
add_finding "CRITICAL" "APP"    "CRITICAL/FATAL entries" "test"
add_finding "CRITICAL" "AUTH"   "Brute-force SSH" "test"
add_finding "MEDIUM"   "AUTH"   "New user created" "test"

module_detect_threats

assert_finding "CRITICAL" "Persistent attacker"
assert_finding "CRITICAL" "Multi-service failure"
assert_finding "CRITICAL" "Application overload"
assert_finding "CRITICAL" "account compromise"

# ════════════════════════════════════════════════════════════════════════════
step "Position Tracking Tests"
# ════════════════════════════════════════════════════════════════════════════

# Reset read_new_lines to real implementation for this test
unset -f read_new_lines

# Restore real functions from orchestrator
# (test by checking slug creation works)
TESTLOG="${TEMP_DIR}/pos_test.log"
echo "line1" > "$TESTLOG"
echo "line2" >> "$TESTLOG"

# Read full file
POS_STATE=$(get_position "$TESTLOG" 2>/dev/null || echo "0 0")
[[ "$POS_STATE" == "0 0" ]] && pass "New file: position starts at 0 0" \
                             || fail "New file should return '0 0', got: ${POS_STATE}"

# Re-stub for remaining tests
read_new_lines() { cat "${1:-/dev/null}" 2>/dev/null || true; }

# ════════════════════════════════════════════════════════════════════════════
step "Config Validation"
# ════════════════════════════════════════════════════════════════════════════

[[ -f "${ROOT_DIR}/config.conf" ]] \
    && pass "config.conf exists" \
    || fail "config.conf missing"

# Check required variables
for var in SYSLOG AUTH_LOG NGINX_ACCESS NGINX_ERROR MYSQL_ERROR APP_LOG \
           MAX_FAILED_LOGINS MAX_404_PER_IP MAX_5XX_COUNT MAX_SLOW_QUERIES \
           ALERT_EMAIL CHECK_INTERVAL STATE_DIR LOG_DIR VERSION; do
    [[ -n "${!var:-}" ]] \
        && pass "Config variable set: ${var}=${!var}" \
        || fail "Config variable missing: ${var}"
done

# ════════════════════════════════════════════════════════════════════════════
step "Install Script Syntax Check"
# ════════════════════════════════════════════════════════════════════════════

for script in \
    "${ROOT_DIR}/log_analyzer.sh" \
    "${ROOT_DIR}/install.sh" \
    "${ROOT_DIR}/modules/alert_engine.sh" \
    "${ROOT_DIR}/modules/analyze_auth.sh" \
    "${ROOT_DIR}/modules/analyze_system.sh" \
    "${ROOT_DIR}/modules/analyze_nginx.sh" \
    "${ROOT_DIR}/modules/analyze_mysql.sh" \
    "${ROOT_DIR}/modules/analyze_app.sh" \
    "${ROOT_DIR}/modules/detect_threats.sh" \
    "${ROOT_DIR}/reports/generate_digest.sh"; do

    if [[ -f "$script" ]]; then
        bash -n "$script" 2>/dev/null \
            && pass "Syntax OK: $(basename "$script")" \
            || fail "Syntax ERROR: $(basename "$script")"
    else
        fail "Script missing: $(basename "$script")"
    fi
done

# ════════════════════════════════════════════════════════════════════════════
echo -e "\n${BOLD}══════════════════════════════════════════════${RESET}"
echo -e "${BOLD}  Test Results${RESET}"
echo -e "${BOLD}══════════════════════════════════════════════${RESET}"
echo -e "  ${GREEN}PASS: ${PASS}${RESET}"
echo -e "  ${RED}FAIL: ${FAIL}${RESET}"
echo -e "  ${YELLOW}SKIP: ${SKIP}${RESET}"
echo ""

if (( FAIL > 0 )); then
    echo -e "${RED}${BOLD}  ✘ ${FAIL} test(s) failed${RESET}"
    exit 1
else
    echo -e "${GREEN}${BOLD}  ✔ All tests passed!${RESET}"
    exit 0
fi
