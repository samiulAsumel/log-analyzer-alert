#!/usr/bin/env bash
# install.sh — One-command setup for Automated Log Analyzer & Alert System v1.0.0
# Installs scripts, configures cron jobs, creates directories.
# Usage: sudo bash install.sh [--uninstall] [--dry-run]
set -euo pipefail
trap 'echo -e "\n[ERROR] Installation failed at line ${LINENO}. Check output above." >&2; exit 1' ERR

# ── Colours ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; AMBER='\033[0;33m'; BOLD='\033[1m'; RESET='\033[0m'

log()  { echo -e "${CYAN}[$(date '+%H:%M:%S')]  INFO ${RESET} $*"; }
ok()   { echo -e "${GREEN}[$(date '+%H:%M:%S')]   OK  ${RESET} $*"; }
warn() { echo -e "${YELLOW}[$(date '+%H:%M:%S')]  WARN ${RESET} $*"; }
die()  { echo -e "${RED}[$(date '+%H:%M:%S')]  FAIL ${RESET} $*" >&2; exit 1; }
step() { echo -e "\n${BOLD}${AMBER}══════ $* ══════${RESET}"; }

# ── Paths ─────────────────────────────────────────────────────────────────────
INSTALL_DIR="/usr/local/bin/loganalyzer"
CONFIG_DIR="/etc/loganalyzer"
LOG_DIR="/var/log/loganalyzer"
STATE_DIR="/var/lib/loganalyzer"
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

DRY_RUN=false
for _arg in "$@"; do
    case "$_arg" in --dry-run) DRY_RUN=true ;; esac
done

$DRY_RUN && echo -e "${YELLOW}${BOLD}[DRY-RUN] No changes will be made${RESET}\n"

# ── Root check ────────────────────────────────────────────────────────────────
[[ $EUID -eq 0 ]] || die "Must be run as root: sudo bash install.sh"

# ── Source config ─────────────────────────────────────────────────────────────
if [[ -f "${SRC_DIR}/config.conf" ]]; then
    # shellcheck source=config.conf
    source "${SRC_DIR}/config.conf"
else
    warn "config.conf not found at ${SRC_DIR}/config.conf — using built-in defaults"
    ANALYZER_CRON="*/15 * * * *"
    DIGEST_CRON="0 7 * * *"
fi

# ── Uninstall mode ────────────────────────────────────────────────────────────
if [[ "${1:-}" == "--uninstall" ]]; then
    step "UNINSTALLING Log Analyzer & Alert System"
    rm -f "/etc/cron.d/loganalyzer"               && ok "Cron jobs removed"
    rm -rf "$INSTALL_DIR"                         && ok "Scripts removed: ${INSTALL_DIR}"
    rm -rf "$CONFIG_DIR"                          && ok "Config removed: ${CONFIG_DIR}"
    warn "Logs preserved at ${LOG_DIR}. Remove manually: rm -rf ${LOG_DIR}"
    warn "State preserved at ${STATE_DIR}. Remove manually: rm -rf ${STATE_DIR}"
    echo -e "\n${GREEN}${BOLD}Uninstall complete.${RESET}"
    exit 0
fi

# ── Banner ────────────────────────────────────────────────────────────────────
echo -e "${BOLD}${AMBER}"
cat <<'BANNER'
╔══════════════════════════════════════════════════════════════════╗
║   Automated Log Analyzer & Alert System  —  Installer  v1.0.0  ║
║   RHEL 9 / Rocky Linux / CentOS Stream / Ubuntu Server          ║
╚══════════════════════════════════════════════════════════════════╝
BANNER
echo -e "${RESET}"

# ── Dependency check ──────────────────────────────────────────────────────────
step "Checking dependencies"

MISSING=()
for cmd in bash awk grep sed find date stat dd wc sort uniq; do
    command -v "$cmd" &>/dev/null && ok "Found: $cmd" || { MISSING+=("$cmd"); warn "Missing: $cmd"; }
done

# Optional tools
for cmd in mailx sendmail curl firewall-cmd bc; do
    command -v "$cmd" &>/dev/null \
        && ok "Found: $cmd (optional)" \
        || warn "Not found: $cmd — some features disabled"
done

[[ ${#MISSING[@]} -gt 0 ]] && die "Required commands missing: ${MISSING[*]}. Install them first."

# ── Detect OS ─────────────────────────────────────────────────────────────────
step "Detecting OS"
OS_ID="unknown"
if [[ -f /etc/os-release ]]; then
    # shellcheck disable=SC1091
    source /etc/os-release
    OS_ID="${ID:-unknown}"
fi

case "$OS_ID" in
    rhel|centos|rocky|almalinux|fedora)
        ok "RHEL-family OS detected: ${OS_ID}"
        # Ubuntu uses /var/log/auth.log and /var/log/syslog
        ;;
    ubuntu|debian)
        ok "Debian-family OS detected: ${OS_ID}"
        warn "Ubuntu uses /var/log/auth.log and /var/log/syslog"
        warn "Edit config.conf after install: AUTH_LOG=/var/log/auth.log SYSLOG=/var/log/syslog"
        ;;
    *)
        warn "Unknown OS: ${OS_ID} — assuming RHEL paths (edit config.conf if needed)"
        ;;
esac

# ── Create directories ────────────────────────────────────────────────────────
step "Creating directories"

for dir in \
    "$INSTALL_DIR" \
    "$INSTALL_DIR/modules" \
    "$INSTALL_DIR/reports" \
    "$CONFIG_DIR" \
    "$LOG_DIR" \
    "${STATE_DIR}" \
    "${STATE_DIR}/positions" \
    "${STATE_DIR}/findings" \
    "${STATE_DIR}/cooldowns"; do
    if $DRY_RUN; then
        log "[DRY-RUN] Would create: $dir"
    else
        mkdir -p "$dir"
        ok "Created: $dir"
    fi
done

$DRY_RUN || chmod 750 "$STATE_DIR" "${STATE_DIR}/positions" "${STATE_DIR}/findings" "${STATE_DIR}/cooldowns"

# ── Install config ────────────────────────────────────────────────────────────
step "Installing configuration"

if [[ -f "${CONFIG_DIR}/config.conf" ]]; then
    warn "Existing config found — backing up to config.conf.bak.$(date +%s)"
    $DRY_RUN || cp "${CONFIG_DIR}/config.conf" "${CONFIG_DIR}/config.conf.bak.$(date +%s)"
fi

if $DRY_RUN; then
    log "[DRY-RUN] Would install: ${SRC_DIR}/config.conf → ${CONFIG_DIR}/config.conf"
else
    cp "${SRC_DIR}/config.conf" "${CONFIG_DIR}/config.conf"
    chmod 640 "${CONFIG_DIR}/config.conf"
    ln -sf "${CONFIG_DIR}/config.conf" "${INSTALL_DIR}/config.conf"
    ok "Config installed: ${CONFIG_DIR}/config.conf (mode 640)"
fi

# ── Install scripts ───────────────────────────────────────────────────────────
step "Installing scripts"

if $DRY_RUN; then
    log "[DRY-RUN] Would install log_analyzer.sh and all modules"
else
    cp "${SRC_DIR}/log_analyzer.sh" "${INSTALL_DIR}/"

    for mod in alert_engine analyze_auth analyze_system analyze_nginx \
               analyze_mysql analyze_app detect_threats; do
        if [[ -f "${SRC_DIR}/modules/${mod}.sh" ]]; then
            cp "${SRC_DIR}/modules/${mod}.sh" "${INSTALL_DIR}/modules/"
            ok "Installed module: ${mod}.sh"
        else
            warn "Module not found (skipped): ${SRC_DIR}/modules/${mod}.sh"
        fi
    done

    if [[ -f "${SRC_DIR}/reports/generate_digest.sh" ]]; then
        cp "${SRC_DIR}/reports/generate_digest.sh" "${INSTALL_DIR}/reports/"
        ok "Installed: generate_digest.sh"
    fi

    find "$INSTALL_DIR" -name "*.sh" -exec chmod 755 {} \;
    ok "All scripts installed and made executable (chmod 755)"
fi

# ── Set up cron jobs ──────────────────────────────────────────────────────────
step "Setting up cron jobs"

CRON_ANALYZE="${ANALYZER_CRON:-*/15 * * * *} root ${INSTALL_DIR}/log_analyzer.sh >> ${LOG_DIR}/cron.log 2>&1"
CRON_DIGEST="${DIGEST_CRON:-0 7 * * *} root ${INSTALL_DIR}/reports/generate_digest.sh >> ${LOG_DIR}/cron.log 2>&1"
CRON_FILE="/etc/cron.d/loganalyzer"

if $DRY_RUN; then
    log "[DRY-RUN] Would install cron at: ${CRON_FILE}"
    log "  Analyzer:  ${ANALYZER_CRON:-*/15 * * * *}"
    log "  Digest:    ${DIGEST_CRON:-0 7 * * *}"
else
    cat > "$CRON_FILE" <<CRONTAB
# Automated Log Analyzer & Alert System — auto-generated by install.sh
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

${CRON_ANALYZE}
${CRON_DIGEST}
CRONTAB
    chmod 644 "$CRON_FILE"
    ok "Cron installed: ${CRON_FILE}"
    ok "  Analyzer:  ${ANALYZER_CRON:-*/15 * * * *} (every 15 min)"
    ok "  Digest:    ${DIGEST_CRON:-0 7 * * *} (daily 07:00)"
fi

# ── Initial dry-run test ──────────────────────────────────────────────────────
step "Running initial test (dry-run)"

if $DRY_RUN; then
    log "[DRY-RUN] Would run: log_analyzer.sh --dry-run --verbose"
else
    if bash "${INSTALL_DIR}/log_analyzer.sh" --dry-run --verbose; then
        ok "Dry-run analyzer test passed"
    else
        warn "Dry-run returned non-zero — check config then run manually"
        warn "  sudo bash ${INSTALL_DIR}/log_analyzer.sh --verbose"
    fi
fi

# ── Log rotation setup ────────────────────────────────────────────────────────
step "Configuring log rotation"

LOGROTATE_FILE="/etc/logrotate.d/loganalyzer"
if $DRY_RUN; then
    log "[DRY-RUN] Would install logrotate config at ${LOGROTATE_FILE}"
else
    cat > "$LOGROTATE_FILE" <<LOGROTATE
${LOG_DIR}/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
    dateext
    dateformat -%Y%m%d
}
LOGROTATE
    chmod 644 "$LOGROTATE_FILE"
    ok "Log rotation configured: ${LOGROTATE_FILE}"
fi

# ── Post-install summary ──────────────────────────────────────────────────────
echo -e "\n${GREEN}${BOLD}╔══════════════════════════════════════════════════════════════════╗${RESET}"
echo -e "${GREEN}${BOLD}║         Installation complete!                                   ║${RESET}"
echo -e "${GREEN}${BOLD}╚══════════════════════════════════════════════════════════════════╝${RESET}"

cat <<INFO

  Config:         ${CONFIG_DIR}/config.conf
  Scripts:        ${INSTALL_DIR}/
  State files:    ${STATE_DIR}/
  Logs:           ${LOG_DIR}/analyzer.log
  Findings:       ${STATE_DIR}/findings/
  Cron:           /etc/cron.d/loganalyzer

  NEXT STEPS:
  ─────────────────────────────────────────────────────────────
  1. Edit config:    nano ${CONFIG_DIR}/config.conf
     Set: ALERT_EMAIL, log file paths, thresholds

  2. Run manually:   sudo bash ${INSTALL_DIR}/log_analyzer.sh --verbose

  3. Force re-read:  sudo bash ${INSTALL_DIR}/log_analyzer.sh --force --verbose

  4. Run one module: sudo bash ${INSTALL_DIR}/log_analyzer.sh --module=auth

  5. Test digest:    sudo bash ${INSTALL_DIR}/reports/generate_digest.sh --dry-run

  6. View findings:  ls -lt ${STATE_DIR}/findings/

  7. View logs:      tail -f ${LOG_DIR}/analyzer.log

  8. Uninstall:      sudo bash ${SRC_DIR}/install.sh --uninstall
  ─────────────────────────────────────────────────────────────

  UBUNTU USERS:
    Edit config.conf — change:
      AUTH_LOG="/var/log/auth.log"
      SYSLOG="/var/log/syslog"
  ─────────────────────────────────────────────────────────────

INFO
