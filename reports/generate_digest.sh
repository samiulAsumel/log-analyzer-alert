#!/usr/bin/env bash
# reports/generate_digest.sh — Daily HTML Digest Report  v1.0.0
# Runs at 07:00 daily via cron.
# Collects all findings from the last 24h and sends an HTML summary email.
# Usage: ./generate_digest.sh [--dry-run] [--verbose] [--since=HOURS]
set -euo pipefail
trap 'echo "[ERROR] Digest failed at line ${LINENO}" >&2; exit 1' ERR

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

# ── Source configuration ──────────────────────────────────────────────────────
CONFIG_FILE="${ROOT_DIR}/config.conf"
[[ -f "$CONFIG_FILE" ]] || { echo "[FATAL] config.conf not found" >&2; exit 1; }
# shellcheck source=../config.conf
source "$CONFIG_FILE"

# Source alert engine for email send function
# shellcheck source=../modules/alert_engine.sh
source "${ROOT_DIR}/modules/alert_engine.sh" 2>/dev/null || true

# ── Runtime flags ─────────────────────────────────────────────────────────────
DRY_RUN=false; VERBOSE=false; SINCE_HOURS=24

for _arg in "$@"; do
    case "$_arg" in
        --dry-run)     DRY_RUN=true        ;;
        --verbose)     VERBOSE=true        ;;
        --since=*)     SINCE_HOURS="${_arg#*=}" ;;
    esac
done

# ── Colours ───────────────────────────────────────────────────────────────────
if [[ -t 1 ]]; then
    GREEN='\033[0;32m'; CYAN='\033[0;36m'; AMBER='\033[0;33m'
    BOLD='\033[1m'; RESET='\033[0m'
else
    GREEN=''; CYAN=''; AMBER=''; BOLD=''; RESET=''
fi

log_d() { echo -e "${CYAN}[$(date '+%H:%M:%S')] [DIGEST]${RESET} $*"; }

# ── Collect findings from last N hours ────────────────────────────────────────
collect_findings() {
    local since_sec=$(( SINCE_HOURS * 3600 ))
    local cutoff=$(( $(date +%s) - since_sec ))
    local findings_dir="${FINDINGS_DIR:-/var/lib/loganalyzer/findings}"

    [[ -d "$findings_dir" ]] || { echo ""; return 0; }

    # Find .findings files modified in the last SINCE_HOURS
    find "$findings_dir" -name "*.findings" -newer \
        <(date -d "@${cutoff}" '+%Y%m%d%H%M%S' 2>/dev/null | xargs -I{} touch -t {} /tmp/la_cutoff_$$ 2>/dev/null; echo /tmp/la_cutoff_$$) \
        2>/dev/null \
        | sort | xargs cat 2>/dev/null || true

    # Cleanup temp
    rm -f /tmp/la_cutoff_$$ 2>/dev/null || true
}

# Alternate: find files by mtime in minutes
collect_findings_v2() {
    local findings_dir="${FINDINGS_DIR:-/var/lib/loganalyzer/findings}"
    [[ -d "$findings_dir" ]] || { echo ""; return 0; }
    find "$findings_dir" -name "*.findings" \
        -mmin -$(( SINCE_HOURS * 60 )) 2>/dev/null \
        | sort | xargs cat 2>/dev/null || true
}

# ── Parse findings into counters and tables ────────────────────────────────────
parse_findings() {
    local raw="$1"
    # Reset counters
    DIGEST_CRITICAL=0; DIGEST_HIGH=0; DIGEST_MEDIUM=0; DIGEST_LOW=0
    DIGEST_AUTH=0; DIGEST_SYSTEM=0; DIGEST_NGINX=0; DIGEST_MYSQL=0
    DIGEST_APP=0; DIGEST_THREATS=0
    DIGEST_FINDINGS_HTML=""
    declare -gA MODULE_COUNTS=()

    while IFS='|' read -r sev mod title detail; do
        [[ -z "$sev" ]] && continue
        case "${sev^^}" in
            CRITICAL) (( DIGEST_CRITICAL++ )) ;;
            HIGH)     (( DIGEST_HIGH++ ))     ;;
            MEDIUM)   (( DIGEST_MEDIUM++ ))   ;;
            LOW)      (( DIGEST_LOW++ ))      ;;
        esac
        case "${mod^^}" in
            AUTH)    (( DIGEST_AUTH++ ))    ;;
            SYSTEM)  (( DIGEST_SYSTEM++ ))  ;;
            NGINX)   (( DIGEST_NGINX++ ))   ;;
            MYSQL)   (( DIGEST_MYSQL++ ))   ;;
            APP)     (( DIGEST_APP++ ))     ;;
            THREATS) (( DIGEST_THREATS++ )) ;;
        esac
        local colour
        case "${sev^^}" in
            CRITICAL) colour="#cc0000" ;;
            HIGH)     colour="#e65c00" ;;
            MEDIUM)   colour="#e6b800" ;;
            LOW)      colour="#0073e6" ;;
            *)        colour="#555555" ;;
        esac
        DIGEST_FINDINGS_HTML+="<tr>
          <td style=\"color:${colour};font-weight:700;\">${sev^^}</td>
          <td>${mod}</td>
          <td>${title}</td>
          <td style=\"font-size:12px;color:#555;\">${detail}</td>
        </tr>"
    done <<< "$raw"
}

# ── System health snapshot ─────────────────────────────────────────────────────
get_system_health() {
    local uptime load mem_info disk_info
    uptime=$(uptime -p 2>/dev/null || uptime 2>/dev/null || echo "n/a")
    load=$(uptime 2>/dev/null | grep -oE 'load average[s]?:.*' | head -1 || echo "n/a")
    mem_info=$(free -h 2>/dev/null | awk '/^Mem:/ {printf "Total: %s | Used: %s | Free: %s", $2, $3, $4}' || echo "n/a")
    disk_info=$(df -h / 2>/dev/null | awk 'NR==2 {printf "/ %s used of %s (%s)", $3, $2, $5}' || echo "n/a")

    echo "<table style='width:100%;border-collapse:collapse;margin:16px 0;'>
      <tr><th style='background:#f0f0f0;text-align:left;padding:8px 12px;font-size:12px;text-transform:uppercase;color:#555;'>Metric</th>
          <th style='background:#f0f0f0;text-align:left;padding:8px 12px;font-size:12px;text-transform:uppercase;color:#555;'>Value</th></tr>
      <tr><td style='padding:8px 12px;border-bottom:1px solid #eee;'>Uptime</td><td style='padding:8px 12px;border-bottom:1px solid #eee;'>${uptime}</td></tr>
      <tr><td style='padding:8px 12px;border-bottom:1px solid #eee;'>Load Average</td><td style='padding:8px 12px;border-bottom:1px solid #eee;'>${load}</td></tr>
      <tr><td style='padding:8px 12px;border-bottom:1px solid #eee;'>Memory</td><td style='padding:8px 12px;border-bottom:1px solid #eee;'>${mem_info}</td></tr>
      <tr><td style='padding:8px 12px;'>Disk (/)</td><td style='padding:8px 12px;'>${disk_info}</td></tr>
    </table>"
}

# ── Recommendations ───────────────────────────────────────────────────────────
get_recommendations() {
    local recs=""
    local raw="${1:-}"

    echo "$raw" | grep -qi "Brute-force\|brute.force" && \
        recs+="<li>🔐 <strong>Block brute-force IPs</strong> — enable <code>AUTO_BLOCK_IP=true</code> or review <code>/etc/hosts.deny</code></li>"
    echo "$raw" | grep -qi "OOM\|Out.of.Memory" && \
        recs+="<li>💾 <strong>Memory pressure detected</strong> — review top memory consumers: <code>ps aux --sort=-%mem | head</code></li>"
    echo "$raw" | grep -qi "disk full\|No space" && \
        recs+="<li>💽 <strong>Disk space critical</strong> — run <code>df -h</code> and <code>du -sh /*</code> to find large directories</li>"
    echo "$raw" | grep -qi "replication" && \
        recs+="<li>🗃️ <strong>MySQL replication error</strong> — check slave status: <code>SHOW SLAVE STATUS\G</code></li>"
    echo "$raw" | grep -qi "scanner\|404 storm" && \
        recs+="<li>🔍 <strong>Web scanner detected</strong> — consider rate limiting in nginx: <code>limit_req_zone</code></li>"
    echo "$raw" | grep -qi "Upstream\|upstream" && \
        recs+="<li>🔗 <strong>Backend failures</strong> — check upstream services and connection pools</li>"
    echo "$raw" | grep -qi "service fail\|entered failed" && \
        recs+="<li>⚙️ <strong>Service crashes</strong> — review: <code>systemctl --failed</code> and <code>journalctl -xe</code></li>"
    echo "$raw" | grep -qi "Root.*login\|root SSH" && \
        recs+="<li>🚫 <strong>Root SSH login</strong> — disable with <code>PermitRootLogin no</code> in <code>/etc/ssh/sshd_config</code></li>"
    echo "$raw" | grep -qi "slow quer" && \
        recs+="<li>🐢 <strong>MySQL slow queries</strong> — run <code>EXPLAIN</code> on slow queries, check missing indexes</li>"

    [[ -z "$recs" ]] && recs="<li>✅ No specific recommendations — system looks healthy</li>"
    echo "$recs"
}

# ── Build HTML email ──────────────────────────────────────────────────────────
build_digest_html() {
    local raw_findings="$1"
    local health_html; health_html=$(get_system_health)
    local recs_html; recs_html=$(get_recommendations "$raw_findings")
    local total=$(( DIGEST_CRITICAL + DIGEST_HIGH + DIGEST_MEDIUM + DIGEST_LOW ))
    local date_range; date_range="$(date -d "${SINCE_HOURS} hours ago" '+%Y-%m-%d %H:%M') → $(date '+%Y-%m-%d %H:%M')"

    local status_colour="#27ae60"; local status_text="ALL CLEAR"
    if (( DIGEST_CRITICAL > 0 )); then status_colour="#cc0000"; status_text="CRITICAL ISSUES"
    elif (( DIGEST_HIGH > 0 ));   then status_colour="#e65c00"; status_text="HIGH ISSUES"
    elif (( DIGEST_MEDIUM > 0 )); then status_colour="#e6b800"; status_text="WARNINGS"
    fi

    cat <<HTML
<!DOCTYPE html>
<html>
<head><meta charset="UTF-8">
<style>
  body    { font-family:'Segoe UI',Arial,sans-serif; background:#f4f4f4; margin:0; padding:0; }
  .wrap   { max-width:760px; margin:30px auto; background:#fff;
            border-radius:8px; overflow:hidden; box-shadow:0 2px 10px rgba(0,0,0,.12); }
  .hdr    { background:#1a1a2e; color:#fff; padding:28px 36px; }
  .hdr h1 { margin:0 0 6px; font-size:22px; }
  .hdr p  { margin:0; opacity:.75; font-size:13px; }
  .status { display:inline-block; padding:4px 14px; border-radius:20px;
            background:${status_colour}; color:#fff; font-weight:700;
            font-size:13px; margin-top:12px; }
  .body   { padding:28px 36px; }
  h2      { font-size:16px; color:#1a1a2e; border-bottom:2px solid #f0f0f0;
            padding-bottom:8px; margin:28px 0 12px; }
  .summary-grid { display:grid; grid-template-columns:repeat(3,1fr); gap:12px; margin:16px 0; }
  .scard  { border-radius:6px; padding:16px; text-align:center; }
  .sc-crit{ background:#fff0f0; border:1px solid #ffcccc; }
  .sc-high{ background:#fff5ee; border:1px solid #ffd9b3; }
  .sc-med { background:#fffde7; border:1px solid #fff176; }
  .sc-low { background:#e8f5fe; border:1px solid #b3dcfc; }
  .sc-mod { background:#f0fff0; border:1px solid #b3f0b3; }
  .sc-tot { background:#f5f0ff; border:1px solid #d9b3ff; }
  .scard .num  { font-size:32px; font-weight:700; margin-bottom:4px; }
  .scard .label{ font-size:11px; text-transform:uppercase; color:#888; }
  table   { width:100%; border-collapse:collapse; margin:12px 0; font-size:13px; }
  th      { background:#f0f0f0; text-align:left; padding:8px 12px;
            font-size:11px; text-transform:uppercase; color:#555; }
  td      { padding:8px 12px; border-bottom:1px solid #eee; vertical-align:top; }
  .mod-row td:first-child { font-weight:600; }
  ul.recs { padding-left:20px; line-height:1.8; font-size:13px; }
  .footer { background:#f9f9f9; padding:16px 36px; font-size:11px; color:#999;
            border-top:1px solid #eee; }
</style></head>
<body>
<div class="wrap">
  <!-- Header -->
  <div class="hdr">
    <h1>📊 Daily Log Digest — $(hostname -f 2>/dev/null || echo unknown)</h1>
    <p>Period: ${date_range}</p>
    <div class="status">${status_text}</div>
  </div>

  <div class="body">
    <!-- Severity summary -->
    <h2>Findings Overview</h2>
    <div class="summary-grid">
      <div class="scard sc-crit"><div class="num" style="color:#cc0000">${DIGEST_CRITICAL}</div><div class="label">Critical</div></div>
      <div class="scard sc-high"><div class="num" style="color:#e65c00">${DIGEST_HIGH}</div><div class="label">High</div></div>
      <div class="scard sc-med"><div class="num" style="color:#e6b800">${DIGEST_MEDIUM}</div><div class="label">Medium</div></div>
      <div class="scard sc-low"><div class="num" style="color:#0073e6">${DIGEST_LOW}</div><div class="label">Low</div></div>
      <div class="scard sc-tot"><div class="num" style="color:#7c3aed">${total}</div><div class="label">Total</div></div>
    </div>

    <!-- By module -->
    <h2>Findings by Module</h2>
    <table>
      <tr><th>Module</th><th>Findings</th><th>Focus</th></tr>
      <tr class="mod-row"><td>🔐 AUTH</td><td>${DIGEST_AUTH}</td><td>SSH logins, brute-force, sudo events</td></tr>
      <tr class="mod-row"><td>⚙️ SYSTEM</td><td>${DIGEST_SYSTEM}</td><td>OOM, kernel, hardware, services</td></tr>
      <tr class="mod-row"><td>🌐 NGINX</td><td>${DIGEST_NGINX}</td><td>Web errors, scanners, slow requests</td></tr>
      <tr class="mod-row"><td>🗃️ MYSQL</td><td>${DIGEST_MYSQL}</td><td>DB errors, slow queries, replication</td></tr>
      <tr class="mod-row"><td>📦 APP</td><td>${DIGEST_APP}</td><td>Exceptions, API errors, timeouts</td></tr>
      <tr class="mod-row"><td>🛡️ THREATS</td><td>${DIGEST_THREATS}</td><td>Cross-log correlated threat detections</td></tr>
    </table>

    <!-- All findings -->
$(if [[ -n "${DIGEST_FINDINGS_HTML:-}" ]]; then
  echo "<h2>All Findings</h2>"
  echo "<table><tr><th>Severity</th><th>Module</th><th>Finding</th><th>Detail</th></tr>"
  echo "${DIGEST_FINDINGS_HTML}"
  echo "</table>"
else
  echo "<h2>All Findings</h2><p style='color:#27ae60;font-weight:600;'>✅ No findings in the last ${SINCE_HOURS} hours — system is healthy.</p>"
fi)

    <!-- System health -->
    <h2>System Health</h2>
    ${health_html}

    <!-- Recommendations -->
    <h2>Recommendations</h2>
    <ul class="recs">${recs_html}</ul>

    <p style="font-size:12px;color:#888;margin-top:24px;">
      Generated by Log Analyzer & Alert System v${VERSION:-1.0.0}<br>
      Findings directory: ${FINDINGS_DIR:-/var/lib/loganalyzer/findings}
    </p>
  </div>
  <div class="footer">
    This is an automated daily digest. Configure digest time via DIGEST_CRON in config.conf.
  </div>
</div>
</body></html>
HTML
}

# ── Main ──────────────────────────────────────────────────────────────────────
main() {
    log_d "Starting daily digest generation (last ${SINCE_HOURS}h)"

    $DRY_RUN && log_d "[DRY-RUN] No email will be sent"

    # Collect
    local raw_findings
    raw_findings=$(collect_findings_v2)

    # Parse
    DIGEST_CRITICAL=0; DIGEST_HIGH=0; DIGEST_MEDIUM=0; DIGEST_LOW=0
    DIGEST_AUTH=0; DIGEST_SYSTEM=0; DIGEST_NGINX=0; DIGEST_MYSQL=0
    DIGEST_APP=0; DIGEST_THREATS=0
    DIGEST_FINDINGS_HTML=""
    declare -gA MODULE_COUNTS=()
    [[ -n "$raw_findings" ]] && parse_findings "$raw_findings"

    local total=$(( DIGEST_CRITICAL + DIGEST_HIGH + DIGEST_MEDIUM + DIGEST_LOW ))
    log_d "Collected ${total} finding(s) — CRIT:${DIGEST_CRITICAL} HIGH:${DIGEST_HIGH} MED:${DIGEST_MEDIUM} LOW:${DIGEST_LOW}"

    # Build HTML
    local html; html=$(build_digest_html "$raw_findings")

    # Send
    if ${DRY_RUN:-false}; then
        log_d "[DRY-RUN] Digest HTML generated (not sent)"
        return 0
    fi

    local subject="[LogDigest] $(date '+%Y-%m-%d') — ${total} finding(s) on $(hostname -s)"
    [[ -z "${ALERT_EMAIL:-}" ]] && { log_d "ALERT_EMAIL not set — digest not sent"; return 0; }

    if command -v mailx &>/dev/null; then
        echo "$html" | mailx -a "Content-Type: text/html" \
            -s "$subject" \
            -r "${ALERT_FROM:-loganalyzer@localhost}" \
            "$ALERT_EMAIL" 2>/dev/null \
        && log_d "Digest sent via mailx → ${ALERT_EMAIL}" \
        || log_d "mailx failed"

    elif command -v sendmail &>/dev/null; then
        {
            echo "To: ${ALERT_EMAIL}"
            echo "From: ${ALERT_FROM:-loganalyzer@localhost}"
            echo "Subject: ${subject}"
            echo "Content-Type: text/html; charset=UTF-8"
            echo "MIME-Version: 1.0"
            echo ""
            echo "$html"
        } | sendmail -t 2>/dev/null \
        && log_d "Digest sent via sendmail → ${ALERT_EMAIL}" \
        || log_d "sendmail failed"
    else
        log_d "No mail agent found — saving digest to ${DIGEST_LOG:-/var/log/loganalyzer/digest.log}"
        echo "$html" > "${DIGEST_LOG:-/var/log/loganalyzer/digest.log}"
    fi

    log_d "Daily digest complete"
}

main "$@"
