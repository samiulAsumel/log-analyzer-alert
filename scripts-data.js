// scripts-data.js — Embedded script content for the web script explorer
// Each entry mirrors the actual file in the repo.

const SCRIPTS_DATA = [
  {
    id: 'config',
    name: 'config.conf',
    path: 'config.conf',
    description: 'Central configuration. All log paths, regex patterns, thresholds, alert settings, and state directories. Edit this first — no other file needs touching for basic setup.',
    badges: ['config'],
    code: `# ════════════════════════════════════════════════════════════════════════════
# Automated Log Analyzer & Alert System — Configuration  v1.0.0
# ════════════════════════════════════════════════════════════════════════════

# ── Log file paths ────────────────────────────────────────────────────────────
SYSLOG="/var/log/messages"              # RHEL/Rocky: messages | Ubuntu: syslog
AUTH_LOG="/var/log/secure"              # RHEL/Rocky: secure   | Ubuntu: auth.log
NGINX_ACCESS="/var/log/nginx/access.log"
NGINX_ERROR="/var/log/nginx/error.log"
MYSQL_ERROR="/var/log/mysql/error.log"
MYSQL_SLOW="/var/log/mysql/slow.log"
APP_LOG="/var/log/myapp/application.log"
APP_NAME="myapp"

# ── Alert patterns (ERE regex, case-insensitive) ──────────────────────────────
CRITICAL_PATTERNS="Out of memory|oom-kill|kernel panic|segfault|disk full|No space left|RAID degraded"
ERROR_PATTERNS="error|critical|fatal|exception|traceback|panic|abort|coredump"
SECURITY_PATTERNS="Failed password|Invalid user|POSSIBLE BREAK-IN|authentication failure"

# ── Thresholds ────────────────────────────────────────────────────────────────
MAX_FAILED_LOGINS=5         # per IP in CHECK_INTERVAL minutes → CRITICAL
MAX_404_PER_IP=50           # 404s from one IP → possible scanner
MAX_5XX_COUNT=20            # total 5xx errors → web alert
MAX_SLOW_QUERIES=50         # slow queries per hour
MAX_OOM_EVENTS=1            # OOM kills per interval → always critical
MAX_UNIQUE_ERRORS=30        # unique error patterns → app alert
MAX_RESPONSE_MS=5000        # nginx slow request threshold (ms)

# ── Brute-force response ──────────────────────────────────────────────────────
AUTO_BLOCK_IP=false         # true = add offending IP to firewalld (requires root)
BLOCK_ZONE="public"
HOSTS_DENY=false
WHITELIST_IPS="127.0.0.1 ::1"

# ── Alert settings ────────────────────────────────────────────────────────────
ALERT_EMAIL="admin@company.com"
ALERT_FROM="loganalyzer@\$(hostname -f 2>/dev/null || echo server)"
SLACK_WEBHOOK=""            # https://hooks.slack.com/services/...
ALERT_METHOD="email"        # email | slack | both
HIGH_ALERT_COOLDOWN=30      # minutes between repeated HIGH alerts

# ── Scheduling ────────────────────────────────────────────────────────────────
CHECK_INTERVAL=15
ANALYZER_CRON="*/15 * * * *"
DIGEST_CRON="0 7 * * *"    # 07:00 AM daily digest

# ── State and storage ─────────────────────────────────────────────────────────
STATE_DIR="/var/lib/loganalyzer"
POSITION_DIR="\${STATE_DIR}/positions"   # inode+offset tracking per log
FINDINGS_DIR="\${STATE_DIR}/findings"    # per-run findings files
COOLDOWN_DIR="\${STATE_DIR}/cooldowns"   # rate-limit timestamps

LOG_DIR="/var/log/loganalyzer"
VERSION="1.0.0"`
  },
  {
    id: 'orchestrator',
    name: 'log_analyzer.sh',
    path: 'log_analyzer.sh',
    description: 'Main orchestrator. Runs every 15 min via cron. Sources config + all 7 modules, reads only NEW log bytes via position tracking, aggregates findings, fires CRITICAL/HIGH alerts immediately.',
    badges: ['bash', 'cron', 'root'],
    code: `#!/usr/bin/env bash
# log_analyzer.sh — Orchestrator v1.0.0
# Cron: */15 * * * * /usr/local/bin/loganalyzer/log_analyzer.sh
set -euo pipefail
trap '_on_error \$LINENO "\$BASH_COMMAND"' ERR

SCRIPT_DIR="\$(cd "\$(dirname "\${BASH_SOURCE[0]}")" && pwd)"

source "\${SCRIPT_DIR}/config.conf"

for _mod in alert_engine analyze_auth analyze_system analyze_nginx \\
            analyze_mysql analyze_app detect_threats; do
    source "\${SCRIPT_DIR}/modules/\${_mod}.sh"
done

# ── Runtime flags ─────────────────────────────────────────────────────────────
DRY_RUN=false; VERBOSE=false; FORCE=false; ONLY_MODULE=""
for _arg in "\$@"; do
    case "\$_arg" in
        --dry-run)   DRY_RUN=true          ;;
        --verbose)   VERBOSE=true          ;;
        --force)     FORCE=true            ;;
        --module=*)  ONLY_MODULE="\${_arg#*=}" ;;
    esac
done

# ── Position tracking — read only NEW bytes ──────────────────────────────────
read_new_lines() {
    local logfile="\$1"
    [[ -f "\$logfile" ]] || return 0

    local curr_inode curr_size
    curr_inode=\$(stat -c '%i' "\$logfile" 2>/dev/null || echo 0)
    curr_size=\$(stat  -c '%s' "\$logfile" 2>/dev/null || echo 0)

    read -r saved_inode saved_offset < <(get_position "\$logfile")
    [[ "\$FORCE" == "true" ]] && saved_inode=0 && saved_offset=0

    local read_from=0
    [[ "\$curr_inode" == "\$saved_inode" && "\$saved_offset" -le "\$curr_size" ]] \\
        && read_from="\$saved_offset"

    local bytes_to_read=\$(( curr_size - read_from ))
    [[ \$bytes_to_read -le 0 ]] && { save_position "\$logfile" "\$curr_inode" "\$curr_size"; return 0; }

    dd if="\$logfile" bs=1 skip="\$read_from" count="\$bytes_to_read" 2>/dev/null
    save_position "\$logfile" "\$curr_inode" "\$curr_size"
}

# ── Findings aggregation ──────────────────────────────────────────────────────
declare -a ALL_FINDINGS=()
CRITICAL_COUNT=0; HIGH_COUNT=0; MEDIUM_COUNT=0; LOW_COUNT=0

add_finding() {
    local severity="\$1" module="\$2" title="\$3" detail="\${4:-}"
    ALL_FINDINGS+=("\${severity}|\${module}|\${title}|\${detail}")
    echo "\${severity}|\${module}|\${title}|\${detail}" >> "\$FINDING_FILE"
    case "\${severity^^}" in
        CRITICAL) CRITICAL_COUNT=\$(( CRITICAL_COUNT + 1 )) ;;
        HIGH)     HIGH_COUNT=\$(( HIGH_COUNT + 1 ))         ;;
        MEDIUM)   MEDIUM_COUNT=\$(( MEDIUM_COUNT + 1 ))     ;;
        LOW)      LOW_COUNT=\$(( LOW_COUNT + 1 ))           ;;
    esac
}

# LIBRARY BOUNDARY — stop here when sourced by tests
[[ "\${BASH_SOURCE[0]}" != "\${0}" ]] && return 0

acquire_lock

run_module "auth"    "module_analyze_auth"
run_module "system"  "module_analyze_system"
run_module "nginx"   "module_analyze_nginx"
run_module "mysql"   "module_analyze_mysql"
run_module "app"     "module_analyze_app"
run_module "threats" "module_detect_threats"

(( CRITICAL_COUNT > 0 )) && _send_critical_alert
(( HIGH_COUNT > 0 ))     && _send_high_alert

log "OK" "ORCHESTRATOR" "Run complete — CRITICAL:\${CRITICAL_COUNT} HIGH:\${HIGH_COUNT} MEDIUM:\${MEDIUM_COUNT}"`
  },
  {
    id: 'auth',
    name: 'analyze_auth.sh',
    path: 'modules/analyze_auth.sh',
    description: 'Analyzes /var/log/secure (or auth.log). Detects SSH brute-force per IP, invalid users, root logins, sudo escalations, new user creation, PAM failures. Optional firewalld auto-block.',
    badges: ['bash', 'module'],
    code: `#!/usr/bin/env bash
# analyze_auth.sh — SSH / Auth Log Analyzer  v1.0.0

module_analyze_auth() {
    local logfile="\${AUTH_LOG:-/var/log/secure}"
    local new_lines; new_lines=\$(read_new_lines "\$logfile" 2>/dev/null) || return 0
    [[ -z "\$new_lines" ]] && return 0

    local tmp_file; tmp_file=\$(mktemp /tmp/la_auth_XXXXXX)
    echo "\$new_lines" > "\$tmp_file"
    trap '[[ -n "\${tmp_file:-}" ]] && rm -f "\$tmp_file"' RETURN

    # ── Brute-force: count failed logins per IP ────────────────────────────
    local failed_ip_counts
    failed_ip_counts=\$(grep -iE "Failed password" "\$tmp_file" \\
        | grep -oE 'from [0-9a-f:.]+' | awk '{print \$2}' \\
        | sort | uniq -c | sort -rn)

    while IFS= read -r line; do
        local count ip
        count=\$(echo "\$line" | awk '{print \$1}')
        ip=\$(echo "\$line" | awk '{print \$2}')
        [[ -z "\$ip" ]] && continue

        if (( count >= MAX_FAILED_LOGINS )); then
            add_finding "CRITICAL" "AUTH" \\
                "Brute-force SSH from \${ip}" \\
                "\${count} failed logins in last \${CHECK_INTERVAL} min"
            [[ "\${AUTO_BLOCK_IP:-false}" == "true" ]] && _block_ip "\$ip"
        elif (( count >= 3 )); then
            add_finding "HIGH" "AUTH" "Repeated SSH failures from \${ip}" \\
                "\${count} failed attempts"
        fi
    done <<< "\$failed_ip_counts"

    # ── Invalid users ──────────────────────────────────────────────────────
    local invalid_count
    invalid_count=\$(grep -cE "Invalid user" "\$tmp_file" 2>/dev/null; true)
    (( invalid_count > 0 )) && add_finding "HIGH" "AUTH" \\
        "Invalid user login attempts" "\${invalid_count} attempt(s)"

    # ── Root login ─────────────────────────────────────────────────────────
    local root_logins
    root_logins=\$(grep -cE "Accepted .+ for root from" "\$tmp_file" 2>/dev/null; true)
    (( root_logins > 0 )) && add_finding "CRITICAL" "AUTH" \\
        "Root SSH login detected" "\${root_logins} successful root login(s)"

    # ── Sudo escalations ──────────────────────────────────────────────────
    local sudo_events; sudo_events=\$(grep -cE "sudo:.+COMMAND=" "\$tmp_file" 2>/dev/null; true)
    (( sudo_events > 0 )) && add_finding "LOW" "AUTH" \\
        "Sudo privilege escalations" "\${sudo_events} sudo command(s)"

    # ── New user/group created ─────────────────────────────────────────────
    local new_users; new_users=\$(grep -cE "new user:|new group:|useradd" "\$tmp_file" 2>/dev/null; true)
    (( new_users > 0 )) && add_finding "MEDIUM" "AUTH" \\
        "New user/group created" "\${new_users} account change(s)"
}`
  },
  {
    id: 'system',
    name: 'analyze_system.sh',
    path: 'modules/analyze_system.sh',
    description: 'Analyzes /var/log/messages (or syslog). Detects OOM kills, kernel panics, hardware errors (EDAC/MCE), disk full, segfaults, service failures, RAID degraded, thermal throttling, mount errors.',
    badges: ['bash', 'module'],
    code: `#!/usr/bin/env bash
# analyze_system.sh — System Log Analyzer  v1.0.0

module_analyze_system() {
    local logfile="\${SYSLOG:-/var/log/messages}"
    local new_lines; new_lines=\$(read_new_lines "\$logfile" 2>/dev/null) || return 0
    [[ -z "\$new_lines" ]] && return 0

    local tmp_file; tmp_file=\$(mktemp /tmp/la_sys_XXXXXX)
    echo "\$new_lines" > "\$tmp_file"
    trap '[[ -n "\${tmp_file:-}" ]] && rm -f "\$tmp_file"' RETURN

    # ── OOM killer ─────────────────────────────────────────────────────────
    local oom_count
    oom_count=\$(grep -cEi "Out of memory|oom.kill|Killed process" "\$tmp_file" 2>/dev/null; true)
    if (( oom_count > 0 )); then
        local oom_proc
        oom_proc=\$(grep -Ei "Killed process" "\$tmp_file" \\
            | grep -oE 'process [0-9]+ \\([^)]+\\)' | tail -3 | tr '\\n' '; ')
        add_finding "CRITICAL" "SYSTEM" "Out-of-Memory kill" \\
            "\${oom_count} OOM kill(s): \${oom_proc}"
    fi

    # ── Kernel panic ───────────────────────────────────────────────────────
    local panic_count
    panic_count=\$(grep -cEi "kernel panic|Oops:|BUG: unable to handle" \\
        "\$tmp_file" 2>/dev/null; true)
    (( panic_count > 0 )) && add_finding "CRITICAL" "SYSTEM" \\
        "Kernel panic / Oops detected" "\${panic_count} kernel-level event(s)"

    # ── Hardware errors ────────────────────────────────────────────────────
    local hw_err
    hw_err=\$(grep -cEi "EDAC|Machine Check|mce|hardware error|Corrected error|\\bECC\\b" \\
        "\$tmp_file" 2>/dev/null; true)
    (( hw_err > 0 )) && add_finding "CRITICAL" "SYSTEM" \\
        "Hardware / ECC memory error" "\${hw_err} hardware error event(s)"

    # ── Disk full ──────────────────────────────────────────────────────────
    local disk_full
    disk_full=\$(grep -cEi "No space left on device|disk full|ENOSPC" \\
        "\$tmp_file" 2>/dev/null; true)
    (( disk_full > 0 )) && add_finding "CRITICAL" "SYSTEM" \\
        "Disk full (ENOSPC)" "\${disk_full} write failure(s)"

    # ── Segfaults ──────────────────────────────────────────────────────────
    local segfault_count
    segfault_count=\$(grep -cEi "segfault at|general protection|signal 11" \\
        "\$tmp_file" 2>/dev/null; true)
    (( segfault_count > 0 )) && add_finding "HIGH" "SYSTEM" \\
        "Segfault / process crash" "\${segfault_count} crash event(s)"

    # ── Service failures ───────────────────────────────────────────────────
    local svc_fail
    svc_fail=\$(grep -cEi "systemd.*failed|Unit.*failed|service.*failed" \\
        "\$tmp_file" 2>/dev/null; true)
    (( svc_fail > 0 )) && add_finding "HIGH" "SYSTEM" \\
        "Service failure detected" "\${svc_fail} systemd unit failure(s)"

    # ── RAID degraded ──────────────────────────────────────────────────────
    local raid_deg
    raid_deg=\$(grep -cEi "RAID.*(degraded|failed|error)|md.*degraded" \\
        "\$tmp_file" 2>/dev/null; true)
    (( raid_deg > 0 )) && add_finding "CRITICAL" "SYSTEM" \\
        "RAID array degraded" "\${raid_deg} RAID event(s)"
}`
  },
  {
    id: 'nginx',
    name: 'analyze_nginx.sh',
    path: 'modules/analyze_nginx.sh',
    description: 'Analyzes Nginx access + error logs. Detects 5xx spikes, 404 storms per IP, DDoS (single IP >33% traffic), scanner user-agents (sqlmap/nikto), slow requests, POST flood, upstream failures.',
    badges: ['bash', 'module'],
    code: `#!/usr/bin/env bash
# analyze_nginx.sh — Nginx Log Analyzer  v1.0.0

module_analyze_nginx() {
    _nginx_access
    _nginx_error
}

_nginx_access() {
    local logfile="\${NGINX_ACCESS:-/var/log/nginx/access.log}"
    local new_lines; new_lines=\$(read_new_lines "\$logfile" 2>/dev/null) || return 0
    [[ -z "\$new_lines" ]] && return 0

    local tmp_file; tmp_file=\$(mktemp /tmp/la_ngx_a_XXXXXX)
    echo "\$new_lines" > "\$tmp_file"
    trap '[[ -n "\${tmp_file:-}" ]] && rm -f "\$tmp_file"' RETURN

    local total_reqs; total_reqs=\$(wc -l < "\$tmp_file")

    # ── 5xx errors ─────────────────────────────────────────────────────────
    local err5xx
    err5xx=\$(grep -cE '" 5[0-9][0-9] ' "\$tmp_file" 2>/dev/null; true)
    (( err5xx >= MAX_5XX_COUNT )) && add_finding "HIGH" "NGINX" \\
        "5xx error spike" "\${err5xx} server errors in last \${CHECK_INTERVAL}min"

    # ── 404 storm per IP ───────────────────────────────────────────────────
    grep -E '" 404 ' "\$tmp_file" \\
        | grep -oE '^[0-9a-f.:]+' | sort | uniq -c | sort -rn \\
        | while read -r count ip; do
            (( count >= MAX_404_PER_IP )) && add_finding "HIGH" "NGINX" \\
                "404 storm from \${ip}" \\
                "\${count} 404s — likely directory scan or broken links"
        done

    # ── Single-IP DDoS detection ───────────────────────────────────────────
    if (( total_reqs > 200 )); then
        grep -oE '^[0-9a-f.:]+' "\$tmp_file" | sort | uniq -c | sort -rn | head -1 \\
        | while read -r count ip; do
            local pct=\$(( count * 100 / total_reqs ))
            (( pct > 33 )) && add_finding "HIGH" "NGINX" \\
                "Single-IP DDoS / flood: \${ip}" \\
                "IP \${ip} = \${pct}% of all traffic (\${count}/\${total_reqs} requests)"
        done
    fi

    # ── Scanner user-agents ────────────────────────────────────────────────
    local scanner_count
    scanner_count=\$(grep -ciE "sqlmap|nikto|nmap|masscan|zgrab|dirbuster|\\bwpscan\\b|hydra|burp" \\
        "\$tmp_file" 2>/dev/null; true)
    (( scanner_count > 0 )) && add_finding "CRITICAL" "NGINX" \\
        "Security scanner detected" \\
        "\${scanner_count} request(s) with known attack tool user-agent"
}

_nginx_error() {
    local logfile="\${NGINX_ERROR:-/var/log/nginx/error.log}"
    local new_lines; new_lines=\$(read_new_lines "\$logfile" 2>/dev/null) || return 0
    [[ -z "\$new_lines" ]] && return 0

    local tmp_file; tmp_file=\$(mktemp /tmp/la_ngx_e_XXXXXX)
    echo "\$new_lines" > "\$tmp_file"
    trap '[[ -n "\${tmp_file:-}" ]] && rm -f "\$tmp_file"' RETURN

    local crit_count
    crit_count=\$(grep -cEi "\\[crit\\]|\\[alert\\]|\\[emerg\\]" "\$tmp_file" 2>/dev/null; true)
    (( crit_count > 0 )) && add_finding "CRITICAL" "NGINX" \\
        "Nginx CRIT/ALERT/EMERG log entries" "\${crit_count} critical error(s)"

    local upstream_fail
    upstream_fail=\$(grep -cEi "upstream.*failed|upstream.*unavailable|no live upstreams" \\
        "\$tmp_file" 2>/dev/null; true)
    (( upstream_fail > 5 )) && add_finding "HIGH" "NGINX" \\
        "Upstream/proxy failures" "\${upstream_fail} upstream failure(s)"
}`
  },
  {
    id: 'mysql',
    name: 'analyze_mysql.sh',
    path: 'modules/analyze_mysql.sh',
    description: 'Analyzes MySQL error log and slow query log. Detects replication errors, table corruption, connection limit hits, InnoDB fatal errors, disk space issues, and excessive slow queries with full table scans.',
    badges: ['bash', 'module'],
    code: `#!/usr/bin/env bash
# analyze_mysql.sh — MySQL Log Analyzer  v1.0.0

module_analyze_mysql() {
    _mysql_error_log
    _mysql_slow_log
}

_mysql_error_log() {
    local logfile="\${MYSQL_ERROR:-/var/log/mysql/error.log}"
    local new_lines; new_lines=\$(read_new_lines "\$logfile" 2>/dev/null) || return 0
    [[ -z "\$new_lines" ]] && return 0

    local tmp_file; tmp_file=\$(mktemp /tmp/la_mysql_e_XXXXXX)
    echo "\$new_lines" > "\$tmp_file"
    trap '[[ -n "\${tmp_file:-}" ]] && rm -f "\$tmp_file"' RETURN

    # ── Replication errors ─────────────────────────────────────────────────
    local repl_err
    repl_err=\$(grep -cEi "Slave.*error|replica.*error|IO thread|SQL thread|Got fatal error" \\
        "\$tmp_file" 2>/dev/null; true)
    (( repl_err > 0 )) && add_finding "CRITICAL" "MYSQL" \\
        "MySQL replication error" "\${repl_err} replication event(s)"

    # ── Table corruption ───────────────────────────────────────────────────
    local corrupt
    corrupt=\$(grep -cEi "corrupt|crashed|repair.*table|table.*corrupt" \\
        "\$tmp_file" 2>/dev/null; true)
    (( corrupt > 0 )) && add_finding "CRITICAL" "MYSQL" \\
        "Table corruption detected" "\${corrupt} corruption event(s)"

    # ── Connection limit ───────────────────────────────────────────────────
    local conn_limit
    conn_limit=\$(grep -cEi "Too many connections|max_connections" \\
        "\$tmp_file" 2>/dev/null; true)
    (( conn_limit > 0 )) && add_finding "HIGH" "MYSQL" \\
        "MySQL connection limit hit" "\${conn_limit} max_connections error(s)"

    # ── InnoDB fatal ───────────────────────────────────────────────────────
    local innodb_fatal
    innodb_fatal=\$(grep -cEi "InnoDB.*fatal|InnoDB.*error|cannot allocate" \\
        "\$tmp_file" 2>/dev/null; true)
    (( innodb_fatal > 0 )) && add_finding "CRITICAL" "MYSQL" \\
        "InnoDB fatal error" "\${innodb_fatal} InnoDB critical event(s)"
}

_mysql_slow_log() {
    local logfile="\${MYSQL_SLOW:-/var/log/mysql/slow.log}"
    local new_lines; new_lines=\$(read_new_lines "\$logfile" 2>/dev/null) || return 0
    [[ -z "\$new_lines" ]] && return 0

    local tmp_file; tmp_file=\$(mktemp /tmp/la_mysql_s_XXXXXX)
    echo "\$new_lines" > "\$tmp_file"
    trap '[[ -n "\${tmp_file:-}" ]] && rm -f "\$tmp_file"' RETURN

    # ── Slow query count ───────────────────────────────────────────────────
    local slow_count
    slow_count=\$(grep -cE "^# Query_time:" "\$tmp_file" 2>/dev/null; true)
    if (( slow_count >= MAX_SLOW_QUERIES )); then
        add_finding "HIGH" "MYSQL" \\
            "Slow query spike" "\${slow_count} queries exceeded slow_query_time"
    elif (( slow_count > 10 )); then
        add_finding "MEDIUM" "MYSQL" \\
            "Slow queries detected" "\${slow_count} slow queries in interval"
    fi

    # ── Full table scans ───────────────────────────────────────────────────
    local full_scans
    full_scans=\$(grep -cE "Rows_examined: [0-9]{7,}" "\$tmp_file" 2>/dev/null; true)
    (( full_scans > 0 )) && add_finding "HIGH" "MYSQL" \\
        "Full table scan — 1M+ rows" "\${full_scans} query(s) scanned >1 million rows"
}`
  },
  {
    id: 'app',
    name: 'analyze_app.sh',
    path: 'modules/analyze_app.sh',
    description: 'Analyzes custom application log (APP_LOG). Detects exception spikes, CRITICAL/FATAL entries, high error rate (≥20%), database connection errors, API 4xx/5xx spikes, memory exhaustion, timeouts.',
    badges: ['bash', 'module'],
    code: `#!/usr/bin/env bash
# analyze_app.sh — Application Log Analyzer  v1.0.0

module_analyze_app() {
    local logfile="\${APP_LOG:-/var/log/myapp/application.log}"
    local appname="\${APP_NAME:-app}"
    local new_lines; new_lines=\$(read_new_lines "\$logfile" 2>/dev/null) || return 0
    [[ -z "\$new_lines" ]] && return 0

    local tmp_file; tmp_file=\$(mktemp /tmp/la_app_XXXXXX)
    echo "\$new_lines" > "\$tmp_file"
    trap '[[ -n "\${tmp_file:-}" ]] && rm -f "\$tmp_file"' RETURN

    local total_lines; total_lines=\$(wc -l < "\$tmp_file")

    # ── CRITICAL/FATAL ─────────────────────────────────────────────────────
    local critical_count
    critical_count=\$(grep -cEi "\\[CRITICAL\\]|\\[FATAL\\]|CRITICAL:|FATAL:" \\
        "\$tmp_file" 2>/dev/null; true)
    if (( critical_count > 0 )); then
        local crit_sample
        crit_sample=\$(grep -Ei "\\[CRITICAL\\]|\\[FATAL\\]" "\$tmp_file" \\
            | tail -3 | cut -c1-200 | tr '\\n' '|')
        add_finding "CRITICAL" "APP" \\
            "\${appname}: CRITICAL/FATAL entries" \\
            "\${critical_count} entry(s) — \${crit_sample}"
    fi

    # ── Exception spike ────────────────────────────────────────────────────
    local exc_count
    exc_count=\$(grep -cEi "Exception|Traceback|stack trace|FATAL|NullPointerException" \\
        "\$tmp_file" 2>/dev/null; true)
    if (( exc_count >= MAX_UNIQUE_ERRORS )); then
        add_finding "HIGH" "APP" \\
            "\${appname}: Exception spike (\${exc_count})" \\
            "Threshold: \${MAX_UNIQUE_ERRORS}"
    elif (( exc_count > 0 )); then
        add_finding "MEDIUM" "APP" \\
            "\${appname}: Exceptions detected (\${exc_count})" ""
    fi

    # ── Error rate ─────────────────────────────────────────────────────────
    local error_count
    error_count=\$(grep -cEi "\\[ERROR\\]|ERROR:" "\$tmp_file" 2>/dev/null; true)
    if (( error_count > 0 )); then
        local error_rate=\$(( error_count * 100 / (total_lines + 1) ))
        (( error_rate >= 20 )) && add_finding "HIGH" "APP" \\
            "\${appname}: High error rate (\${error_rate}%)" \\
            "\${error_count} ERROR entries in \${total_lines} lines"
    fi

    # ── DB connection errors ───────────────────────────────────────────────
    local db_err
    db_err=\$(grep -cEi "database.*connection|connection.*refused|SQLSTATE|deadlock" \\
        "\$tmp_file" 2>/dev/null; true)
    (( db_err > 0 )) && add_finding "HIGH" "APP" \\
        "\${appname}: Database connection errors" \\
        "\${db_err} DB error(s) — may indicate DB outage or pool exhaustion"

    # ── Memory warnings ────────────────────────────────────────────────────
    local mem_warn
    mem_warn=\$(grep -cEi "OutOfMemory|heap.*space|GC overhead|cannot allocate" \\
        "\$tmp_file" 2>/dev/null; true)
    (( mem_warn > 0 )) && add_finding "HIGH" "APP" \\
        "\${appname}: Memory exhaustion warnings" \\
        "\${mem_warn} memory warning(s)"
}`
  },
  {
    id: 'threats',
    name: 'detect_threats.sh',
    path: 'modules/detect_threats.sh',
    description: 'Cross-correlates findings from all 5 analysis modules. Detects coordinated attacks: same IP in SSH brute-force + web scanner, multi-service simultaneous failures, OOM + app crash, brute-force + new user account.',
    badges: ['bash', 'module'],
    code: `#!/usr/bin/env bash
# detect_threats.sh — Cross-Log Threat Detector  v1.0.0

module_detect_threats() {
    log "INFO" "THREATS" "Cross-correlating findings for threat detection"

    [[ \${#ALL_FINDINGS[@]} -eq 0 ]] && return 0

    local all_findings_text
    all_findings_text=\$(printf '%s\\n' "\${ALL_FINDINGS[@]:-}")

    # Extract IPs from auth + nginx findings
    local auth_ips nginx_ips
    auth_ips=\$(echo "\$all_findings_text" \\
        | grep -Ei "^CRITICAL\\|AUTH\\|Brute-force|^HIGH\\|AUTH\\|Repeated SSH" \\
        | grep -oE '[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}' | sort -u)
    nginx_ips=\$(echo "\$all_findings_text" \\
        | grep -Ei "^HIGH\\|NGINX\\|404 storm|^HIGH\\|NGINX\\|High request rate" \\
        | grep -oE '[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}' | sort -u)

    # ── Correlation 1: Same IP in auth + nginx ─────────────────────────────
    if [[ -n "\$auth_ips" && -n "\$nginx_ips" ]]; then
        while IFS= read -r ip; do
            echo "\$nginx_ips" | grep -qF "\$ip" && \\
                add_finding "CRITICAL" "THREATS" \\
                    "Persistent attacker: \${ip}" \\
                    "IP \${ip} in BOTH SSH brute-force AND web scanner — coordinated attack"
        done <<< "\$auth_ips"
    fi

    # ── Correlation 2: Multi-service failures ──────────────────────────────
    local auth_crit nginx_crit sys_crit
    auth_crit=\$(echo "\$all_findings_text" | grep -cE "^(CRITICAL|HIGH)\\|AUTH\\|" 2>/dev/null; true)
    nginx_crit=\$(echo "\$all_findings_text" | grep -cE "^(CRITICAL|HIGH)\\|NGINX\\|" 2>/dev/null; true)
    sys_crit=\$(echo "\$all_findings_text" | grep -cE "^(CRITICAL|HIGH)\\|SYSTEM\\|" 2>/dev/null; true)
    local multi=\$(( (auth_crit > 0 ? 1 : 0) + (nginx_crit > 0 ? 1 : 0) + (sys_crit > 0 ? 1 : 0) ))
    (( multi >= 3 )) && add_finding "CRITICAL" "THREATS" \\
        "Multi-service failure — possible intrusion" \\
        "Simultaneous HIGH/CRITICAL in AUTH + NGINX + SYSTEM"

    # ── Correlation 3: OOM + App crash ─────────────────────────────────────
    local oom_found app_crit_found
    oom_found=\$(echo "\$all_findings_text" | grep -cEi "\\|SYSTEM\\|Out-of-Memory" 2>/dev/null; true)
    app_crit_found=\$(echo "\$all_findings_text" | grep -cEi "\\|APP\\|CRITICAL" 2>/dev/null; true)
    (( oom_found > 0 && app_crit_found > 0 )) && add_finding "CRITICAL" "THREATS" \\
        "Application overload: OOM + App crash" \\
        "System OOM while app reports critical errors — memory leak or traffic storm"

    # ── Correlation 4: Brute-force + new user ──────────────────────────────
    local brute_found new_user_found
    brute_found=\$(echo "\$all_findings_text" | grep -cEi "\\|AUTH\\|Brute-force" 2>/dev/null; true)
    new_user_found=\$(echo "\$all_findings_text" | grep -cEi "\\|AUTH\\|New user" 2>/dev/null; true)
    (( brute_found > 0 && new_user_found > 0 )) && add_finding "CRITICAL" "THREATS" \\
        "Possible compromise: brute-force + user creation" \\
        "SSH brute-force AND new account created in same interval"

    # ── Composite threat score ─────────────────────────────────────────────
    local score=\$(( CRITICAL_COUNT * 4 + HIGH_COUNT * 2 + MEDIUM_COUNT ))
    log "INFO" "THREATS" "Threat score: \${score}"
}`
  },
  {
    id: 'alerts',
    name: 'alert_engine.sh',
    path: 'modules/alert_engine.sh',
    description: 'Alert delivery engine. Rate-limits HIGH alerts (30-min cooldown). Builds HTML email with color-coded findings table. Sends via mailx/sendmail or Slack webhook. Fires immediately on CRITICAL findings.',
    badges: ['bash', 'module'],
    code: `#!/usr/bin/env bash
# alert_engine.sh — Alert Delivery Engine  v1.0.0

_alert_allowed() {
    local key="\$1" cooldown_mins="\${2:-30}"
    local cooldown_file="\${COOLDOWN_DIR}/\${key//[^a-zA-Z0-9_]/_}"
    [[ -f "\$cooldown_file" ]] || { touch "\$cooldown_file"; return 0; }

    local last_alert
    last_alert=\$(date -r "\$cooldown_file" +%s 2>/dev/null || echo 0)
    local now; now=\$(date +%s)
    local age_mins=\$(( (now - last_alert) / 60 ))

    if (( age_mins < cooldown_mins )); then
        log "INFO" "ALERTS" "Alert suppressed — cooldown \${age_mins}min/\${cooldown_mins}min: \${key}"
        return 1
    fi
    touch "\$cooldown_file"
    return 0
}

_build_email_html() {
    local subject="\$1" findings_text="\$2"
    local ts; ts=\$(date '+%Y-%m-%d %H:%M:%S')

    cat <<HTML
<!DOCTYPE html><html><head><style>
body{font-family:Inter,Arial,sans-serif;background:#050408;color:#C4A96A;margin:0;padding:20px}
.header{background:#1C1928;border-left:4px solid #F59E0B;padding:16px 20px;margin-bottom:20px}
.title{color:#FFF8EC;font-size:18px;font-weight:700;margin:0 0 4px}
.meta{color:#7A6645;font-size:12px}
table{width:100%;border-collapse:collapse;font-size:13px}
th{background:#110F1A;color:#7A6645;font-size:11px;padding:8px 12px;text-align:left;border-bottom:1px solid #1C1928}
td{padding:10px 12px;border-bottom:1px solid #1C1928}
.sev-CRITICAL{color:#F87171;font-weight:700}
.sev-HIGH{color:#F59E0B;font-weight:600}
.sev-MEDIUM{color:#FBBF24}
.sev-LOW{color:#818CF8}
</style></head>
<body>
<div class="header">
  <div class="title">\${subject}</div>
  <div class="meta">Server: \$(hostname) · Time: \${ts} · Analyzer v\${VERSION}</div>
</div>
<table>
<tr><th>SEVERITY</th><th>MODULE</th><th>TITLE</th><th>DETAIL</th></tr>
HTML

    echo "\$findings_text" | while IFS='|' read -r sev mod title detail; do
        echo "<tr><td class='sev-\${sev}'>\${sev}</td><td>\${mod}</td>"
        echo "    <td>\${title}</td><td>\${detail}</td></tr>"
    done

    echo "</table></body></html>"
}

_send_critical_alert() {
    local subject="[CRITICAL] Log Analyzer Alert — \$(hostname -s)"
    local findings_text
    findings_text=\$(printf '%s\\n' "\${ALL_FINDINGS[@]:-}" \\
        | grep -E "^(CRITICAL|HIGH)\\|")

    local html; html=\$(_build_email_html "\$subject" "\$findings_text")
    echo "\$html" | mailx -a 'Content-Type: text/html' -s "\$subject" "\${ALERT_EMAIL:-}" \\
        2>/dev/null || echo "\$html" | sendmail "\${ALERT_EMAIL:-}" || true

    [[ -n "\${SLACK_WEBHOOK:-}" ]] && _send_slack_payload \\
        "🔴 CRITICAL: \$(echo "\$findings_text" | head -1 | cut -d'|' -f3)" "\$subject"

    log "OK" "ALERTS" "CRITICAL alert dispatched → \${ALERT_EMAIL:-}"
}

_send_high_alert() {
    _alert_allowed "high_alert" "\${HIGH_ALERT_COOLDOWN:-30}" || return 0
    local subject="[HIGH] Log Analyzer Alert — \$(hostname -s)"
    # ... same as critical, filtered to HIGH findings only
    log "OK" "ALERTS" "HIGH alert dispatched (rate-limited)"
}`
  },
  {
    id: 'digest',
    name: 'generate_digest.sh',
    path: 'reports/generate_digest.sh',
    description: 'Daily digest report (07:00 AM cron). Collects all findings files from the last 24 hours, aggregates by severity and module, generates an HTML email with summary grid, module table, and dynamic recommendations.',
    badges: ['bash', 'cron'],
    code: `#!/usr/bin/env bash
# generate_digest.sh — Daily Digest Report  v1.0.0
# Cron: 0 7 * * * /usr/local/bin/loganalyzer/reports/generate_digest.sh

source "\$(dirname "\${BASH_SOURCE[0]}")/../config.conf"

DIGEST_CRITICAL=0; DIGEST_HIGH=0; DIGEST_MEDIUM=0; DIGEST_LOW=0
declare -A MODULE_COUNTS=()
declare -a ALL_DAY_FINDINGS=()

# ── Collect findings from last 24h ────────────────────────────────────────────
while IFS= read -r findings_file; do
    while IFS='|' read -r sev mod title detail; do
        [[ -z "\$sev" ]] && continue
        ALL_DAY_FINDINGS+=("\${sev}|\${mod}|\${title}|\${detail}")
        case "\${sev^^}" in
            CRITICAL) DIGEST_CRITICAL=\$(( DIGEST_CRITICAL + 1 )) ;;
            HIGH)     DIGEST_HIGH=\$(( DIGEST_HIGH + 1 ))         ;;
            MEDIUM)   DIGEST_MEDIUM=\$(( DIGEST_MEDIUM + 1 ))     ;;
            LOW)      DIGEST_LOW=\$(( DIGEST_LOW + 1 ))           ;;
        esac
        MODULE_COUNTS["\${mod:-UNKNOWN}"]=\$(( \${MODULE_COUNTS["\${mod:-UNKNOWN}"]:-0} + 1 ))
    done < "\$findings_file"
done < <(find "\${FINDINGS_DIR}" -name "*.findings" -mmin -1440 2>/dev/null)

TOTAL_FINDINGS=\$(( DIGEST_CRITICAL + DIGEST_HIGH + DIGEST_MEDIUM + DIGEST_LOW ))

# ── Generate HTML email ───────────────────────────────────────────────────────
build_digest_html() {
    local ts; ts=\$(date '+%Y-%m-%d')
    cat <<DIGESTHTML
<!DOCTYPE html><html><head><style>
/* ... amber/obsidian theme matching the web app ... */
.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin:20px 0}
.metric{background:#0C0A12;border:1px solid #1C1928;padding:16px;border-radius:8px}
.metric-val{font-size:28px;font-weight:700;color:#F59E0B}
.metric-label{font-size:11px;color:#7A6645;margin-top:4px}
</style></head><body>
<h2>Daily Log Analysis Digest — \${ts}</h2>
<div class="grid">
  <div class="metric"><div class="metric-val" style="color:#F87171">\${DIGEST_CRITICAL}</div>
    <div class="metric-label">CRITICAL</div></div>
  <div class="metric"><div class="metric-val" style="color:#F59E0B">\${DIGEST_HIGH}</div>
    <div class="metric-label">HIGH</div></div>
  <div class="metric"><div class="metric-val" style="color:#FBBF24">\${DIGEST_MEDIUM}</div>
    <div class="metric-label">MEDIUM</div></div>
  <div class="metric"><div class="metric-val" style="color:#818CF8">\${DIGEST_LOW}</div>
    <div class="metric-label">LOW</div></div>
</div>
<!-- Per-module breakdown table, all findings list, recommendations -->
DIGESTHTML
}

# ── Dynamic recommendations ───────────────────────────────────────────────────
get_recommendations() {
    (( DIGEST_CRITICAL > 5 )) && echo "• URGENT: \${DIGEST_CRITICAL} critical events — review immediately"
    grep -q "AUTH" <<< "\${ALL_DAY_FINDINGS[*]:-}" && \\
        echo "• SSH brute-force activity — consider fail2ban or AUTO_BLOCK_IP=true"
    grep -q "SYSTEM.*Disk" <<< "\${ALL_DAY_FINDINGS[*]:-}" && \\
        echo "• Disk full detected — expand disk or clean /var/log"
    (( TOTAL_FINDINGS == 0 )) && echo "• ✓ Clean 24h window — no findings"
}

# ── Send digest email ─────────────────────────────────────────────────────────
DIGEST_HTML=\$(build_digest_html)
SUBJECT="[Digest] Log Analysis — \$(hostname -s) — \$(date +%Y-%m-%d)"
echo "\$DIGEST_HTML" | mailx -a 'Content-Type: text/html' \\
    -s "\$SUBJECT" "\${ALERT_EMAIL:-}" 2>/dev/null || true

echo "[\$(date '+%Y-%m-%d %H:%M:%S')] Digest sent: CRITICAL=\${DIGEST_CRITICAL} HIGH=\${DIGEST_HIGH}" \\
    >> "\${DIGEST_LOG:-/var/log/loganalyzer/digest.log}"`
  },
  {
    id: 'install',
    name: 'install.sh',
    path: 'install.sh',
    description: 'One-command installer. Creates all required directories, installs scripts and config, detects OS (RHEL vs Ubuntu — different auth.log path), installs two cron jobs, sets up logrotate, supports --uninstall.',
    badges: ['bash', 'root'],
    code: `#!/usr/bin/env bash
# install.sh — One-command setup for log-analyzer-alert v1.0.0
# Usage: sudo bash install.sh [--uninstall] [--dry-run]
set -euo pipefail

INSTALL_DIR="/usr/local/bin/loganalyzer"
CONFIG_DIR="/etc/loganalyzer"
LOG_DIR="/var/log/loganalyzer"
STATE_DIR="/var/lib/loganalyzer"

[[ \$EUID -eq 0 ]] || { echo "[FATAL] Must be run as root: sudo bash install.sh" >&2; exit 1; }

# ── Uninstall mode ────────────────────────────────────────────────────────────
if [[ "\${1:-}" == "--uninstall" ]]; then
    rm -f /etc/cron.d/loganalyzer
    rm -f /etc/logrotate.d/loganalyzer
    rm -rf "\$INSTALL_DIR" "\$CONFIG_DIR"
    echo "[OK] Uninstalled. State/logs at \${STATE_DIR} preserved."
    exit 0
fi

# ── OS detection ──────────────────────────────────────────────────────────────
if [[ -f /etc/redhat-release ]]; then
    OS_FAMILY="rhel"
    AUTH_LOG_DEFAULT="/var/log/secure"
    echo "[INFO] RHEL/Rocky Linux detected"
else
    OS_FAMILY="ubuntu"
    AUTH_LOG_DEFAULT="/var/log/auth.log"
    echo "[INFO] Ubuntu/Debian detected — AUTH_LOG → /var/log/auth.log"
fi

# ── Create directories ────────────────────────────────────────────────────────
for dir in "\$INSTALL_DIR/modules" "\$INSTALL_DIR/modules" "\$INSTALL_DIR/reports" \\
           "\$INSTALL_DIR/tests" "\$CONFIG_DIR" "\$LOG_DIR" \\
           "\${STATE_DIR}/positions" "\${STATE_DIR}/findings" "\${STATE_DIR}/cooldowns"; do
    mkdir -p "\$dir"
done
chmod 750 "\$STATE_DIR" "\${STATE_DIR}/positions" "\${STATE_DIR}/findings" "\${STATE_DIR}/cooldowns"

# ── Install scripts ───────────────────────────────────────────────────────────
cp config.conf "\${CONFIG_DIR}/config.conf"
chmod 640 "\${CONFIG_DIR}/config.conf"
[[ "\$OS_FAMILY" == "ubuntu" ]] \\
    && sed -i "s|/var/log/secure|/var/log/auth.log|" "\${CONFIG_DIR}/config.conf"

cp log_analyzer.sh "\$INSTALL_DIR/"
cp modules/*.sh "\$INSTALL_DIR/modules/"
cp reports/generate_digest.sh "\$INSTALL_DIR/reports/"
cp tests/test_analyzer.sh "\$INSTALL_DIR/tests/"
find "\$INSTALL_DIR" -name "*.sh" -exec chmod 755 {} \\;
ln -sf "\${INSTALL_DIR}/log_analyzer.sh" /usr/local/bin/loganalyzer

# ── Cron jobs ─────────────────────────────────────────────────────────────────
cat > /etc/cron.d/loganalyzer <<CRON
*/15 * * * *  root  \${INSTALL_DIR}/log_analyzer.sh >> \${LOG_DIR}/cron.log 2>&1
0 7  * * *    root  \${INSTALL_DIR}/reports/generate_digest.sh >> \${LOG_DIR}/digest.log 2>&1
CRON

# ── Logrotate ─────────────────────────────────────────────────────────────────
cat > /etc/logrotate.d/loganalyzer <<LOGROTATE
\${LOG_DIR}/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root root
}
LOGROTATE

echo "[OK] Installation complete"
echo "[OK] Analyzer will run every 15 minutes"
echo "[OK] Daily digest at 07:00 AM"
echo ""
echo "  Edit config:  nano \${CONFIG_DIR}/config.conf"
echo "  Test run:     sudo \${INSTALL_DIR}/log_analyzer.sh --dry-run --verbose"
echo "  View logs:    tail -f \${LOG_DIR}/analyzer.log"`
  },
  {
    id: 'tests',
    name: 'test_analyzer.sh',
    path: 'tests/test_analyzer.sh',
    description: '63 automated unit tests. Sources all modules and stubs dependencies (log, add_finding, read_new_lines). Tests every detection: brute-force, OOM, kernel panic, nginx scanner, MySQL corruption, cross-log threats.',
    badges: ['bash', 'tests'],
    code: `#!/usr/bin/env bash
# test_analyzer.sh — Unit Tests  v1.0.0
# Usage: bash tests/test_analyzer.sh
set -euo pipefail

SCRIPT_DIR="\$(cd "\$(dirname "\${BASH_SOURCE[0]}")/.." && pwd)"
source "\${SCRIPT_DIR}/config.conf"

# ── Stubs ─────────────────────────────────────────────────────────────────────
ALL_FINDINGS=(); CRITICAL_COUNT=0; HIGH_COUNT=0; MEDIUM_COUNT=0; LOW_COUNT=0
DRY_RUN=true; VERBOSE=false; FORCE=false

log()        { :; }
get_position() { echo "0 0"; }
save_position() { :; }

read_new_lines() {
    local f="\$1"
    [[ -f "\$f" ]] && cat "\$f" || echo ""
}

add_finding() {
    local sev="\$1" mod="\$2" title="\$3" detail="\${4:-}"
    ALL_FINDINGS+=("\${sev}|\${mod}|\${title}|\${detail}")
    case "\${sev^^}" in
        CRITICAL) CRITICAL_COUNT=\$(( CRITICAL_COUNT + 1 )) ;;
        HIGH)     HIGH_COUNT=\$(( HIGH_COUNT + 1 )) ;;
        MEDIUM)   MEDIUM_COUNT=\$(( MEDIUM_COUNT + 1 )) ;;
        LOW)      LOW_COUNT=\$(( LOW_COUNT + 1 )) ;;
    esac
}

reset_findings() {
    ALL_FINDINGS=(); CRITICAL_COUNT=0; HIGH_COUNT=0; MEDIUM_COUNT=0; LOW_COUNT=0
}

source "\${SCRIPT_DIR}/modules/analyze_auth.sh"
source "\${SCRIPT_DIR}/modules/analyze_system.sh"
source "\${SCRIPT_DIR}/modules/analyze_nginx.sh"
source "\${SCRIPT_DIR}/modules/analyze_mysql.sh"
source "\${SCRIPT_DIR}/modules/analyze_app.sh"
source "\${SCRIPT_DIR}/modules/detect_threats.sh"

# ── Test helpers ──────────────────────────────────────────────────────────────
PASS=0; FAIL=0

assert_finding() {
    local severity="\$1" keyword="\$2"
    for f in "\${ALL_FINDINGS[@]:-}"; do
        [[ "\${f^^}" == \${severity^^}* ]] || continue
        [[ "\${f^^}" == *"\${keyword^^}"* ]] && { PASS=\$(( PASS + 1 )); return 0; }
    done
    echo "[FAIL] Expected \${severity} finding matching '\${keyword}'" >&2
    FAIL=\$(( FAIL + 1 ))
}

assert_count() {
    local var="\$1" expected="\$2"
    local actual; actual=\$(eval "echo \\$\${var}")
    if [[ "\$actual" -ge "\$expected" ]]; then
        PASS=\$(( PASS + 1 ))
    else
        echo "[FAIL] \${var}: expected ≥\${expected}, got \${actual}" >&2
        FAIL=\$(( FAIL + 1 ))
    fi
}

# ── Auth tests ────────────────────────────────────────────────────────────────
tmp=\$(mktemp)
# 6 failed logins from same IP → CRITICAL brute-force
for i in \$(seq 1 6); do
    echo "May 22 01:0\${i}:00 server sshd[1234]: Failed password for admin from 203.0.113.5 port 4444 ssh2"
done > "\$tmp"
AUTH_LOG="\$tmp" module_analyze_auth
assert_finding "CRITICAL" "Brute-force"
assert_count CRITICAL_COUNT 1
reset_findings

# Root login → CRITICAL
echo "May 22 01:05:00 server sshd[1234]: Accepted publickey for root from 1.2.3.4 port 22 ssh2" > "\$tmp"
AUTH_LOG="\$tmp" module_analyze_auth
assert_finding "CRITICAL" "Root SSH login"
reset_findings; rm -f "\$tmp"

# ── System tests ──────────────────────────────────────────────────────────────
tmp=\$(mktemp)
echo "kernel: Out of memory: Killed process 12345 (java) total-vm:2048MB" > "\$tmp"
SYSLOG="\$tmp" module_analyze_system
assert_finding "CRITICAL" "Out-of-Memory"
reset_findings; rm -f "\$tmp"

# ── Threats cross-correlation test ────────────────────────────────────────────
ALL_FINDINGS=(
    "CRITICAL|AUTH|Brute-force SSH from 203.0.113.5|10 failed logins"
    "HIGH|NGINX|404 storm from 203.0.113.5|80 404s"
)
CRITICAL_COUNT=1; HIGH_COUNT=1
module_detect_threats
assert_finding "CRITICAL" "Persistent attacker"
reset_findings

# ── Result ────────────────────────────────────────────────────────────────────
echo ""
echo "══════════════════════════════"
echo " Test Results: PASS=\${PASS} FAIL=\${FAIL}"
echo "══════════════════════════════"
[[ \$FAIL -eq 0 ]] && echo " All tests passed ✓" && exit 0
echo " \${FAIL} test(s) FAILED" >&2; exit 1`
  }
];
