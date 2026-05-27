# Automated Log Analyzer & Alert System

> Production-grade automated log analysis for RHEL 9, Rocky Linux, Ubuntu Server, and any systemd-based Linux distribution.
> Scans syslog, auth, nginx, MySQL, application logs, and the systemd journal every 15 minutes.
> Detects threats, errors, and anomalies — then fires instant alerts via **Email, Slack, Microsoft Teams, and PagerDuty**, and sends a daily HTML digest.

[![CI](https://github.com/samiulAsumel/log-analyzer-alert/actions/workflows/ci.yml/badge.svg)](https://github.com/samiulAsumel/log-analyzer-alert/actions/workflows/ci.yml)
![Bash](https://img.shields.io/badge/shell-bash%205%2B-brightgreen)
![License](https://img.shields.io/badge/license-MIT-blue)
![Version](https://img.shields.io/badge/version-2.0.0-orange)

---

## Why This Exists

| Pain | Solution |
|---|---|
| Servers generate gigabytes of logs — nobody reads them | 15-minute automated scan of all major log sources |
| Errors sit undetected for days before causing outages | Instant alert on CRITICAL and HIGH findings |
| Manual `grep` through 100,000 lines takes 2 hours | Zero manual analysis — script finds what matters |
| Security breach detected weeks later | SSH brute-force, scanners, root logins → immediate alert |
| "Did the server have any issues last night?" | 07:00 daily HTML digest with full findings summary |
| SIEM team needs structured data | JSON/NDJSON export compatible with Splunk, Elastic, Loki |

---

## Quick Start

```bash
# 1. Clone
git clone https://github.com/samiulAsumel/log-analyzer-alert.git
cd log-analyzer-alert

# 2. Configure
nano config.conf    # Set ALERT_EMAIL, SLACK_WEBHOOK, log paths, thresholds

# 3. Install (as root — auto-detects systemd vs cron)
sudo bash install.sh

# 4. Test immediately
sudo bash /usr/local/bin/loganalyzer/log_analyzer.sh --verbose

# 5. Verify health
bash /usr/local/bin/loganalyzer/scripts/health_check.sh
```

---

## Architecture

```
Every 15 minutes (cron or systemd timer):
┌──────────────────────────────────────────────────────────────────────┐
│  log_analyzer.sh  (orchestrator)                                     │
│                                                                      │
│  01 Acquire lock (prevent overlapping runs)                          │
│  02 Read ONLY new bytes per log (inode + offset tracking)            │
│  03 ┌── analyze_auth.sh    → SSH brute-force, root login, sudo       │
│     ├── analyze_system.sh  → OOM, kernel panic, hardware, segfaults  │
│     ├── analyze_nginx.sh   → 5xx spike, scanners, slow requests      │
│     ├── analyze_mysql.sh   → slow queries, replication, corruption   │
│     ├── analyze_app.sh     → exceptions, API errors, timeouts        │
│     ├── analyze_journal.sh → systemd journal: failed units, coredumps│
│     └── detect_threats.sh  → cross-log correlation + threat score    │
│  04 Aggregate findings → pipe-delimited + JSON files                 │
│  05 CRITICAL found? → immediate Email / Slack / Teams / PagerDuty   │
│     HIGH found?     → rate-limited alert (max 1 per 30 min)         │
│     MEDIUM/LOW?     → batched into daily digest                      │
└──────────────────────────────────────────────────────────────────────┘

Daily at 07:00 (cron or systemd timer):
┌──────────────────────────────────────────────────────────────────────┐
│  generate_digest.sh  (daily HTML report)                             │
│                                                                      │
│  01 Collect all findings from last 24 hours                          │
│  02 Count by severity: CRITICAL / HIGH / MEDIUM / LOW                │
│  03 Count by module: AUTH / SYSTEM / NGINX / MYSQL / APP / JOURNAL   │
│  04 System health snapshot: uptime, load, memory, disk              │
│  05 Auto-generate actionable recommendations per finding type        │
│  06 Send colour-coded HTML email                                     │
└──────────────────────────────────────────────────────────────────────┘
```

---

## What It Detects

### 🔐 AUTH / SSH (`analyze_auth.sh`)
| Detection | Severity | Action |
|---|---|---|
| Brute-force SSH (≥5 failures/IP in 15 min) | CRITICAL | Alert + optional firewalld block |
| Repeated SSH failures (3–4/IP) | HIGH | Alert |
| Successful root SSH login | CRITICAL | Alert |
| Root SSH brute-force | HIGH | Alert |
| Invalid username attempts | HIGH | Alert |
| Sudo privilege escalations | LOW | Log |
| Sudo auth failures | MEDIUM | Alert |
| New user/group creation | MEDIUM | Alert |
| PAM auth failures (bulk) | MEDIUM | Alert |

### ⚙️ SYSTEM (`analyze_system.sh`)
| Detection | Severity |
|---|---|
| Out-of-Memory (OOM) kill | CRITICAL |
| Kernel panic | CRITICAL |
| Hardware errors (disk I/O, MCE, EDAC) | CRITICAL |
| Disk full / no space left | CRITICAL |
| RAID array degraded | CRITICAL |
| Segmentation faults | HIGH |
| Service failures (systemd) | HIGH |
| CPU thermal throttling | HIGH |
| Filesystem mount errors | MEDIUM |
| Kernel errors/warnings | MEDIUM |

### 🌐 NGINX (`analyze_nginx.sh`)
| Detection | Severity |
|---|---|
| 5xx error spike (≥20 in 15 min) | CRITICAL |
| 404 storm per IP (≥50 in 15 min) | HIGH |
| Single IP > 33% of all traffic | HIGH |
| Scanner user-agents (sqlmap, nikto, DirBuster, etc.) | HIGH |
| Nginx crit/alert/emerg errors | HIGH |
| Upstream backend failures | HIGH |
| Slow requests (> configurable ms) | MEDIUM |
| Unusual POST request volume | MEDIUM |

### 🗃️ MYSQL (`analyze_mysql.sh`)
| Detection | Severity |
|---|---|
| Replication errors | CRITICAL |
| Table corruption | CRITICAL |
| InnoDB fatal errors | CRITICAL |
| Disk space / write failures | CRITICAL |
| Connection limit hit | HIGH |
| Slow query threshold exceeded | HIGH |
| High aborted connections | MEDIUM |
| Full table scans (>1M rows) | MEDIUM |

### 📦 APP (`analyze_app.sh`)
| Detection | Severity |
|---|---|
| CRITICAL/FATAL log entries | CRITICAL |
| Custom `CRITICAL_PATTERNS` regex match | CRITICAL |
| Exception spike (≥30 in interval) | HIGH |
| Error rate ≥ 20% of log lines | HIGH |
| Database connection errors | HIGH |
| Memory exhaustion warnings | HIGH |
| API error response spike | HIGH |
| Timeout spike (>10 in interval) | MEDIUM |

### 📋 JOURNAL (`analyze_journal.sh`)
| Detection | Severity |
|---|---|
| Kernel error/panic in systemd journal | CRITICAL |
| OOM kill in journal | CRITICAL |
| Disk I/O errors in journal | CRITICAL |
| Core dumps (coredumpctl) | HIGH |
| systemd error-level journal entries | HIGH |
| Service restart loops (start-limit-hit) | HIGH |
| SSH failures via journal | HIGH |
| SELinux/AVC denials | MEDIUM |

### 🛡️ THREATS — Cross-Log Correlation (`detect_threats.sh`)
| Pattern | Severity |
|---|---|
| Same IP in SSH brute-force AND web scanner | CRITICAL |
| HIGH/CRITICAL findings across 3+ modules simultaneously | CRITICAL |
| OOM + App crash at the same time | CRITICAL |
| Brute-force followed by new user creation | CRITICAL |
| Disk full + database errors together | CRITICAL |
| Web scanning + SSH brute-force | HIGH |
| External IPs appearing 10+ times across multiple logs | MEDIUM |

---

## File Structure

```
log-analyzer-alert/
├── config.conf                    # All settings (edit this first)
├── log_analyzer.sh                # Main orchestrator (runs every 15 min)
├── install.sh                     # One-command installer (cron + systemd)
├── modules/
│   ├── alert_engine.sh            # Email, Slack, Teams, PagerDuty alerts
│   ├── analyze_auth.sh            # SSH / auth log analyzer
│   ├── analyze_system.sh          # /var/log/messages analyzer
│   ├── analyze_nginx.sh           # Nginx access + error log analyzer
│   ├── analyze_mysql.sh           # MySQL error + slow query analyzer
│   ├── analyze_app.sh             # Custom application log analyzer
│   ├── analyze_journal.sh         # systemd journal analyzer
│   └── detect_threats.sh          # Cross-log threat correlation engine
├── reports/
│   └── generate_digest.sh         # Daily HTML digest report
├── scripts/
│   ├── health_check.sh            # Operational health check (monitoring-compatible)
│   └── export_findings.sh         # SIEM export: JSON / NDJSON / CSV
├── systemd/
│   ├── loganalyzer.service        # systemd service (oneshot)
│   ├── loganalyzer.timer          # systemd timer (every 15 min)
│   ├── loganalyzer-digest.service # Daily digest service
│   └── loganalyzer-digest.timer   # Daily digest timer (07:00)
├── tests/
│   └── test_analyzer.sh           # Test suite (simulated log lines)
└── .github/
    └── workflows/ci.yml           # GitHub Actions: lint + test + security scan
```

---

## Configuration

Edit `/etc/loganalyzer/config.conf` after installation, or `config.conf` in the source directory.

### Essential Settings

```bash
# ── Email ─────────────────────────────────────────────────────────────────────
ALERT_EMAIL="ops@yourcompany.com"

# ── Alert channels ────────────────────────────────────────────────────────────
ALERT_METHOD="email"               # email | slack | teams | email,slack | both

SLACK_WEBHOOK="https://hooks.slack.com/services/XXX/YYY/ZZZ"
TEAMS_WEBHOOK="https://outlook.office.com/webhook/..."
PAGERDUTY_KEY="abc123..."          # Fires automatically on CRITICAL + HIGH

# ── Log paths ─────────────────────────────────────────────────────────────────
# RHEL 9 / Rocky Linux (defaults):
SYSLOG="/var/log/messages"
AUTH_LOG="/var/log/secure"

# Ubuntu (change these two lines):
# SYSLOG="/var/log/syslog"
# AUTH_LOG="/var/log/auth.log"

# ── Thresholds ─────────────────────────────────────────────────────────────────
MAX_FAILED_LOGINS=5        # SSH failures per IP → CRITICAL
MAX_404_PER_IP=50          # 404s from one IP → scanner alert
MAX_5XX_COUNT=20           # Total 5xx errors → web alert
MAX_SLOW_QUERIES=50        # MySQL slow queries per interval
MAX_RESPONSE_MS=5000       # Nginx slow request threshold (ms)

# ── SIEM / JSON export ────────────────────────────────────────────────────────
JSON_EXPORT_ENABLED=true   # Write JSON findings alongside pipe-delimited
```

### Multi-Channel Alerts

```bash
# Send to both email AND Slack
ALERT_METHOD="email,slack"
SLACK_WEBHOOK="https://hooks.slack.com/services/..."

# Send to Teams + trigger PagerDuty for CRITICAL/HIGH
ALERT_METHOD="teams"
TEAMS_WEBHOOK="https://outlook.office.com/webhook/..."
PAGERDUTY_KEY="your-events-v2-key"
```

---

## Usage

```bash
# Full analysis
sudo bash /usr/local/bin/loganalyzer/log_analyzer.sh

# Verbose terminal output
sudo bash /usr/local/bin/loganalyzer/log_analyzer.sh --verbose

# Force re-read all logs from byte 0 (ignore position state)
sudo bash /usr/local/bin/loganalyzer/log_analyzer.sh --force --verbose

# Run a single module only
sudo bash /usr/local/bin/loganalyzer/log_analyzer.sh --module=auth
sudo bash /usr/local/bin/loganalyzer/log_analyzer.sh --module=journal
sudo bash /usr/local/bin/loganalyzer/log_analyzer.sh --module=threats

# Dry run — no state changes, no alerts sent
sudo bash /usr/local/bin/loganalyzer/log_analyzer.sh --dry-run --verbose

# Generate daily digest immediately
sudo bash /usr/local/bin/loganalyzer/reports/generate_digest.sh

# Digest covering last 48 hours
sudo bash /usr/local/bin/loganalyzer/reports/generate_digest.sh --since=48

# Operational health check (nagios-compatible exit codes)
bash /usr/local/bin/loganalyzer/scripts/health_check.sh
bash /usr/local/bin/loganalyzer/scripts/health_check.sh --json

# Export findings for SIEM ingestion
bash /usr/local/bin/loganalyzer/scripts/export_findings.sh --format=ndjson
bash /usr/local/bin/loganalyzer/scripts/export_findings.sh --format=json --out=/tmp/findings.json
bash /usr/local/bin/loganalyzer/scripts/export_findings.sh --format=csv --since=48
```

---

## Scheduling

The installer auto-detects systemd and installs timers if available, otherwise falls back to cron.

### systemd (preferred)

```bash
# Check timer status
systemctl status loganalyzer.timer
systemctl status loganalyzer-digest.timer

# List all timer runs
systemctl list-timers loganalyzer*

# View logs
journalctl -u loganalyzer.service -f
```

### cron (fallback)

```bash
# View schedule
cat /etc/cron.d/loganalyzer

# View cron output
tail -f /var/log/loganalyzer/cron.log
```

---

## How Position Tracking Works

Unlike naive log analyzers that re-read entire files every run:

```
Run 1 (15:00): /var/log/secure  → inode=12345, size=50,000 bytes
               Read bytes 0–50000. Save: "12345 50000"

Run 2 (15:15): /var/log/secure  → inode=12345, size=52,400 bytes
               Read bytes 50000–52400 only (2,400 new bytes = ~40 lines)

Log rotated:   /var/log/secure  → inode=99999, size=800 bytes
               Inode changed → read from byte 0 of the new file
```

State files live in `/var/lib/loganalyzer/positions/`. Delete them to force a full re-read.

---

## SIEM Integration

JSON findings are written to `/var/lib/loganalyzer/findings_json/<RUN_ID>.json` each run (when `JSON_EXPORT_ENABLED=true`).

**Filebeat configuration** to ship to Elasticsearch:
```yaml
filebeat.inputs:
  - type: log
    paths:
      - /var/lib/loganalyzer/findings_json/*.json
    json.keys_under_root: true
    json.add_error_key: true
```

**Fluent Bit** (forward to Loki/Splunk):
```ini
[INPUT]
    Name  tail
    Path  /var/lib/loganalyzer/findings_json/*.json
    Tag   loganalyzer

[OUTPUT]
    Name  loki
    Match loganalyzer
    Host  your-loki-host
```

---

## Alert Email Format

**Immediate CRITICAL/HIGH alert:**
- Subject: `[LogAlert][CRITICAL] 2 critical issues detected on server01`
- HTML body with colour-coded findings table per row: Severity | Module | Finding | Detail

**Daily digest (07:00):**
- Subject: `[LogDigest] 2026-05-28 — 14 findings on server01`
- Summary grid: CRITICAL / HIGH / MEDIUM / LOW counts
- Findings grouped by module
- Full findings table with all details
- System health snapshot: uptime, load, memory, disk
- Auto-generated actionable recommendations

---

## Installation Details

| Path | Purpose |
|---|---|
| `/usr/local/bin/loganalyzer/` | All scripts |
| `/usr/local/bin/loganalyzer/scripts/` | Utility scripts (health, export) |
| `/etc/loganalyzer/config.conf` | Configuration (mode 640) |
| `/var/log/loganalyzer/` | Analyzer logs |
| `/var/lib/loganalyzer/positions/` | Log position state (inode+offset) |
| `/var/lib/loganalyzer/findings/` | Per-run pipe-delimited finding files |
| `/var/lib/loganalyzer/findings_json/` | Per-run JSON finding files (SIEM) |
| `/var/lib/loganalyzer/cooldowns/` | Rate-limit timestamps |
| `/etc/systemd/system/loganalyzer*.{service,timer}` | systemd units |
| `/etc/cron.d/loganalyzer` | Cron schedule (fallback) |
| `/etc/logrotate.d/loganalyzer` | Log rotation config |

---

## OS Compatibility

| OS | Auth Log | Syslog | Journal |
|---|---|---|---|
| RHEL 9 / Rocky Linux 9 | `/var/log/secure` | `/var/log/messages` | ✅ journalctl |
| CentOS Stream 9 | `/var/log/secure` | `/var/log/messages` | ✅ journalctl |
| Ubuntu 22.04 / 24.04 | `/var/log/auth.log` | `/var/log/syslog` | ✅ journalctl |
| Debian 12 | `/var/log/auth.log` | `/var/log/syslog` | ✅ journalctl |

For Ubuntu/Debian, change two lines in `config.conf`:
```bash
AUTH_LOG="/var/log/auth.log"
SYSLOG="/var/log/syslog"
```

---

## Troubleshooting

```bash
# Check what the analyzer found last run
ls -lt /var/lib/loganalyzer/findings/
cat /var/lib/loganalyzer/findings/<latest>.findings

# View analyzer logs
tail -100 /var/log/loganalyzer/analyzer.log

# Reset position for one log file (force re-read)
rm /var/lib/loganalyzer/positions/_var_log_secure

# Run health check
bash /usr/local/bin/loganalyzer/scripts/health_check.sh

# Test email delivery
echo "Test" | mailx -s "Test from loganalyzer" admin@company.com

# Check blocked IPs
cat /var/lib/loganalyzer/blocked_ips.log

# View systemd timer status
systemctl list-timers loganalyzer*

# Check cron schedule
cat /etc/cron.d/loganalyzer
```

---

## Uninstall

```bash
sudo bash install.sh --uninstall
# Logs and findings preserved — remove manually if desired:
# sudo rm -rf /var/log/loganalyzer /var/lib/loganalyzer
```

---

## CI / Testing

```bash
# Run the full test suite locally (no root needed)
bash tests/test_analyzer.sh --verbose

# ShellCheck lint
shellcheck -S warning modules/*.sh log_analyzer.sh install.sh

# Bash syntax check
bash -n log_analyzer.sh && echo OK
```

GitHub Actions runs lint, syntax check, security scan, and the test suite on every push and pull request.

---

*Built with Bash · No external dependencies · RHEL 9 / Rocky Linux 9 / Ubuntu 22.04 / Ubuntu 24.04*
