# Automated Log Analyzer & Alert System

> Production-grade automated log analysis for RHEL 9, Rocky Linux, and Ubuntu Server.
> Scans syslog, auth, nginx, MySQL, and application logs every 15 minutes — detects threats, errors, and anomalies, then sends instant alerts and a daily HTML digest.

---

## Pain → Solution → ROI

| Pain | Solution |
|---|---|
| Servers generate gigabytes of logs — nobody reads them | 15-minute automated scan of all major log sources |
| Errors sit undetected for days before causing outages | Instant email/Slack alert on CRITICAL and HIGH findings |
| Manual `grep` through 100,000 lines takes 2 hours | Zero manual analysis — script finds what matters |
| Security breach detected weeks later | SSH brute-force, scanners, root logins → immediate alert |
| "Did the server have any issues last night?" | 07:00 daily HTML digest with full findings summary |

**ROI:** A single prevented outage or security breach pays for itself. One incident avoided = $10,000–$1,000,000+ saved.

---

## Quick Start

```bash
# 1. Clone
git clone https://github.com/samiulAsumel/log-analyzer-alert.git
cd log-analyzer-alert

# 2. Configure
nano config.conf    # Set ALERT_EMAIL, log file paths, thresholds

# 3. Install (as root)
sudo bash install.sh

# 4. Test manually
sudo bash /usr/local/bin/loganalyzer/log_analyzer.sh --verbose

# 5. Force re-read all logs (no position tracking)
sudo bash /usr/local/bin/loganalyzer/log_analyzer.sh --force --verbose
```

---

## System Architecture

```
Every 15 minutes (cron):
┌─────────────────────────────────────────────────────────────────────┐
│  log_analyzer.sh  (orchestrator)                                    │
│                                                                     │
│  01 Acquire lock (prevent overlapping runs)                         │
│  02 Read ONLY new bytes per log (inode + offset tracking)           │
│  03 ┌── analyze_auth.sh    → SSH brute-force, root login, sudo      │
│     ├── analyze_system.sh  → OOM, kernel panic, segfaults           │
│     ├── analyze_nginx.sh   → 5xx spike, scanners, slow requests     │
│     ├── analyze_mysql.sh   → slow queries, replication, corruption  │
│     ├── analyze_app.sh     → exceptions, API errors, timeouts       │
│     └── detect_threats.sh  → cross-log correlation + threat score   │
│  04 Aggregate all findings → /var/lib/loganalyzer/findings/         │
│  05 CRITICAL found? → immediate email/Slack alert                   │
│     HIGH found?     → rate-limited email (max 1 per 30 min)         │
│     MEDIUM/LOW?     → saved for daily digest                        │
└─────────────────────────────────────────────────────────────────────┘

Daily at 07:00 (cron):
┌─────────────────────────────────────────────────────────────────────┐
│  generate_digest.sh  (daily HTML report)                            │
│                                                                     │
│  01 Collect all findings from last 24h                              │
│  02 Count by severity: CRITICAL / HIGH / MEDIUM / LOW               │
│  03 Count by module: AUTH / SYSTEM / NGINX / MYSQL / APP / THREATS  │
│  04 System health snapshot: uptime, load, memory, disk              │
│  05 Auto-generate recommendations based on finding types            │
│  06 Send colour-coded HTML email report                             │
└─────────────────────────────────────────────────────────────────────┘
```

---

## What It Detects

### 🔐 AUTH / SSH (`analyze_auth.sh`)
| Detection | Severity | Action |
|---|---|---|
| Brute-force SSH (≥5 failures/IP in 15 min) | CRITICAL | Alert + optional IP block |
| Repeated SSH failures (3–4 per IP) | HIGH | Alert |
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
| Hardware errors (disk, MCE, EDAC) | CRITICAL |
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
| Single IP > 33% of traffic | HIGH |
| Scanner user-agents (sqlmap, nikto, etc.) | HIGH |
| Nginx crit/alert/emerg errors | HIGH |
| Upstream backend failures | HIGH |
| Slow requests (> configurable ms) | MEDIUM |
| Unusual POST request volume | MEDIUM |
| Nginx [error] log spike | MEDIUM |

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
| Custom CRITICAL_PATTERNS match | CRITICAL |
| Exception spike (≥30 in interval) | HIGH |
| Error rate ≥ 20% of log lines | HIGH |
| Database connection errors | HIGH |
| Memory exhaustion warnings | HIGH |
| API error response spike | HIGH |
| Disk/file system errors | HIGH |
| Exception count (< threshold) | MEDIUM |
| Timeout spike (>10 in interval) | MEDIUM |

### 🛡️ THREATS — Cross-Log Correlation (`detect_threats.sh`)
| Pattern | Severity |
|---|---|
| Same IP in SSH brute-force AND web scanner | CRITICAL |
| HIGH/CRITICAL findings across 3+ modules | CRITICAL |
| OOM + App crash simultaneously | CRITICAL |
| Brute-force followed by new user creation | CRITICAL |
| Disk full + database errors together | CRITICAL |
| Web scanning + SSH brute-force | HIGH |
| External IPs appearing 10+ times across logs | MEDIUM |

---

## File Structure

```
log-analyzer-alert/
├── config.conf                    # All settings (edit this first)
├── log_analyzer.sh                # Main orchestrator (run every 15 min)
├── modules/
│   ├── alert_engine.sh            # Email + Slack alerts with rate-limiting
│   ├── analyze_auth.sh            # SSH / auth log analyzer
│   ├── analyze_system.sh          # /var/log/messages analyzer
│   ├── analyze_nginx.sh           # Nginx access + error log analyzer
│   ├── analyze_mysql.sh           # MySQL error + slow query analyzer
│   ├── analyze_app.sh             # Custom application log analyzer
│   └── detect_threats.sh          # Cross-log threat correlation
├── reports/
│   └── generate_digest.sh         # Daily HTML digest report
├── tests/
│   └── test_analyzer.sh           # Test suite (simulated log lines)
├── install.sh                     # One-command installer
└── README.md
```

---

## Configuration

Edit `/etc/loganalyzer/config.conf` (installed) or `config.conf` (source).

### Essential Settings

```bash
# ── Email ─────────────────────────────────────────────────────────────────────
ALERT_EMAIL="admin@yourcompany.com"   # Who receives alerts

# ── Log paths ─────────────────────────────────────────────────────────────────
# RHEL 9 / Rocky Linux (defaults):
SYSLOG="/var/log/messages"
AUTH_LOG="/var/log/secure"

# Ubuntu (change these):
# SYSLOG="/var/log/syslog"
# AUTH_LOG="/var/log/auth.log"

# ── Thresholds ─────────────────────────────────────────────────────────────────
MAX_FAILED_LOGINS=5        # SSH failures per IP before CRITICAL alert
MAX_404_PER_IP=50          # 404s from one IP before scanner alert
MAX_5XX_COUNT=20           # Total 5xx errors before web alert
MAX_SLOW_QUERIES=50        # MySQL slow queries per interval
MAX_RESPONSE_MS=5000       # Nginx request time threshold (ms)

# ── Auto-block brute-force IPs ─────────────────────────────────────────────────
AUTO_BLOCK_IP=false        # Set true to block via firewalld automatically
WHITELIST_IPS="127.0.0.1 ::1 10.0.0.1"   # Never block these
```

### Slack Alerts

```bash
ALERT_METHOD="both"        # email | slack | both
SLACK_WEBHOOK="https://hooks.slack.com/services/XXX/YYY/ZZZ"
```

---

## Usage

```bash
# Run full analysis
sudo bash /usr/local/bin/loganalyzer/log_analyzer.sh

# Verbose output
sudo bash /usr/local/bin/loganalyzer/log_analyzer.sh --verbose

# Force re-read all logs from start (ignore saved positions)
sudo bash /usr/local/bin/loganalyzer/log_analyzer.sh --force --verbose

# Run only one module
sudo bash /usr/local/bin/loganalyzer/log_analyzer.sh --module=auth
sudo bash /usr/local/bin/loganalyzer/log_analyzer.sh --module=nginx
sudo bash /usr/local/bin/loganalyzer/log_analyzer.sh --module=threats

# Dry run (no state changes, no alerts)
sudo bash /usr/local/bin/loganalyzer/log_analyzer.sh --dry-run --verbose

# Generate today's digest now
sudo bash /usr/local/bin/loganalyzer/reports/generate_digest.sh

# Digest for last 48 hours
sudo bash /usr/local/bin/loganalyzer/reports/generate_digest.sh --since=48
```

---

## How Position Tracking Works

Unlike naive log analyzers that re-read entire files every run:

```
Run 1 (15:00): /var/log/secure  → inode=12345, size=50,000 bytes
               Read bytes 0–50000. Save: 12345 50000

Run 2 (15:15): /var/log/secure  → inode=12345, size=52,400 bytes
               Read bytes 50000–52400 only (2,400 new bytes = ~40 new lines)

Log rotated:   /var/log/secure  → inode=99999, size=800 bytes
               Inode changed → read from byte 0 of the new file
```

State files live in `/var/lib/loganalyzer/positions/`. Delete them to force a full re-read.

---

## Alert Email Format

**CRITICAL/HIGH alert (sent immediately):**
- Subject: `[LogAlert][CRITICAL] 2 critical issues detected @ server01`
- HTML body with colour-coded findings table
- Severity, module, title, detail per row

**Daily digest (07:00):**
- Subject: `[LogDigest] 2026-05-28 — 14 findings on server01`
- Summary grid: CRITICAL / HIGH / MEDIUM / LOW counts
- Findings by module
- Full findings table
- System health (uptime, load, memory, disk)
- Auto-generated recommendations

---

## Installation Details

| Path | Purpose |
|---|---|
| `/usr/local/bin/loganalyzer/` | Scripts |
| `/etc/loganalyzer/config.conf` | Configuration |
| `/var/log/loganalyzer/` | Analyzer logs |
| `/var/lib/loganalyzer/positions/` | Log position state |
| `/var/lib/loganalyzer/findings/` | Per-run finding files |
| `/var/lib/loganalyzer/cooldowns/` | Rate-limit timestamps |
| `/etc/cron.d/loganalyzer` | Cron schedules |
| `/etc/logrotate.d/loganalyzer` | Log rotation |

---

## OS Compatibility

| OS | Auth Log | Syslog | Notes |
|---|---|---|---|
| RHEL 9 / Rocky Linux | `/var/log/secure` | `/var/log/messages` | Default config |
| CentOS Stream 9 | `/var/log/secure` | `/var/log/messages` | Default config |
| Ubuntu 22.04/24.04 | `/var/log/auth.log` | `/var/log/syslog` | Change 2 lines in config |
| Debian 12 | `/var/log/auth.log` | `/var/log/syslog` | Change 2 lines in config |

---

## Troubleshooting

```bash
# Check what the analyzer found last run
ls -lt /var/lib/loganalyzer/findings/
cat /var/lib/loganalyzer/findings/<latest>.findings

# View analyzer logs
tail -100 /var/log/loganalyzer/analyzer.log

# Reset position for one log (force re-read)
rm /var/lib/loganalyzer/positions/_var_log_secure

# Test email delivery
echo "Test" | mailx -s "Test from loganalyzer" admin@company.com

# Check blocked IPs
cat /var/lib/loganalyzer/blocked_ips.log

# View cron schedule
cat /etc/cron.d/loganalyzer
```

---

## Uninstall

```bash
sudo bash install.sh --uninstall
# Logs and findings preserved — remove manually:
# sudo rm -rf /var/log/loganalyzer /var/lib/loganalyzer
```

---

## Fiverr Delivery Tiers

| Tier | Price | What's Included |
|---|---|---|
| **Basic** | $80 | Scripts + config + cron setup + README |
| **Standard** | $160 | Basic + custom patterns + email config + 1 week support |
| **Premium** | $280 | Standard + Slack integration + custom modules + 30-day support |

---

*Built with Bash · Tested on RHEL 9 / Rocky Linux 9 / Ubuntu 22.04*
