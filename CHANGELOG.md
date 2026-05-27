# Changelog

All notable changes to the Automated Log Analyzer & Alert System are documented here.

---

## [2.0.0] — 2026-05-28

### Added
- **Microsoft Teams alerts** — `TEAMS_WEBHOOK` in config, Teams Incoming Webhook connector support in `alert_engine.sh`
- **PagerDuty integration** — Events API v2 (`PAGERDUTY_KEY`), fires on CRITICAL and HIGH; includes dedup key to prevent alert storms
- **`modules/analyze_journal.sh`** — systemd journal analyzer: failed units, core dumps, kernel errors, OOM from journald, SELinux denials, service restart loops, disk I/O errors
- **`scripts/health_check.sh`** — Nagios/Icinga-compatible health check (exit 0/1/2); also supports `--json` output for monitoring APIs
- **`scripts/export_findings.sh`** — SIEM-ready findings export in **NDJSON** (Filebeat/Fluentd), **JSON** (REST upload), or **CSV** formats
- **systemd service + timer units** (`systemd/`) — `loganalyzer.service`, `loganalyzer.timer`, `loganalyzer-digest.service`, `loganalyzer-digest.timer`; persist across reboots, include CPU/memory resource limits
- **JSON findings export** — each run writes a structured JSON file to `findings_json/` when `JSON_EXPORT_ENABLED=true` (Splunk, Elasticsearch, Loki compatible)
- **GitHub Actions CI** (`.github/workflows/ci.yml`) — lint (ShellCheck), bash syntax check, test suite, and secrets scan on every push/PR
- **`.gitignore`** — excludes runtime artifacts, stale lock files, editor directories, and placeholder secrets

### Changed
- **`alert_engine.sh`** — `ALERT_METHOD` now accepts comma/space-separated values (`"email,slack"`, `"teams"`) for multi-channel delivery; PagerDuty fires automatically if key is set regardless of `ALERT_METHOD`
- **`install.sh`** — auto-detects systemd; installs timers if available, falls back to cron; now also installs `scripts/` and `analyze_journal.sh`; post-install summary shows scheduling method and new commands
- **`log_analyzer.sh`** — sources `analyze_journal.sh` if present (optional); runs journal module in the pipeline; exports JSON findings per run; added `--json` flag
- **`config.conf`** — added `TEAMS_WEBHOOK`, `JSON_EXPORT_ENABLED`, `JSON_EXPORT_DIR`, `JOURNAL_LINES`; bumped `VERSION` to `2.0.0`
- **`README.md`** — complete rewrite: enterprise-focused, multi-channel alert docs, SIEM integration guide, systemd scheduling docs, CI badge

### Fixed
- Alert subject line now includes hostname for immediate triage context
- Rate-limit cooldown correctly handles zero-length cooldown files

---

## [1.0.0] — 2026-05-28

### Added
- `log_analyzer.sh` — main orchestrator with inode+offset position tracking, lock file, run summary
- `modules/alert_engine.sh` — email (mailx/sendmail) and Slack webhook alerts with HTML formatting and rate-limiting
- `modules/analyze_auth.sh` — SSH brute-force, invalid users, root login, sudo escalations, new user creation, PAM failures
- `modules/analyze_system.sh` — OOM kills, kernel panic, hardware errors, disk full, segfaults, service failures, RAID degraded, thermal throttling
- `modules/analyze_nginx.sh` — 5xx spikes, 404 storms, DDoS detection, scanner user-agents, upstream failures, slow requests
- `modules/analyze_mysql.sh` — replication errors, table corruption, InnoDB fatal errors, connection limits, slow queries
- `modules/analyze_app.sh` — exception spikes, CRITICAL/FATAL entries, error rates, DB errors, API failures, memory warnings, timeouts
- `modules/detect_threats.sh` — cross-log threat correlation: persistent attacker, multi-service failure, OOM+crash, brute-force+user-creation, disk+DB, reconnaissance
- `reports/generate_digest.sh` — daily HTML email digest with severity counts, module breakdown, system health, recommendations
- `install.sh` — one-command installer: directories, config, cron jobs, logrotate, initial dry-run test
- `tests/test_analyzer.sh` — test suite covering all modules with synthetic log data
- `config.conf` — centralized configuration for all settings
