#!/usr/bin/env bash
# modules/analyze_journal.sh — systemd Journal Analyzer  v2.0.0
# Sourced by log_analyzer.sh.
# Reads from journald (journalctl) for systems using systemd journal.
# Detects: failed units, core dumps, kernel messages, boot errors, audit events.
# Falls back gracefully if journalctl is unavailable.
# set -euo pipefail is inherited.

module_analyze_journal() {
    command -v journalctl &>/dev/null || {
        log "INFO" "JOURNAL" "journalctl not found — skipping journal analysis"
        return 0
    }

    log "INFO" "JOURNAL" "Analyzing systemd journal (last ${JOURNAL_LINES:-2000} lines)"

    local lines="${JOURNAL_LINES:-2000}"
    local tmp_file
    tmp_file=$(mktemp /tmp/la_journal_XXXXXX)
    trap '[[ -n "${tmp_file:-}" ]] && rm -f "$tmp_file"' RETURN

    # Read recent journal entries (no-pager, UTC, quiet)
    journalctl -n "$lines" --no-pager -q 2>/dev/null > "$tmp_file" || {
        log "WARN" "JOURNAL" "journalctl returned non-zero — partial results may follow"
    }

    local total_lines
    total_lines=$(wc -l < "$tmp_file")
    [[ "$total_lines" -eq 0 ]] && { log "INFO" "JOURNAL" "No journal entries available"; return 0; }
    log "INFO" "JOURNAL" "Analyzing ${total_lines} journal line(s)"

    # ── Failed systemd units ──────────────────────────────────────────────
    local failed_units
    failed_units=$(journalctl --no-pager -q --since "-${CHECK_INTERVAL:-15}min" \
        -p err..emerg 2>/dev/null | wc -l; true)
    if (( failed_units > 0 )); then
        local unit_names
        unit_names=$(journalctl --no-pager -q --since "-${CHECK_INTERVAL:-15}min" \
            -p err..emerg 2>/dev/null \
            | grep -Eo '[a-zA-Z0-9_-]+\.service' \
            | sort -u | head -10 | tr '\n' ' ')
        add_finding "HIGH" "JOURNAL" \
            "systemd journal error/critical entries" \
            "${failed_units} error-level line(s) in last ${CHECK_INTERVAL:-15}min — services: ${unit_names:-n/a}"
    fi

    # ── Core dumps ────────────────────────────────────────────────────────
    local coredumps
    coredumps=$(grep -cEi "core dump|coredump|segfault" "$tmp_file" 2>/dev/null; true)
    if (( coredumps > 0 )); then
        local core_procs
        core_procs=$(grep -Ei "core dump|coredump" "$tmp_file" \
            | grep -oE 'of process [0-9]+ \([^)]+\)' \
            | head -5 | tr '\n' '; ')
        add_finding "HIGH" "JOURNAL" \
            "Core dump(s) detected via journal" \
            "${coredumps} coredump event(s) — ${core_procs:-check journalctl -t systemd-coredump}"
    fi

    # ── Kernel errors from journal ─────────────────────────────────────────
    local kern_errs
    kern_errs=$(grep -cEi "^.* kernel: .*(error|panic|BUG|fault|Oops)" "$tmp_file" 2>/dev/null; true)
    if (( kern_errs > 0 )); then
        local k_sample
        k_sample=$(grep -Ei "kernel: .*(error|panic|BUG|fault|Oops)" "$tmp_file" \
            | tail -3 | cut -c1-140 | tr '\n' ' | ')
        add_finding "CRITICAL" "JOURNAL" \
            "Kernel error/panic in journal" \
            "${kern_errs} kernel error(s) — ${k_sample}"
    fi

    # ── OOM from journal ──────────────────────────────────────────────────
    local oom_events
    oom_events=$(grep -cEi "Out of memory|oom_kill|Killed process" "$tmp_file" 2>/dev/null; true)
    if (( oom_events > 0 )); then
        local oom_procs
        oom_procs=$(grep -Ei "Killed process" "$tmp_file" \
            | grep -oE 'process [0-9]+ \([^)]+\)' \
            | head -3 | tr '\n' '; ')
        add_finding "CRITICAL" "JOURNAL" \
            "OOM kill detected via journal" \
            "${oom_events} OOM event(s) — ${oom_procs:-check journalctl -k}"
    fi

    # ── SSH failures via journal (auth.log alternative) ──────────────────
    local ssh_fails
    ssh_fails=$(grep -cEi "Failed password|Invalid user" "$tmp_file" 2>/dev/null; true)
    if (( ssh_fails > 0 )); then
        local top_ips
        top_ips=$(grep -Ei "Failed password|Invalid user" "$tmp_file" \
            | grep -oE 'from [0-9a-f:\.]+' | awk '{print $2}' \
            | sort | uniq -c | sort -rn | head -5 \
            | awk '{printf "%s(%d) ", $2, $1}')
        add_finding "HIGH" "JOURNAL" \
            "SSH authentication failures in journal" \
            "${ssh_fails} failure(s) — top IPs: ${top_ips:-see journalctl _SYSTEMD_UNIT=sshd.service}"
    fi

    # ── Audit / SELinux denials ────────────────────────────────────────────
    local avc_denials
    avc_denials=$(grep -cEi "avc:.*denied|SELinux.*denied|type=AVC" "$tmp_file" 2>/dev/null; true)
    if (( avc_denials > 0 )); then
        add_finding "MEDIUM" "JOURNAL" \
            "SELinux/AVC denial(s) in journal" \
            "${avc_denials} AVC denial(s) — run: audit2why < /var/log/audit/audit.log"
    fi

    # ── Service restart loops ─────────────────────────────────────────────
    local restart_loops
    restart_loops=$(grep -cEi "start-limit-hit|too many restarts" "$tmp_file" 2>/dev/null; true)
    if (( restart_loops > 0 )); then
        local loop_svcs
        loop_svcs=$(grep -Ei "start-limit-hit" "$tmp_file" \
            | grep -oE '[a-zA-Z0-9_-]+\.service' \
            | sort -u | head -5 | tr '\n' ' ')
        add_finding "HIGH" "JOURNAL" \
            "Service restart loop detected" \
            "${restart_loops} start-limit-hit event(s) — services: ${loop_svcs:-check systemctl --failed}"
    fi

    # ── Disk I/O errors from journal ──────────────────────────────────────
    local io_errors
    io_errors=$(grep -cEi "I/O error|blk_update_request|Buffer I/O error|disk error" \
        "$tmp_file" 2>/dev/null; true)
    if (( io_errors > 0 )); then
        local io_devs
        io_devs=$(grep -Ei "I/O error|Buffer I/O error" "$tmp_file" \
            | grep -oE '(sd[a-z]+|nvme[0-9a-z]+|dm-[0-9]+)' \
            | sort -u | head -5 | tr '\n' ' ')
        add_finding "CRITICAL" "JOURNAL" \
            "Disk I/O error(s) in journal" \
            "${io_errors} I/O error(s) — devices: ${io_devs:-check dmesg | grep -i error}"
    fi

    log "INFO" "JOURNAL" "Journal analysis complete"
}
