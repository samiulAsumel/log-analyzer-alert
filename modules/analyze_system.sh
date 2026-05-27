#!/usr/bin/env bash
# modules/analyze_system.sh — System Log Analyzer  v1.0.0
# Sourced by log_analyzer.sh.
# Detects: OOM kills, kernel panics, hardware errors, segfaults, service crashes.
# set -euo pipefail is inherited.

module_analyze_system() {
    local logfile="${SYSLOG:-/var/log/messages}"
    log "INFO" "SYSTEM" "Analyzing: ${logfile}"

    local new_lines
    new_lines=$(read_new_lines "$logfile" 2>/dev/null) || {
        log "WARN" "SYSTEM" "Could not read ${logfile}"
        return 0
    }
    [[ -z "$new_lines" ]] && { log "INFO" "SYSTEM" "No new system log entries"; return 0; }

    local tmp_file
    tmp_file=$(mktemp /tmp/la_sys_XXXXXX)
    echo "$new_lines" > "$tmp_file"
    trap '[[ -n "${tmp_file:-}" ]] && rm -f "$tmp_file"' RETURN

    # ── Out-of-Memory (OOM) kills ──────────────────────────────────────────
    local oom_count
    oom_count=$(grep -cEi "Out of memory|oom-kill|oom_kill_process|Killed process" \
        "$tmp_file" 2>/dev/null; true)
    if (( oom_count > 0 )); then
        local oom_procs
        oom_procs=$(grep -Ei "Killed process" "$tmp_file" \
            | grep -oE 'process [0-9]+ \([^)]+\)' \
            | head -5 | tr '\n' ';' )
        add_finding "CRITICAL" "SYSTEM" \
            "Out-of-Memory kill detected" \
            "${oom_count} OOM event(s) — ${oom_procs}"
    fi

    # ── Kernel panic ──────────────────────────────────────────────────────
    local kpanic
    kpanic=$(grep -cEi "kernel panic|Kernel panic" "$tmp_file" 2>/dev/null; true)
    if (( kpanic > 0 )); then
        local kp_msg
        kp_msg=$(grep -Ei "kernel panic" "$tmp_file" | tail -1 | cut -c1-120)
        add_finding "CRITICAL" "SYSTEM" \
            "Kernel panic detected" \
            "${kpanic} panic(s) — last: ${kp_msg}"
    fi

    # ── Hardware errors ────────────────────────────────────────────────────
    local hw_errors
    hw_errors=$(grep -cEi "hardware error|machine check|MCE|EDAC|disk error|I/O error|sector.*error|bad block" \
        "$tmp_file" 2>/dev/null; true)
    if (( hw_errors > 0 )); then
        local hw_sample
        hw_sample=$(grep -Ei "hardware error|machine check|MCE|EDAC|disk error|I/O error" \
            "$tmp_file" | tail -3 | awk '{print $NF}' | tr '\n' ';')
        add_finding "CRITICAL" "SYSTEM" \
            "Hardware errors detected" \
            "${hw_errors} hardware error(s) — ${hw_sample}"
    fi

    # ── Disk full / no space ──────────────────────────────────────────────
    local disk_full
    disk_full=$(grep -cEi "No space left on device|disk full|filesystem.*full" \
        "$tmp_file" 2>/dev/null; true)
    if (( disk_full > 0 )); then
        local df_output
        df_output=$(df -h --output=pcent,target 2>/dev/null \
            | awk '$1 ~ /[0-9]/ { gsub(/%/,""); if ($1+0 >= 90) print $1"% "$2 }' \
            | tr '\n' ' ')
        add_finding "CRITICAL" "SYSTEM" \
            "Disk full / No space left on device" \
            "${disk_full} event(s). High usage: ${df_output:-check df -h}"
    fi

    # ── Segmentation faults ────────────────────────────────────────────────
    local segfaults
    segfaults=$(grep -cEi "segfault|segmentation fault|general protection fault" \
        "$tmp_file" 2>/dev/null; true)
    if (( segfaults > 0 )); then
        local seg_procs
        seg_procs=$(grep -Ei "segfault" "$tmp_file" \
            | grep -oE '\S+\[' | tr -d '[' | sort -u | head -5 | tr '\n' ' ')
        add_finding "HIGH" "SYSTEM" \
            "Segmentation fault(s) detected" \
            "${segfaults} segfault(s) — processes: ${seg_procs}"
    fi

    # ── Service crashes / systemd failures ────────────────────────────────
    local svc_crash
    svc_crash=$(grep -cEi "Failed to start|Service.*failed|start-limit-hit|entered failed state" \
        "$tmp_file" 2>/dev/null; true)
    if (( svc_crash > 0 )); then
        local failed_svcs
        failed_svcs=$(grep -Ei "Failed to start|entered failed state" "$tmp_file" \
            | grep -oE '\S+\.service' | sort -u | head -10 | tr '\n' ' ')
        add_finding "HIGH" "SYSTEM" \
            "Service failure(s) detected" \
            "${svc_crash} service failure(s) — ${failed_svcs}"
    fi

    # ── RAID degraded ─────────────────────────────────────────────────────
    local raid_events
    raid_events=$(grep -cEi "RAID degraded|md[0-9]+.*degraded|array.*degraded|disk.*removed from" \
        "$tmp_file" 2>/dev/null; true)
    if (( raid_events > 0 )); then
        add_finding "CRITICAL" "SYSTEM" \
            "RAID array degraded" \
            "${raid_events} RAID event(s) — check /proc/mdstat"
    fi

    # ── CPU / memory thermal throttling ───────────────────────────────────
    local thermal
    thermal=$(grep -cEi "CPU.*throttled|thermal throttle|temperature above threshold|Critical Temperature" \
        "$tmp_file" 2>/dev/null; true)
    if (( thermal > 0 )); then
        add_finding "HIGH" "SYSTEM" \
            "CPU thermal throttling detected" \
            "${thermal} throttle event(s) — check cooling"
    fi

    # ── NFS / mount errors ─────────────────────────────────────────────────
    local mount_errors
    mount_errors=$(grep -cEi "nfs: server|mount.*failed|unable to mount|Transport endpoint is not connected" \
        "$tmp_file" 2>/dev/null; true)
    if (( mount_errors > 0 )); then
        add_finding "MEDIUM" "SYSTEM" \
            "Filesystem mount errors" \
            "${mount_errors} mount error(s)"
    fi

    # ── Generic kernel errors ──────────────────────────────────────────────
    local kern_errors
    kern_errors=$(grep -cEi "kernel:.*error|kernel:.*warning|call trace|BUG:" \
        "$tmp_file" 2>/dev/null; true)
    if (( kern_errors > 0 )); then
        add_finding "MEDIUM" "SYSTEM" \
            "Kernel errors/warnings" \
            "${kern_errors} kernel error/warning line(s)"
    fi

    log "INFO" "SYSTEM" "System log analysis complete"
}
