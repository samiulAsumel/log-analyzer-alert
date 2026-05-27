#!/usr/bin/env bash
# modules/alert_engine.sh — Alert Engine  v1.0.0
# Sourced by log_analyzer.sh.
# Provides: _send_critical_alert  _send_high_alert  _send_alert
# Handles email (sendmail/mailx), Slack webhooks, rate-limiting.
# set -euo pipefail is inherited from the orchestrator.

# ── Rate-limit helper ─────────────────────────────────────────────────────────
# Returns 0 (allow) or 1 (suppressed) for a given alert key.
_alert_allowed() {
    local key="$1" cooldown_min="${2:-${HIGH_ALERT_COOLDOWN:-30}}"
    local slug; slug=$(echo "$key" | tr -cs 'a-zA-Z0-9' '_')
    local stamp_file="${COOLDOWN_DIR:-/var/lib/loganalyzer/cooldowns}/${slug}"
    local now; now=$(date +%s)
    local cutoff=$(( now - cooldown_min * 60 ))

    if [[ -f "$stamp_file" ]]; then
        local last; last=$(cat "$stamp_file" 2>/dev/null || echo 0)
        if [[ "$last" -gt "$cutoff" ]]; then
            local wait=$(( (last - cutoff) / 60 ))
            log "INFO" "ALERT" "Rate-limited '${key}' — suppressed for ${wait} more min"
            return 1
        fi
    fi
    ${DRY_RUN:-false} || echo "$now" > "$stamp_file"
    return 0
}

# ── HTML email body builder ───────────────────────────────────────────────────
_build_email_html() {
    local subject="$1" severity="$2"
    shift 2
    local findings=("$@")

    local colour
    case "${severity^^}" in
        CRITICAL) colour="#cc0000" ;;
        HIGH)     colour="#e65c00" ;;
        MEDIUM)   colour="#e6b800" ;;
        *)        colour="#0073e6" ;;
    esac

    cat <<HTML
<!DOCTYPE html>
<html>
<head><meta charset="UTF-8">
<style>
  body   { font-family: 'Segoe UI', Arial, sans-serif; background:#f4f4f4; margin:0; padding:0; }
  .wrap  { max-width:680px; margin:30px auto; background:#fff;
           border-radius:8px; overflow:hidden; box-shadow:0 2px 8px rgba(0,0,0,.12); }
  .hdr   { background:${colour}; color:#fff; padding:24px 32px; }
  .hdr h1{ margin:0; font-size:20px; }
  .hdr p { margin:6px 0 0; opacity:.85; font-size:13px; }
  .body  { padding:28px 32px; }
  table  { width:100%; border-collapse:collapse; margin:16px 0; }
  th     { background:#f0f0f0; text-align:left; padding:8px 12px;
           font-size:12px; text-transform:uppercase; color:#555; }
  td     { padding:8px 12px; border-bottom:1px solid #eee; font-size:13px; vertical-align:top; }
  .sev-CRITICAL { color:#cc0000; font-weight:700; }
  .sev-HIGH     { color:#e65c00; font-weight:700; }
  .sev-MEDIUM   { color:#e6b800; font-weight:600; }
  .sev-LOW      { color:#0073e6; }
  .footer { background:#f9f9f9; padding:16px 32px; font-size:11px; color:#999;
            border-top:1px solid #eee; }
</style></head>
<body>
<div class="wrap">
  <div class="hdr">
    <h1>🔔 ${subject}</h1>
    <p>Host: $(hostname -f 2>/dev/null || echo unknown) &nbsp;|&nbsp; $(date '+%Y-%m-%d %H:%M:%S %Z')</p>
  </div>
  <div class="body">
    <table>
      <tr><th>Severity</th><th>Module</th><th>Finding</th><th>Detail</th></tr>
HTML

    for f in "${findings[@]}"; do
        IFS='|' read -r sev mod title detail <<< "$f"
        cat <<ROW
      <tr>
        <td class="sev-${sev^^}">${sev^^}</td>
        <td>${mod}</td>
        <td>${title}</td>
        <td style="color:#555;font-size:12px;">${detail}</td>
      </tr>
ROW
    done

    cat <<HTML
    </table>
    <p style="font-size:12px;color:#777;margin-top:20px;">
      Log Analyzer &amp; Alert System v${VERSION:-1.0.0} — findings stored in ${FINDINGS_DIR:-/var/lib/loganalyzer/findings}
    </p>
  </div>
  <div class="footer">This is an automated alert. Do not reply to this message.</div>
</div>
</body></html>
HTML
}

# ── Slack message builder ─────────────────────────────────────────────────────
_build_slack_payload() {
    local subject="$1" severity="$2"
    shift 2
    local findings=("$@")

    local emoji colour
    case "${severity^^}" in
        CRITICAL) emoji=":red_circle:"; colour="danger"  ;;
        HIGH)     emoji=":orange_circle:"; colour="warning" ;;
        MEDIUM)   emoji=":yellow_circle:"; colour="warning" ;;
        *)        emoji=":blue_circle:";  colour="good"    ;;
    esac

    local text="${emoji} *${subject}* on \`$(hostname -s 2>/dev/null)\`\n"
    local fields=""
    for f in "${findings[@]:0:5}"; do   # Slack limits; cap at 5
        IFS='|' read -r sev mod title detail <<< "$f"
        fields+="*[${sev^^}]* ${mod}: ${title}"
        [[ -n "$detail" ]] && fields+=" — ${detail}"
        fields+="\n"
    done

    printf '{"attachments":[{"color":"%s","text":"%s","fields":[{"value":"%s","short":false}],"footer":"LogAnalyzer v%s","ts":%s}]}' \
        "$colour" \
        "$(echo -n "$text" | sed 's/"/\\"/g')" \
        "$(echo -n "$fields" | sed 's/"/\\"/g')" \
        "${VERSION:-1.0.0}" \
        "$(date +%s)"
}

# ── Core send function ────────────────────────────────────────────────────────
# _send_alert SEVERITY SUBJECT FINDING [FINDING ...]
_send_alert() {
    local severity="$1" subject="$2"
    shift 2
    local findings=("$@")

    ${DRY_RUN:-false} && {
        log "INFO" "ALERT" "[DRY-RUN] Would send ${severity} alert: ${subject}"
        return 0
    }

    local method="${ALERT_METHOD:-email}"

    # ── Email ──────────────────────────────────────────────────────────────
    if [[ "$method" == "email" || "$method" == "both" ]]; then
        if [[ -z "${ALERT_EMAIL:-}" ]]; then
            log "WARN" "ALERT" "ALERT_EMAIL not set — skipping email"
        else
            local html
            html=$(_build_email_html "$subject" "$severity" "${findings[@]}")
            local full_subject="[LogAlert][${severity^^}] ${subject} @ $(hostname -s)"

            # Try mailx, then sendmail, then mutt
            if command -v mailx &>/dev/null; then
                echo "$html" | mailx -a "Content-Type: text/html" \
                    -s "$full_subject" \
                    -r "${ALERT_FROM:-loganalyzer@localhost}" \
                    "$ALERT_EMAIL" 2>/dev/null \
                && log "OK" "ALERT" "Email sent via mailx → ${ALERT_EMAIL}" \
                || log "WARN" "ALERT" "mailx failed"

            elif command -v sendmail &>/dev/null; then
                {
                    echo "To: ${ALERT_EMAIL}"
                    echo "From: ${ALERT_FROM:-loganalyzer@localhost}"
                    echo "Subject: ${full_subject}"
                    echo "Content-Type: text/html; charset=UTF-8"
                    echo "MIME-Version: 1.0"
                    echo ""
                    echo "$html"
                } | sendmail -t 2>/dev/null \
                && log "OK" "ALERT" "Email sent via sendmail → ${ALERT_EMAIL}" \
                || log "WARN" "ALERT" "sendmail failed"
            else
                log "WARN" "ALERT" "No mail agent found (mailx/sendmail) — email not sent"
            fi
        fi
    fi

    # ── Slack ──────────────────────────────────────────────────────────────
    if [[ "$method" == "slack" || "$method" == "both" ]]; then
        if [[ -z "${SLACK_WEBHOOK:-}" ]]; then
            log "WARN" "ALERT" "SLACK_WEBHOOK not set — skipping Slack"
        elif command -v curl &>/dev/null; then
            local payload
            payload=$(_build_slack_payload "$subject" "$severity" "${findings[@]}")
            curl -s -X POST -H 'Content-type: application/json' \
                --data "$payload" \
                "$SLACK_WEBHOOK" &>/dev/null \
            && log "OK" "ALERT" "Slack message sent" \
            || log "WARN" "ALERT" "Slack webhook call failed"
        else
            log "WARN" "ALERT" "curl not found — Slack alert skipped"
        fi
    fi
}

# ── Public helpers called by orchestrator ────────────────────────────────────

_send_critical_alert() {
    local critical_findings=()
    for f in "${ALL_FINDINGS[@]:-}"; do
        [[ "$f" == CRITICAL* ]] && critical_findings+=("$f")
    done
    [[ ${#critical_findings[@]} -eq 0 ]] && return 0

    local key="CRITICAL_$(date '+%Y%m%d_%H')"   # one per hour, always fires
    # CRITICAL always bypasses rate-limit
    local subject="CRITICAL: ${CRITICAL_COUNT} critical issue(s) detected"
    _send_alert "CRITICAL" "$subject" "${critical_findings[@]}"
    log "OK" "ALERT" "CRITICAL alert dispatched (${CRITICAL_COUNT} finding(s))"
}

_send_high_alert() {
    local high_findings=()
    for f in "${ALL_FINDINGS[@]:-}"; do
        [[ "$f" == HIGH* ]] && high_findings+=("$f")
    done
    [[ ${#high_findings[@]} -eq 0 ]] && return 0

    local key="HIGH_$(date '+%Y%m%d')"
    _alert_allowed "$key" "${HIGH_ALERT_COOLDOWN:-30}" || return 0

    local subject="HIGH: ${HIGH_COUNT} high-severity issue(s) detected"
    _send_alert "HIGH" "$subject" "${high_findings[@]}"
    log "OK" "ALERT" "HIGH alert dispatched (${HIGH_COUNT} finding(s))"
}
