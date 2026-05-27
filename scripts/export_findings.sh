#!/usr/bin/env bash
# scripts/export_findings.sh — SIEM-Ready Findings Export  v2.0.0
# Exports findings to JSON (Splunk/Elasticsearch/Loki compatible) or CSV.
# Usage: bash export_findings.sh [--format=json|csv|ndjson] [--since=HOURS] [--out=FILE]
# Outputs to stdout if --out is not specified.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
CONFIG_FILE="${ROOT_DIR}/config.conf"

FORMAT="ndjson"; SINCE_HOURS=24; OUT_FILE=""
for _arg in "$@"; do
    case "$_arg" in
        --format=*) FORMAT="${_arg#*=}"       ;;
        --since=*)  SINCE_HOURS="${_arg#*=}"  ;;
        --out=*)    OUT_FILE="${_arg#*=}"      ;;
    esac
done

# ── Load config ───────────────────────────────────────────────────────────────
if [[ -f "$CONFIG_FILE" ]]; then
    # shellcheck source=../config.conf
    source "$CONFIG_FILE"
elif [[ -f /etc/loganalyzer/config.conf ]]; then
    source /etc/loganalyzer/config.conf
fi

FINDINGS_DIR="${FINDINGS_DIR:-/var/lib/loganalyzer/findings}"
HOST=$(hostname -f 2>/dev/null || echo unknown)
VERSION="${VERSION:-2.0.0}"

# ── Collect findings ──────────────────────────────────────────────────────────
collect_raw() {
    [[ -d "$FINDINGS_DIR" ]] || { echo ""; return 0; }
    find "$FINDINGS_DIR" -name "*.findings" \
        -mmin "-$(( SINCE_HOURS * 60 ))" 2>/dev/null \
        | sort | xargs cat 2>/dev/null || true
}

# ── JSON escape helper ────────────────────────────────────────────────────────
_jq_str() { echo -n "$1" | sed 's/\\/\\\\/g; s/"/\\"/g; s/\t/\\t/g'; }

# ── CSV header ────────────────────────────────────────────────────────────────
_csv_header() { echo "timestamp,host,severity,module,title,detail,version"; }

# ── Build output ──────────────────────────────────────────────────────────────
NOW_ISO=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
FINDINGS_ARRAY=()

while IFS='|' read -r sev mod title detail; do
    [[ -z "$sev" ]] && continue
    FINDINGS_ARRAY+=("${sev}|${mod}|${title}|${detail}")
done < <(collect_raw)

# Determine output fd
if [[ -n "$OUT_FILE" ]]; then
    exec 3>"$OUT_FILE"
else
    exec 3>&1
fi

case "$FORMAT" in
    ndjson)
        # Newline-delimited JSON — ideal for fluentd/filebeat/logstash
        for f in "${FINDINGS_ARRAY[@]:-}"; do
            IFS='|' read -r sev mod title detail <<< "$f"
            printf '{"@timestamp":"%s","host":"%s","severity":"%s","module":"%s","title":"%s","detail":"%s","source":"loganalyzer","version":"%s"}\n' \
                "$NOW_ISO" \
                "$(_jq_str "$HOST")" \
                "$(_jq_str "${sev^^}")" \
                "$(_jq_str "$mod")" \
                "$(_jq_str "$title")" \
                "$(_jq_str "$detail")" \
                "$VERSION" >&3
        done
        ;;

    json)
        # Single JSON array — for REST API upload or manual review
        printf '{\n  "export_time": "%s",\n  "host": "%s",\n  "since_hours": %s,\n  "count": %d,\n  "findings": [\n' \
            "$NOW_ISO" "$(_jq_str "$HOST")" "$SINCE_HOURS" "${#FINDINGS_ARRAY[@]}" >&3
        local_sep=""
        for f in "${FINDINGS_ARRAY[@]:-}"; do
            IFS='|' read -r sev mod title detail <<< "$f"
            printf '%s    {"severity":"%s","module":"%s","title":"%s","detail":"%s"}' \
                "$local_sep" \
                "$(_jq_str "${sev^^}")" \
                "$(_jq_str "$mod")" \
                "$(_jq_str "$title")" \
                "$(_jq_str "$detail")" >&3
            local_sep=$',\n'
        done
        printf '\n  ]\n}\n' >&3
        ;;

    csv)
        _csv_header >&3
        for f in "${FINDINGS_ARRAY[@]:-}"; do
            IFS='|' read -r sev mod title detail <<< "$f"
            # Escape commas/quotes for CSV
            _csv_field() { echo -n "\"$(echo -n "$1" | sed 's/"/\"\"/g')\""; }
            printf '%s,%s,%s,%s,%s,%s,%s\n' \
                "$NOW_ISO" \
                "$(_csv_field "$HOST")" \
                "$(_csv_field "${sev^^}")" \
                "$(_csv_field "$mod")" \
                "$(_csv_field "$title")" \
                "$(_csv_field "$detail")" \
                "$VERSION" >&3
        done
        ;;

    *)
        echo "Unknown format: ${FORMAT}. Use: json | ndjson | csv" >&2
        exit 1
        ;;
esac

exec 3>&-

if [[ -n "$OUT_FILE" ]]; then
    echo "Exported ${#FINDINGS_ARRAY[@]} finding(s) → ${OUT_FILE} (format: ${FORMAT})"
fi
