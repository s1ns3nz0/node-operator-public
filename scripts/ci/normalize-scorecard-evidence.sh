#!/usr/bin/env bash
# Check objective: Convert official Scorecard SARIF into bounded, non-secret posture evidence.
set -euo pipefail

: "${SCORECARD_SARIF:?SCORECARD_SARIF is required}"
: "${OUTPUT:?OUTPUT is required}"
[[ "$SCORECARD_SARIF" = /* && "$OUTPUT" = /* ]] || { printf '%s\n' 'paths must be absolute' >&2; exit 64; }
[[ -f "$SCORECARD_SARIF" ]] || { printf '%s\n' 'Scorecard SARIF is missing' >&2; exit 1; }
command -v jq >/dev/null || { printf '%s\n' 'missing command: jq' >&2; exit 1; }

jq -e '
  .version == "2.1.0" and
  (.runs | type == "array" and length > 0) and
  ([.runs[].tool.driver.name] | any(. == "Scorecard" or . == "OpenSSF Scorecard"))
' "$SCORECARD_SARIF" >/dev/null || {
  printf '%s\n' 'Scorecard SARIF schema is invalid' >&2
  exit 1
}

mkdir -p "$(dirname "$OUTPUT")"
jq -n \
  --arg commit "${GITHUB_SHA:-unknown}" \
  --arg collected_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --slurpfile sarif "$SCORECARD_SARIF" \
  '{schema_version:"v1",tool:"OpenSSF Scorecard",commit_sha:$commit,collected_at:$collected_at,result:{status:"complete",sarif_version:$sarif[0].version,run_count:($sarif[0].runs|length),artifact:"scorecard.sarif"}}' \
  > "$OUTPUT"
printf 'PASS: normalized OpenSSF Scorecard evidence at %s\n' "$OUTPUT"
