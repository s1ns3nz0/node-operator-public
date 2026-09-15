#!/usr/bin/env bash
# Purpose: Run the bounded static Fence security scan with the supplied scanner binary.
# Inputs: GOSEC_BIN and the validator-signing-fence source tree.
# Outputs: Fence SAST report files in the configured runner path.
# Side effects: Local static analysis and report writes only; no network, cloud, or image publication.
# Check objective: Scan the signing-fence source with pinned gosec and reject HIGH findings or scan errors.
set -euo pipefail

[ "$#" -eq 1 ] || { printf 'usage: %s OUTPUT_DIRECTORY\n' "$0" >&2; exit 64; }
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
output="$1"; mkdir -p "$output"
gosec_bin="${GOSEC_BIN:-gosec}"
command -v "$gosec_bin" >/dev/null 2>&1 || { printf 'pinned gosec is required\n' >&2; exit 69; }
revision="$(git -C "$root" rev-parse HEAD)"
raw="$output/gosec.json"
# Exit 1 is a documented findings result; all other nonzero exits are scanner
# failures. A report with parse or package errors is never treated as clean.
set +e
"$gosec_bin" -fmt=json -out="$raw" "$root/cmd/validator-signing-fence"
scanner_exit=$?
set -e
case "$scanner_exit" in 0|1) ;; *) printf 'gosec execution failed with exit %s\n' "$scanner_exit" >&2; exit 1;; esac
jq -e '
  (.Issues | type == "array") and
  ((.GosecErrors // {}) | ((type == "array" or type == "object") and length == 0)) and
  ((.Stats.files // 0) | type == "number" and . > 0) and
  all(.Issues[]; (.severity | type == "string") and ((.severity | ascii_upcase) == "LOW" or (.severity | ascii_upcase) == "MEDIUM" or (.severity | ascii_upcase) == "HIGH") and (.rule_id | type == "string")) and
  ([.Issues[] | select((.severity | ascii_upcase) == "HIGH")] | length == 0)
' "$raw" >/dev/null || { printf 'gosec report is incomplete, has scan errors, or has HIGH findings\n' >&2; exit 1; }
raw_sha="$(sha256sum "$raw" | awk '{print $1}')"
jq -n --arg source_sha "$revision" --arg gosec_version "$("$gosec_bin" -version 2>&1 | tr '\n' ' ')" --arg report_sha256 "$raw_sha" \
  '{schema_version:1,scanner:"gosec",source_sha:$source_sha,report_sha256:$report_sha256,tool_version:$gosec_version,result:"PASS",high_findings:0}' > "$output/result.json"
printf 'PASS gosec SAST result bound to %s\n' "$revision"
