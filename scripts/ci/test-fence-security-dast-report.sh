#!/usr/bin/env bash
# Check objective: Reject malformed, target-mismatched, or high-risk Fence ZAP reports.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
filter="$root/.ci/fence-security/zap-report.jq"
target='http://127.0.0.1:9002'
assert_rejected() {
  if printf '%s\n' "$1" | jq -e --arg target "$target" -f "$filter" >/dev/null; then
    printf 'accepted invalid synthetic ZAP report: %s\n' "$2" >&2; exit 1
  fi
}
medium='{"site":[{"@name":"http://127.0.0.1:9002","alerts":[{"riskcode":"2"}]}]}'
printf '%s\n' "$medium" | jq -e --arg target "$target" -f "$filter" >/dev/null
assert_rejected '{}' malformed
assert_rejected '{"site":[]}' missing-site
assert_rejected '{"site":[{"@name":"http://127.0.0.1:9002"}]}' missing-alerts
assert_rejected '{"site":[{"@name":"http://127.0.0.1:9002","alerts":[{"riskcode":"9"}]}]}' unknown-risk
assert_rejected '{"site":[{"@name":"http://127.0.0.1:9999","alerts":[]}]}' wrong-target
assert_rejected '{"site":[{"@name":"http://127.0.0.1:9002","alerts":[{"riskcode":"3"}]}]}' high
stale="$(mktemp -d)"; trap 'rm -rf "$stale"' EXIT
touch "$stale/scan.done"
if "$root/scripts/ci/run-fence-security-dast.sh" "$stale" >/dev/null 2>&1; then
  printf 'accepted stale DAST output directory\n' >&2; exit 1
fi
printf 'PASS fence DAST report parser rejects incomplete, unknown, high, and stale results.\n'
