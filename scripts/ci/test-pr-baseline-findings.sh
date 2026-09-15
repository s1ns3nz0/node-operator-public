#!/usr/bin/env bash
# Check objective: Verify baseline filtering preserves findings unless a reviewed exception applies.
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$script_dir/lib/common.sh"
require_command jq

temporary_directory="$(mktemp -d)"
trap 'rm -rf "$temporary_directory"' EXIT
head="$temporary_directory/head"
base="$temporary_directory/base"
output="$temporary_directory/output"
mkdir -p "$head" "$base"
sha="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

for directory in "$head" "$base"; do
  for tool in gitleaks osv semgrep format terraform; do
    printf '{"schema_version":"v1","tool":"%s","commit_sha":"%s","collected_at":"2026-09-07T00:00:00Z","result":{}}\n' "$tool" "$sha" > "$directory/$tool.json"
  done
done
printf '{"schema_version":"v1","tool":"checkov","commit_sha":"%s","collected_at":"2026-09-07T00:00:00Z","result":{"failed_checks":[{"resource":"aws_s3_bucket.legacy","check_id":"CKV_AWS_18","check_name":"legacy finding"}]}}\n' "$sha" > "$base/checkov.json"
printf '{"schema_version":"v1","tool":"zizmor","commit_sha":"%s","collected_at":"2026-09-07T00:00:00Z","result":{"findings":[{"path":".github/workflows/legacy.yml","rule_id":"unpinned-uses","message":"legacy finding"}]}}\n' "$sha" > "$base/zizmor.json"
printf '{"schema_version":"v1","tool":"checkov","commit_sha":"%s","collected_at":"2026-09-07T00:00:00Z","result":{"failed_checks":[{"resource":"aws_s3_bucket.legacy","check_id":"CKV_AWS_18","check_name":"legacy finding"},{"resource":"aws_iam_policy.new","check_id":"CKV_AWS_999","check_name":"new finding"}]}}\n' "$sha" > "$head/checkov.json"
printf '{"schema_version":"v1","tool":"zizmor","commit_sha":"%s","collected_at":"2026-09-07T00:00:00Z","result":{"findings":[{"path":".github/workflows/legacy.yml","rule_id":"unpinned-uses","message":"legacy finding"},{"path":".github/workflows/new.yml","rule_id":"dangerous-triggers","message":"new finding"}]}}\n' "$sha" > "$head/zizmor.json"

bash "$script_dir/filter-pr-baseline-findings.sh" "$head" "$base" "$output" "$sha"
cmp "$head/checkov.json" "$output/checkov.json"
jq -e '.result.failed_checks | length == 2' "$output/checkov.json" >/dev/null
jq -e '.result.findings == [{path:".github/workflows/new.yml",rule_id:"dangerous-triggers",message:"new finding"}]' "$output/zizmor.json" >/dev/null
jq -e '.tools.checkov == {base_count:1,head_count:2} and .tools.zizmor == {base_count:1,head_count:2}' "$output/baseline-summary.json" >/dev/null
printf 'PASS pre-existing and new Checkov findings both reach OPA without implicit baseline exemptions.\n'
