#!/usr/bin/env bash
# Check objective: Retain scanner evidence while deriving an actionable, reviewed PR baseline.
set -euo pipefail

# Preserve full scanner results as baseline evidence, but make the trusted PR
# decision actionable. All Checkov findings reach OPA, including findings on
# the base revision: only reviewed, expiring policy exceptions may exempt them.
# Zizmor delta handling is retained separately. Inputs are redacted envelopes.

if [ "$#" -ne 4 ]; then
  printf 'usage: %s HEAD_EVIDENCE_DIR BASE_EVIDENCE_DIR OUTPUT_EVIDENCE_DIR HEAD_SHA\n' "$0" >&2
  exit 64
fi

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$script_dir/lib/common.sh"
head_directory="$1"
base_directory="$2"
output_directory="$3"
head_sha="$4"

require_command jq
[[ "$head_sha" =~ ^[0-9a-f]{40}$ ]] || { printf 'head SHA must be 40 lowercase hexadecimal characters\n' >&2; exit 64; }
for tool in gitleaks osv semgrep zizmor checkov format terraform; do require_file "$head_directory/$tool.json"; done
for tool in zizmor checkov; do
  require_file "$base_directory/$tool.json"
  jq -e --arg tool "$tool" '.schema_version == "v1" and .tool == $tool and (.commit_sha | type == "string" and test("^[0-9a-f]{40}$")) and (.result | type == "object")' "$head_directory/$tool.json" "$base_directory/$tool.json" >/dev/null || { printf 'invalid %s scanner envelope\n' "$tool" >&2; exit 1; }
done

rm -rf "$output_directory"
mkdir -p "$output_directory"
cp "$head_directory"/{gitleaks,osv,semgrep,format,terraform}.json "$output_directory/"

# A pre-existing IaC vulnerability must not become an implicit exception.
cp "$head_directory/checkov.json" "$output_directory/checkov.json"

jq --slurpfile base "$base_directory/zizmor.json" '
  .result.findings as $head |
  ($base[0].result.findings // [] | map([(.path // "unknown"), (.rule_id // "unknown"), (.message // "unsafe workflow finding")] | @json) | unique) as $known |
  .result.findings = [$head[]? | select(([(.path // "unknown"), (.rule_id // "unknown"), (.message // "unsafe workflow finding")] | @json) as $identity | ($known | index($identity) | not))]
' "$head_directory/zizmor.json" > "$output_directory/zizmor.json"

jq -n --arg head_sha "$head_sha" --slurpfile head_checkov "$head_directory/checkov.json" --slurpfile base_checkov "$base_directory/checkov.json" --slurpfile head_zizmor "$head_directory/zizmor.json" --slurpfile base_zizmor "$base_directory/zizmor.json" '
  {schema_version:"v1", subject:{head_sha:$head_sha}, tools:{checkov:{base_count:($base_checkov[0].result.failed_checks | length), head_count:($head_checkov[0].result.failed_checks | length)}, zizmor:{base_count:($base_zizmor[0].result.findings | length), head_count:($head_zizmor[0].result.findings | length)}}}
' > "$output_directory/baseline-summary.json"

printf 'PASS: all Checkov findings reach policy; baseline counts and Zizmor deltas are retained.\n'
