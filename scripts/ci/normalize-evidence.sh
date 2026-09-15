#!/usr/bin/env bash
# Purpose: Validate trusted scanner envelopes and construct bounded normalized policy input.
# Inputs: Raw evidence directory, subject SHA, SCM JSON, and destination JSON path.
# Outputs: Normalized evidence JSON for OPA evaluation.
# Side effects: Local validation and output-file creation only; no network or scanner execution.
# Check objective: Validate scanner envelopes and assemble the bounded OPA policy input.
set -euo pipefail

if [ "$#" -ne 4 ]; then printf 'usage: %s RAW_EVIDENCE_DIR COMMIT_SHA SCM_JSON OUTPUT_JSON\n' "$0" >&2; exit 64; fi
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$script_dir/lib/common.sh"
root="$(repo_root)"; raw_directory="$1"; commit_sha="$2"; scm_path="$3"; output_path="$4"
require_command jq
[[ "$commit_sha" =~ ^[0-9a-f]{40}$ ]] || { printf 'commit SHA must be 40 lowercase hexadecimal characters\n' >&2; exit 64; }
require_file "$scm_path"
jq -e --arg sha "$commit_sha" '(.changed_files | type == "array") and (.pull_request.author | type == "string") and .pull_request.head_sha == $sha and (.approvers | type == "array")' "$scm_path" >/dev/null || { printf 'invalid SCM posture evidence\n' >&2; exit 1; }
for tool in gitleaks osv semgrep zizmor checkov format terraform; do
  source_path="$raw_directory/$tool.json"
  require_file "$source_path"
  jq -e --arg tool "$tool" --arg sha "$commit_sha" '
    .schema_version == "v1" and .tool == $tool and .commit_sha == $sha and
    (.collected_at | type == "string") and (.result | type == "object")
  ' "$source_path" >/dev/null || { printf 'invalid %s collector envelope\n' "$tool" >&2; exit 1; }
done
mkdir -p "$(dirname "$output_path")"
jq -n --arg sha "$commit_sha" --slurpfile tiers "$root/policy/data/tiers.json" --slurpfile exceptions "$root/policy/data/exceptions.json" \
  --slurpfile gitleaks "$raw_directory/gitleaks.json" --slurpfile osv "$raw_directory/osv.json" --slurpfile semgrep "$raw_directory/semgrep.json" \
  --slurpfile zizmor "$raw_directory/zizmor.json" --slurpfile checkov "$raw_directory/checkov.json" --slurpfile format "$raw_directory/format.json" \
  --slurpfile terraform "$raw_directory/terraform.json" --slurpfile scm "$scm_path" \
  '{subject:{commit_sha:$sha}, evidence:{gitleaks:{findings:[$gitleaks[0].result.findings[]? | {path:(.path // "unknown"), rule_id:(.rule_id // "unknown")} ]}, osv:$osv[0].result, semgrep:$semgrep[0].result, zizmor:$zizmor[0].result, checkov:$checkov[0].result, format:$format[0].result, terraform:$terraform[0].result}, scm:$scm[0], policy:{tiers:$tiers[0], exceptions:$exceptions[0].exceptions}}' > "$output_path"
