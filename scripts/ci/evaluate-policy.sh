#!/usr/bin/env bash
# Purpose: Evaluate normalized evidence with the repository policy bundle.
# Inputs: Normalized evidence JSON, destination decision path, and local OPA tooling.
# Outputs: Policy decision JSON, including blocking and approval counts.
# Side effects: Local policy evaluation and file write only; no GitHub, cloud, or deployment action.
# Check objective: Evaluate a normalized evidence subject with OPA and fail on blocking decisions.
set -euo pipefail
if [ "$#" -ne 2 ]; then printf 'usage: %s INPUT_JSON OUTPUT_JSON\n' "$0" >&2; exit 64; fi
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$script_dir/lib/common.sh"
root="$(repo_root)"; input_path="$1"; output_path="$2"
require_command opa; require_command jq; require_file "$input_path"
mkdir -p "$(dirname "$output_path")"
opa eval --format json --ignore fixtures --data "$root/policy" --input "$input_path" 'data.nodeoperator.decision.decision' | jq -e '.result[0].expressions[0].value' > "$output_path"
if jq -e '.summary.block > 0' "$output_path" >/dev/null; then printf 'OPA policy blocked this subject; see %s\n' "$output_path" >&2; exit 1; fi
