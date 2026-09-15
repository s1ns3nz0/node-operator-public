#!/usr/bin/env bash
# Purpose: Copy validated evidence and decision JSON and derive a bounded SARIF representation.
# Inputs: Normalized evidence JSON, decision JSON, and a new output directory.
# Outputs: evidence.json, decision.json, and policy.sarif beneath the output directory.
# Side effects: Creates local evidence files only; it does not upload or publish them.
set -euo pipefail

if [ "$#" -ne 3 ]; then printf 'usage: %s NORMALIZED_JSON DECISION_JSON OUTPUT_DIRECTORY\n' "$0" >&2; exit 64; fi

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$script_dir/lib/common.sh"

normalized_path="$1"; decision_path="$2"; output_directory="$3"
require_command jq; require_file "$normalized_path"; require_file "$decision_path"
jq -e '.subject.commit_sha | test("^[0-9a-f]{40}$")' "$normalized_path" >/dev/null
jq -e '.violations | type == "array"' "$decision_path" >/dev/null

[ ! -e "$output_directory" ] || { printf 'output directory already exists: %s\n' "$output_directory" >&2; exit 1; }
mkdir -p "$output_directory"
cp "$normalized_path" "$output_directory/evidence.json"
cp "$decision_path" "$output_directory/decision.json"
jq -n --slurpfile decision "$decision_path" --arg sha "$(jq -r '.subject.commit_sha' "$normalized_path")" '
  {version:"2.1.0","$schema":"https://json.schemastore.org/sarif-2.1.0.json",runs:[{
    tool:{driver:{name:"node-operator-opa",informationUri:"https://www.openpolicyagent.org/",rules:([ $decision[0].violations[] | {id:.id,name:.id,shortDescription:{text:.reason}} ] | unique_by(.id))}},
    results:[ $decision[0].violations[] | {ruleId:.id,level:(if .class == "block" then "error" else "warning" end),message:{text:.reason},locations:[{physicalLocation:{artifactLocation:{uri:.evidence_ref}}}],partialFingerprints:{nodeOperatorSubject:$sha}} ]
  }]}' > "$output_directory/policy.sarif"
