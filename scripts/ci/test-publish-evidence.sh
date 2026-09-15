#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$script_dir/lib/common.sh"
root="$(repo_root)"; temporary_directory="$(mktemp -d)"
trap 'rm -rf "$temporary_directory"' EXIT

printf '%s\n' '{"violations":[{"id":"secret.detected","class":"block","reason":"secret detection finding reported","subject":"fixture.env","evidence_ref":"evidence.gitleaks"}],"summary":{"block":1,"warn":0,"require_approval":0}}' > "$temporary_directory/decision.json"
"$script_dir/publish-evidence.sh" "$root/policy/tests/fixtures/evidence-clean.json" "$temporary_directory/decision.json" "$temporary_directory/published"
jq -e '.runs[0].results[0].ruleId == "secret.detected" and .runs[0].results[0].partialFingerprints.nodeOperatorSubject == "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"' "$temporary_directory/published/policy.sarif" >/dev/null
test -f "$temporary_directory/published/evidence.json"
test -f "$temporary_directory/published/decision.json"
