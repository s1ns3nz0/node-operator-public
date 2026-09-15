#!/usr/bin/env bash
# Check objective: Verify evidence normalization rejects malformed scanner and SCM inputs.
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$script_dir/lib/common.sh"
root="$(repo_root)"
temporary_directory="$(mktemp -d)"
trap 'rm -rf "$temporary_directory"' EXIT
"$script_dir/normalize-evidence.sh" "$root/policy/tests/fixtures/raw-evidence/clean" aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa "$root/policy/tests/fixtures/raw-evidence/clean/scm.json" "$temporary_directory/normalized.json"
jq -e --slurpfile exceptions "$root/policy/data/exceptions.json" '
  .evidence.gitleaks.findings == [] and
  .evidence.format.status == "passed" and
  .evidence.terraform.status == "not_applicable" and
  .policy.exceptions == $exceptions[0].exceptions
' "$temporary_directory/normalized.json" >/dev/null
cp -R "$root/policy/tests/fixtures/raw-evidence/clean" "$temporary_directory/secret-bearing"
jq '.result.findings = [{path:"fixture.env", rule_id:"fixture-rule", Secret:"DO_NOT_PERSIST"}]' "$temporary_directory/secret-bearing/gitleaks.json" > "$temporary_directory/secret-bearing/gitleaks.next"
mv "$temporary_directory/secret-bearing/gitleaks.next" "$temporary_directory/secret-bearing/gitleaks.json"
"$script_dir/normalize-evidence.sh" "$temporary_directory/secret-bearing" aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa "$root/policy/tests/fixtures/raw-evidence/clean/scm.json" "$temporary_directory/redacted.json"
jq -e '.evidence.gitleaks.findings == [{path:"fixture.env",rule_id:"fixture-rule"}]' "$temporary_directory/redacted.json" >/dev/null
if grep -l 'DO_NOT_PERSIST' "$temporary_directory/redacted.json" >/dev/null; then printf 'normalizer retained a secret-bearing Gitleaks field\n' >&2; exit 1; fi
if incomplete_output="$("$script_dir/normalize-evidence.sh" "$root/policy/tests/fixtures/raw-evidence/incomplete" aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa "$root/policy/tests/fixtures/raw-evidence/clean/scm.json" "$temporary_directory/incomplete.json" 2>&1)"; then
  printf 'incomplete evidence fixture unexpectedly normalized\n' >&2
  exit 1
fi
grep -Fqx 'invalid osv collector envelope' <<<"$incomplete_output"
