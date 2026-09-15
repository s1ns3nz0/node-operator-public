#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
script="$root/scripts/ci/verify-vault-bootstrap-revocation.sh"
doc="$root/docs/gitops/vault-bootstrap-phases.md"
revoke_plan_test="$root/scripts/ci/test-vault-bootstrap-revoke-plan.sh"
grep -Fqx "policy_arn='arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy'" "$script"
grep -Fq 'list-associated-access-policies' "$script"
grep -Fq "select(.policyArn == \$policy)" "$script"
test -x "$revoke_plan_test" || test -f "$revoke_plan_test"
for phase in '**Prepare:**' '**Deploy:**' '**Revoke:**'; do grep -Fq "$phase" "$doc"; done
if grep -Eqi 'vault operator (init|unseal)|kubectl.*secret.*-o (json|yaml)' "$script" "$doc"; then exit 1; fi
printf 'PASS Vault bootstrap revocation contract is explicit and secret-free.\n'
