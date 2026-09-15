#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# A container-mounted worktree has host-only Git metadata. Only source paths
# are needed, so this check also works from an extracted release bundle.
root="$(cd "$script_dir/../.." && pwd -P)"
temporary_directory="$(mktemp -d)"
trap 'rm -rf "$temporary_directory"' EXIT
fail() { printf 'FAIL Argo CD bootstrap enabled plan: %s\n' "$*" >&2; exit 1; }

"$script_dir/validate-terraform-offline.sh" \
  "$root/infra/terraform" \
  "$temporary_directory/disabled" \
  fixtures/offline-baseline.tfvars

"$script_dir/validate-terraform-offline.sh" \
  "$root/infra/terraform" \
  "$temporary_directory" \
  fixtures/offline-argocd-bootstrap.tfvars

plan="$temporary_directory/plan.json"
if [ "$#" -eq 1 ]; then
  # Export a synthetic plan for the host Python verifier when the pinned
  # Terraform container has no Python. The runner must verify this artifact.
  cp "$plan" "$1"
elif [ "$#" -eq 0 ]; then
  python3 "$script_dir/test-deployment-tags.py" "$plan"
else
  fail 'expected at most one synthetic plan output path'
fi
jq -e '
  any(.resource_changes[]?; .address == "aws_codebuild_project.argocd_bootstrap[0]" and (.change.actions | index("create")))
  and any(.resource_changes[]?; .address == "aws_eks_access_entry.argocd_bootstrap[0]" and (.change.actions | index("create")))
' "$plan" >/dev/null || fail 'enabled plan does not create the bootstrap project and its EKS access entry'

jq -e '
  ([.resource_changes[]? | select(.change.actions | index("create")) | .type]
    | any(. == "aws_nat_gateway" or . == "aws_internet_gateway") | not)
  and
  ([.resource_changes[]? | select(.change.actions | index("create")) | select(.change.after.public_access == true)] | length == 0)
' "$plan" >/dev/null || fail 'enabled plan crosses the private infrastructure boundary'

# A changed chart NAT value must fail the same plan-time precondition that
# accepts the fixture's explicit offline authoritative NAT mock.
negative_module="$temporary_directory/negative-module"
cp -a "$root/infra/terraform" "$negative_module"
negative_fixture="$negative_module/fixtures/offline-argocd-bootstrap.tfvars"
sed -i.bak 's/prysmP2PHostIp  = "198\.51\.100\.42"/prysmP2PHostIp  = "198.51.100.43"/' "$negative_fixture"
rm -f "$negative_fixture.bak"
grep -Fq 'prysmP2PHostIp  = "198.51.100.43"' "$negative_fixture" || fail 'negative fixture did not change the deployment NAT input'
negative_log="$temporary_directory/negative-plan.log"
if "$script_dir/validate-terraform-offline.sh" \
  "$negative_module" "$temporary_directory/negative" \
  fixtures/offline-argocd-bootstrap.tfvars >"$negative_log" 2>&1; then
  fail 'changed deployment NAT input passed the authoritative NAT binding'
fi
if ! grep -Fq 'Argo NAT binding precondition failed.' "$negative_log"; then
  tail -n 40 "$negative_log" >&2
  fail 'changed deployment NAT input did not reach the NAT binding precondition'
fi

# Null is permitted only while the optional bootstrap is disabled. A supplied
# object must still satisfy the complete deployment-profile validation.
invalid_module="$temporary_directory/invalid-values-module"
cp -a "$root/infra/terraform" "$invalid_module"
invalid_fixture="$invalid_module/fixtures/offline-argocd-bootstrap.tfvars"
sed -i.bak 's/dast = { enabled = false }/dast = { enabled = true }/' "$invalid_fixture"
rm -f "$invalid_fixture.bak"
invalid_log="$temporary_directory/invalid-values.log"
if "$script_dir/validate-terraform-offline.sh" \
  "$invalid_module" "$temporary_directory/invalid-values" \
  fixtures/offline-argocd-bootstrap.tfvars >"$invalid_log" 2>&1; then
  fail 'invalid non-null deployment values passed validation'
fi
if ! grep -Fq 'gitops_client_chart_values must be the complete deployment profile' "$invalid_log"; then
  tail -n 40 "$invalid_log" >&2
  fail 'invalid non-null deployment values did not fail their variable validation'
fi

printf 'PASS Argo CD bootstrap enabled offline plan is private-boundary compliant.\n'
