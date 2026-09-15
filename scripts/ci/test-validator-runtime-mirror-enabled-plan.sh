#!/usr/bin/env bash
# Check objective: Reject enabled validator-runtime mirror plans that exceed the approved scope.
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# A bind-mounted Git worktree can point at host-only metadata. This test needs
# the source tree, not Git history, and must also work from a release checkout.
root="$(cd "$script_dir/../.." && pwd -P)"
temporary_directory="$(mktemp -d)"
trap 'rm -rf "$temporary_directory"' EXIT
fail() { printf 'FAIL validator runtime mirror enabled plan: %s\n' "$*" >&2; exit 1; }

"$script_dir/validate-terraform-offline.sh" \
  "$root/infra/terraform" \
  "$temporary_directory" \
  fixtures/offline-validator-runtime-mirror.tfvars

plan="$temporary_directory/plan.json"
jq -e '
  ([.resource_changes[]? | select(.change.actions | index("create")) | select(.type == "aws_ecr_repository")] | length == 2)
  and any(.resource_changes[]?; .address == "aws_iam_role.github_validator_runtime_mirror[0]" and (.change.actions | index("create")))
  and any(.resource_changes[]?; .address == "aws_iam_role_policy.github_validator_runtime_mirror[0]" and (.change.actions | index("create")))
' "$plan" >/dev/null || fail 'enabled plan does not create both runtime repositories and the GitHub OIDC boundary'

jq -e '
  ([.resource_changes[]? | select(.change.actions | index("create")) | .type]
    | any(. == "aws_nat_gateway" or . == "aws_internet_gateway") | not)
  and
  ([.resource_changes[]? | select(.change.actions | index("create")) | select(.change.after.public_access == true)] | length == 0)
' "$plan" >/dev/null || fail 'enabled plan crosses the private infrastructure boundary'

printf '%s\n' 'PASS: validator runtime mirror enabled offline plan is private-boundary compliant.'
