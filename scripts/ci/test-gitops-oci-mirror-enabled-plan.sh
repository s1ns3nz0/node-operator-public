#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$script_dir/lib/common.sh"
root="$(repo_root)"
temporary_directory="$(mktemp -d)"
trap 'rm -rf "$temporary_directory"' EXIT
fail() { printf 'FAIL GitOps OCI mirror enabled plan: %s\n' "$*" >&2; exit 1; }

"$script_dir/validate-terraform-offline.sh" \
  "$root/infra/terraform" \
  "$temporary_directory" \
  fixtures/offline-private-gitops.tfvars

plan="$temporary_directory/plan.json"
jq -e '
  ([.resource_changes[]? | select(.change.actions | index("create")) | select(.type == "aws_ecr_repository")] | length == 6)
  and any(.resource_changes[]?; .address == "aws_iam_role.github_gitops_oci_mirror[0]" and (.change.actions | index("create")))
  and any(.resource_changes[]?; .address == "aws_iam_role_policy.github_gitops_oci_mirror[0]" and (.change.actions | index("create")))
' "$plan" >/dev/null || fail 'enabled plan does not create the complete ECR OCI and GitHub OIDC boundary'

jq -e '
  ([.resource_changes[]? | select(.change.actions | index("create")) | .type]
    | any(. == "aws_nat_gateway" or . == "aws_internet_gateway") | not)
  and
  ([.resource_changes[]? | select(.change.actions | index("create")) | select(.change.after.public_access == true)] | length == 0)
' "$plan" >/dev/null || fail 'enabled plan crosses the private infrastructure boundary'

printf 'PASS GitOps OCI enabled offline plan is private-boundary compliant.\n'
