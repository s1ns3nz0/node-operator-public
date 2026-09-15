#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$script_dir/lib/common.sh"
root="$(repo_root)"
temporary_directory="$(mktemp -d)"
trap 'rm -rf "$temporary_directory"' EXIT
fail() { printf 'FAIL CodeBuild signer enabled plan: %s\n' "$*" >&2; exit 1; }

"$script_dir/validate-terraform-offline.sh" \
  "$root/infra/terraform" \
  "$temporary_directory" \
  fixtures/offline-release-signer.tfvars

plan="$temporary_directory/plan.json"
jq -e '
  any(.resource_changes[]?; .address == "aws_codebuild_project.release_signer[0]" and (.change.actions | index("create")))
' "$plan" >/dev/null || fail 'enabled plan does not create the release signer CodeBuild project'

jq -e '
  ([.resource_changes[]? | select(.change.actions | index("create")) | .type]
    | any(. == "aws_nat_gateway" or . == "aws_internet_gateway") | not)
  and
  ([.resource_changes[]? | select(.change.actions | index("create")) | select(.change.after.public_access == true)] | length == 0)
' "$plan" >/dev/null || fail 'enabled plan crosses the private infrastructure boundary'

printf 'PASS CodeBuild signer enabled offline plan is private-boundary compliant.\n'
