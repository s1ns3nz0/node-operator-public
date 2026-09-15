#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

"$root/scripts/ci/validate-terraform-offline.sh" "$root/infra/terraform" "$tmp" fixtures/offline-vault-bootstrap-revoke.tfvars

if jq -e 'any(.resource_changes[]?; .address == "aws_eks_access_policy_association.vault_bootstrap_cluster_admin[0]")' "$tmp/plan.json" >/dev/null; then
  printf 'revoke configuration retains the Vault bootstrap cluster-admin association\n' >&2
  exit 1
fi

jq -e 'any(.resource_changes[]?; .address == "aws_codebuild_project.vault_bootstrap[0]" and (.change.actions | index("create")))' "$tmp/plan.json" >/dev/null
printf 'PASS Vault revoke configuration retains the private executor but omits cluster-admin.\n'
