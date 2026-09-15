#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
"$root/scripts/ci/validate-terraform-offline.sh" "$root/infra/terraform" "$tmp" fixtures/offline-vault-bootstrap-prepare.tfvars
jq -e 'any(.resource_changes[]?; .address == "aws_codebuild_project.vault_bootstrap[0]") and (any(.resource_changes[]?; .address == "aws_eks_access_policy_association.vault_bootstrap_cluster_admin[0]") | not)' "$tmp/plan.json" >/dev/null
printf 'PASS Vault bootstrap prepare plan contains no cluster-admin association.\n'
