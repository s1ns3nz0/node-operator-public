#!/usr/bin/env bash
# shellcheck disable=SC2016 # Literal Terraform fragments intentionally contain $ expressions.
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$script_dir/lib/common.sh"
root="$(repo_root)"
terraform_file="$root/infra/terraform/vault-bootstrap.tf"
fixture="$root/infra/terraform/fixtures/offline-vault-bootstrap.tfvars"
phases="$root/docs/gitops/vault-bootstrap-phases.md"

fail() { printf 'FAIL Vault chart manifest binding: %s\n' "$*" >&2; exit 1; }

for required in \
  'variable "vault_chart_manifest_digest"' \
  '^sha256:[a-f0-9]{64}$' \
  'VAULT_CHART_MANIFEST_DIGEST' \
  'ecr:DescribeImages' \
  'aws_ecr_repository.private_gitops["vault_chart"].arn' \
  'aws ecr describe-images' \
  'oci://${aws_ecr_repository.private_gitops["vault_chart"].repository_url}@${var.vault_chart_manifest_digest}' \
  'pinned toolchain and chart manifest digests'; do
  grep -Fq "$required" "$terraform_file" || fail "missing fail-closed binding: $required"
done

grep -Eq '^vault_chart_manifest_digest[[:space:]]*=[[:space:]]*"sha256:[a-f0-9]{64}"$' "$fixture" || fail 'enabled fixture lacks a chart manifest digest'
grep -Fq 'reviewed OCI manifest digest' "$phases" || fail 'deployment phases omit the chart manifest gate'

if grep -Fq 'oci://${aws_ecr_repository.private_gitops["vault_chart"].repository_url} --version ${var.vault_chart_version}' "$terraform_file"; then
  fail 'Helm chart may not be selected by mutable version tag alone'
fi

printf 'PASS Vault bootstrap binds Helm to the approved ECR OCI manifest digest.\n'
