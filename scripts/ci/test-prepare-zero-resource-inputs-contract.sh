#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
script="$root/scripts/release/prepare-zero-resource-inputs.sh"
scratch="$(mktemp -d /private/tmp/node-operator-zero-inputs.XXXXXX)"
output="$scratch/inputs"

"$script" --aws-account-id 123456789012 --availability-zone ap-northeast-2a --availability-zone ap-northeast-2c --name hoodi-operator --backend-principal-arn arn:aws:iam::123456789012:role/NodeOperatorTerraformApply --github-repository example/operator --github-owner-id 101 --github-repository-id 102 --gitops-client-github-repository example/gitops --gitops-client-github-owner-id 103 --gitops-client-github-repository-id 104 --ci-evidence-archive-retention-mode GOVERNANCE --output-dir "$output" >/dev/null
for file in bootstrap-state.tfvars.json foundation-network.tfvars.json baseline.tfvars.json zero-resource-inputs.json; do
  [ -f "$output/$file" ] || { printf 'missing generated input: %s\n' "$file" >&2; exit 1; }
  [ "$(stat -f '%Lp' "$output/$file")" = 600 ] || { printf 'generated input has unsafe mode: %s\n' "$file" >&2; exit 1; }
done
[ "$(stat -f '%Lp' "$output")" = 700 ]
jq -e '.aws_account_id == "123456789012" and .aws_region == "ap-northeast-2" and .availability_zones == ["ap-northeast-2a", "ap-northeast-2c"] and .name == "hoodi-operator" and (.bootstrap_config | endswith("/bootstrap-state.tfvars.json"))' "$output/zero-resource-inputs.json" >/dev/null
jq -e '.aws_region == "ap-northeast-2" and .backend_principal_arns == ["arn:aws:iam::123456789012:role/NodeOperatorTerraformApply"] and .state_bucket_name == null' "$output/bootstrap-state.tfvars.json" >/dev/null
jq -e '.network_mode == "fresh" and .aws_region == "ap-northeast-2"' "$output/foundation-network.tfvars.json" >/dev/null
jq -e '.enable_gitops_client_ecr_publisher == true and .ci_evidence_archive_retention_mode == "GOVERNANCE" and .enable_temporary_ssm_ops_host == false and .enable_argocd_bootstrap_runner == false and .enable_vault_bootstrap_runner == false' "$output/baseline.tfvars.json" >/dev/null
"$script" --aws-account-id 123456789012 --aws-region ap-northeast-1 --availability-zone ap-northeast-1a --availability-zone ap-northeast-1c --name hoodi-tokyo --backend-principal-arn arn:aws:iam::123456789012:role/NodeOperatorTerraformApply --github-repository example/operator --github-owner-id 101 --github-repository-id 102 --gitops-client-github-repository example/gitops --gitops-client-github-owner-id 103 --gitops-client-github-repository-id 104 --output-dir "$scratch/tokyo" >/dev/null
jq -e '.aws_region == "ap-northeast-1" and .availability_zones == ["ap-northeast-1a", "ap-northeast-1c"]' "$scratch/tokyo/zero-resource-inputs.json" >/dev/null
jq -e '.aws_region == "ap-northeast-1" and .audit_replica_region == "ap-northeast-2" and .availability_zones == ["ap-northeast-1a", "ap-northeast-1c"]' "$scratch/tokyo/baseline.tfvars.json" >/dev/null
if "$script" --aws-account-id 123456789012 --backend-principal-arn arn:aws:iam::999999999999:role/WrongAccount --output-dir "$scratch/wrong" >/dev/null 2>&1; then
  printf '%s\n' 'cross-account backend principal unexpectedly accepted' >&2
  exit 1
fi
if "$script" --aws-account-id 123456789012 --name node-operator-tokyo-smoke --backend-principal-arn arn:aws:iam::123456789012:role/NodeOperatorTerraformApply --output-dir "$scratch/too-long" >/dev/null 2>&1; then
  printf '%s\n' 'name that would overflow derived IAM and S3 resource names unexpectedly accepted' >&2
  exit 1
fi
if "$script" --aws-account-id 123456789012 --availability-zone ap-northeast-2a --availability-zone ap-northeast-2c --name hoodi-invalid --backend-principal-arn arn:aws:iam::123456789012:role/NodeOperatorTerraformApply --github-repository example/operator --github-owner-id 101 --github-repository-id 102 --gitops-client-github-repository example/gitops --gitops-client-github-owner-id 103 --gitops-client-github-repository-id 104 --ci-evidence-archive-retention-mode BYPASS --output-dir "$scratch/invalid-mode" >/dev/null 2>&1; then
  printf '%s\n' 'invalid CI evidence retention mode unexpectedly accepted' >&2
  exit 1
fi
printf '%s\n' 'PASS: zero-resource input preparation emits one bounded non-secret configuration set.'
