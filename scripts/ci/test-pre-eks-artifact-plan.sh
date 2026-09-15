#!/usr/bin/env bash
# Check objective: Prove generated baseline inputs support the exact ECR/KMS pre-EKS target plan.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT
fail() { printf 'FAIL pre-EKS artifact plan: %s\n' "$*" >&2; exit 1; }
plan_output=''
if [ "$#" -gt 0 ]; then
  [ "$#" -eq 2 ] && [ "$1" = --plan-output ] || fail 'expected --plan-output ABSOLUTE_PATH'
  plan_output="$2"
  case "$plan_output" in /*) ;; *) fail 'plan output must be absolute' ;; esac
  [ ! -L "$plan_output" ] && [ -d "$(dirname "$plan_output")" ] || fail 'plan output is unsafe'
fi

# Use the release generator, not a hand-written baseline fixture.  Supplying
# AZs and a principal makes this entirely offline.
"$root/scripts/release/prepare-zero-resource-inputs.sh" \
  --aws-account-id 123456789012 --aws-region ap-northeast-2 --name node-operator \
  --availability-zone ap-northeast-2a --availability-zone ap-northeast-2c \
  --backend-principal-arn arn:aws:iam::123456789012:role/offline-preflight \
  --output-dir "$scratch/inputs" >/dev/null
jq -e '.enable_validator_log_collector_ecr_mirror == true' "$scratch/inputs/baseline.tfvars.json" >/dev/null || fail 'generated baseline inputs do not enable collector prerequisite closure'

cp -a "$root/infra/terraform" "$scratch/baseline"
rm -f "$scratch/baseline/backend.tf"
for values in argocd-private-values.example.yaml cert-manager-values.example.yaml vault-tls-internal-ca.example.yaml; do
  cp "$root/docs/gitops/$values" "$scratch/baseline/$values"
done
jq '. + {offline_validation:true,enable_private_gitops_foundation:true,enable_vault_audit_relay_repository:true}' \
  "$scratch/inputs/baseline.tfvars.json" > "$scratch/baseline/pre-eks.tfvars.json"

export AWS_ACCESS_KEY_ID=offline AWS_SECRET_ACCESS_KEY=offline AWS_EC2_METADATA_DISABLED=true
export TF_DATA_DIR="$scratch/tf-data"
terraform -chdir="$scratch/baseline" init -backend=false -input=false -get=false -lockfile=readonly
terraform -chdir="$scratch/baseline" plan -refresh=false -input=false -var-file=pre-eks.tfvars.json \
  -target=aws_ecr_repository.private_gitops \
  -target=aws_ecr_lifecycle_policy.private_gitops \
  -target=aws_ecr_repository.gitops_client \
  -target=aws_ecr_repository.gitops_client_chart \
  -target=aws_ecr_lifecycle_policy.gitops_client \
  -target=aws_ecr_lifecycle_policy.gitops_client_chart \
  -target=aws_kms_key.validator_runtime_ecr \
  -target=aws_ecr_repository.validator_runtime \
  -target=aws_kms_key.validator_client_ecr \
  -target=aws_ecr_repository.validator_client \
  -target=aws_ecr_repository.validator_signing_fence \
  -target=aws_ecr_repository.validator_signer_identity_probe \
  -target=aws_kms_key.validator_log_collector_ecr \
  -target=aws_ecr_repository.validator_log_collector \
  -target=aws_kms_key.vault_audit_relay_ecr \
  -target=aws_ecr_repository.vault_audit_relay \
  -out="$scratch/pre-eks.tfplan" >/dev/null
terraform -chdir="$scratch/baseline" show -json "$scratch/pre-eks.tfplan" > "$scratch/plan.json"

jq -e '
  [
    "data.aws_iam_policy_document.kms_key_administrator",
    "data.aws_iam_policy_document.validator_client_ecr_key[0]",
    "data.aws_iam_policy_document.validator_log_collector_ecr_key[0]",
    "data.aws_iam_policy_document.validator_runtime_ecr_key[0]",
    "data.aws_iam_policy_document.vault_audit_relay_ecr_key[0]",
    "aws_iam_role.kms_administrator",
    "aws_kms_key.validator_runtime_ecr[0]",
    "aws_kms_key.validator_client_ecr[0]",
    "aws_kms_key.validator_log_collector_ecr[0]",
    "aws_kms_key.vault_audit_relay_ecr[0]",
    "aws_ecr_repository.private_gitops[\"argocd\"]",
    "aws_ecr_repository.private_gitops[\"argocd_chart\"]",
    "aws_ecr_repository.private_gitops[\"charts\"]",
    "aws_ecr_repository.private_gitops[\"nodes\"]",
    "aws_ecr_repository.private_gitops[\"vault\"]",
    "aws_ecr_repository.private_gitops[\"cert_manager\"]",
    "aws_ecr_repository.private_gitops[\"vault_chart\"]",
    "aws_ecr_repository.private_gitops[\"cert_manager_chart\"]",
    "aws_ecr_lifecycle_policy.private_gitops[\"argocd\"]",
    "aws_ecr_lifecycle_policy.private_gitops[\"argocd_chart\"]",
    "aws_ecr_lifecycle_policy.private_gitops[\"charts\"]",
    "aws_ecr_lifecycle_policy.private_gitops[\"nodes\"]",
    "aws_ecr_lifecycle_policy.private_gitops[\"vault\"]",
    "aws_ecr_lifecycle_policy.private_gitops[\"cert_manager\"]",
    "aws_ecr_lifecycle_policy.private_gitops[\"vault_chart\"]",
    "aws_ecr_lifecycle_policy.private_gitops[\"cert_manager_chart\"]",
    "aws_ecr_repository.gitops_client[0]",
    "aws_ecr_repository.gitops_client_chart[0]",
    "aws_ecr_lifecycle_policy.gitops_client[0]",
    "aws_ecr_lifecycle_policy.gitops_client_chart[0]",
    "aws_ecr_repository.validator_runtime[\"validator-runtime-web3signer\"]",
    "aws_ecr_repository.validator_runtime[\"validator-runtime-postgres\"]",
    "aws_ecr_repository.validator_client[0]",
    "aws_ecr_repository.validator_signing_fence[0]",
    "aws_ecr_repository.validator_signer_identity_probe[0]",
    "aws_ecr_repository.validator_log_collector[0]",
    "aws_ecr_repository.vault_audit_relay[0]"
  ] as $allowed |
  ([.resource_changes[]? | .address] | unique) as $actual |
  ($actual | length) == ($allowed | length) and
  # The existing slice has 30 managed prerequisites (including ten retained
  # lifecycle policies); the collector KMS key and repository make 32.
  ([.resource_changes[]? | select(.mode == "managed")] | length) == 32 and
  ([.resource_changes[]? | select(.mode == "data")] | length) == 5 and
  all($allowed[]; . as $address | $actual | index($address)) and
  all(.resource_changes[]?;
    if .mode == "data" then (.change.actions == ["read"])
    else (.mode == "managed" and (.change.actions == ["create"]))
    end)
' "$scratch/plan.json" >/dev/null || fail 'pre-EKS target plan has an unexpected resource, action, or omitted prerequisite'

if [ -n "$plan_output" ]; then
  cp "$scratch/plan.json" "$plan_output"
  chmod 600 "$plan_output"
  printf 'Pre-EKS plan exported; caller must run the artifact prerequisite validator.\n'
else
  python3 "$root/scripts/release/installer_artifact_prerequisites.py" plan \
    --plan "$scratch/plan.json" --account 123456789012 --region ap-northeast-2 --name node-operator
fi

printf 'PASS pre-EKS ECR target plan uses generated baseline inputs and creates no VPC/EKS resources.\n'
