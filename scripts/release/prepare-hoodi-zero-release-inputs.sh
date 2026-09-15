#!/usr/bin/env bash
set -euo pipefail
umask 077

# Produces the complete non-secret input set for a new Hoodi validator release.
# Terraform, GitOps publication, Vault recovery, custody, and activation remain
# independently authorized operations; this command only removes duplicated
# operator input while preserving those boundaries.
usage() {
  printf '%s\n' "usage: ${0##*/} --aws-account-id <12-digit-id> --validator-set <hoodi-id> --validator-public-key <0x-key> --withdrawal-address <0x-address> --web3signer-image <private-ecr@sha256> --postgres-image <private-ecr@sha256> --prysm-validator-image <private-ecr@sha256> --signing-fence-image <private-ecr@sha256> --kubernetes-api-cidr <ipv4/32> --output-dir <new-absolute-dir> [--aws-region <ap-northeast-1|ap-northeast-2>] [--audit-replica-region <aws-region>] [--availability-zone <zone> --availability-zone <zone>] [--name <dns-name>] [--backend-principal-arn <same-account-role-arn>] [--manage-config-recorder true|false]" >&2
  exit 64
}

account=''; validator_set=''; validator_public_key=''; withdrawal_address=''; ci_evidence_archive_retention_mode=COMPLIANCE
release_identity=''
web3signer_image=''; postgres_image=''; prysm_image=''; fence_image=''; kubernetes_api_cidr=''; output_dir=''; name='node-operator'; aws_region='ap-northeast-2'; audit_replica_region=''; github_repository=''; github_owner_id=''; github_repository_id=''; gitops_client_github_repository=''; gitops_client_github_owner_id=''; gitops_client_github_repository_id=''; availability_zones=(); principals=(); manage_config_recorder=true
while [ "$#" -gt 0 ]; do
  case "$1" in
    --aws-account-id) account="${2:-}"; shift 2 ;;
    --validator-set) validator_set="${2:-}"; shift 2 ;;
    --validator-public-key) validator_public_key="${2:-}"; shift 2 ;;
    --withdrawal-address) withdrawal_address="${2:-}"; shift 2 ;;
    --web3signer-image) web3signer_image="${2:-}"; shift 2 ;;
    --postgres-image) postgres_image="${2:-}"; shift 2 ;;
    --prysm-validator-image) prysm_image="${2:-}"; shift 2 ;;
    --signing-fence-image) fence_image="${2:-}"; shift 2 ;;
    --kubernetes-api-cidr) kubernetes_api_cidr="${2:-}"; shift 2 ;;
    --output-dir) output_dir="${2:-}"; shift 2 ;;
    --aws-region) aws_region="${2:-}"; shift 2 ;;
    --audit-replica-region) audit_replica_region="${2:-}"; shift 2 ;;
    --github-repository) github_repository="${2:-}"; shift 2 ;;
    --github-owner-id) github_owner_id="${2:-}"; shift 2 ;;
    --github-repository-id) github_repository_id="${2:-}"; shift 2 ;;
    --gitops-client-github-repository) gitops_client_github_repository="${2:-}"; shift 2 ;;
    --gitops-client-github-owner-id) gitops_client_github_owner_id="${2:-}"; shift 2 ;;
    --gitops-client-github-repository-id) gitops_client_github_repository_id="${2:-}"; shift 2 ;;
    --availability-zone) availability_zones+=("${2:-}"); shift 2 ;;
    --name) name="${2:-}"; shift 2 ;;
    --release-revision) release_identity="${2:-}"; shift 2 ;;
    --backend-principal-arn) principals+=("${2:-}"); shift 2 ;;
    --manage-config-recorder) manage_config_recorder="${2:-}"; shift 2 ;;
    --ci-evidence-archive-retention-mode) ci_evidence_archive_retention_mode="${2:-}"; shift 2 ;;
    *) usage ;;
  esac
done

case "$account" in [0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]) ;; *) usage ;; esac
case "$ci_evidence_archive_retention_mode" in COMPLIANCE|GOVERNANCE) ;; *) usage ;; esac
case "$validator_set" in hoodi-[a-z0-9][a-z0-9-]*) ;; *) usage ;; esac
case "$output_dir" in /*) ;; *) usage ;; esac
set --
if [ -n "$release_identity" ]; then
  [[ "$release_identity" =~ ^[0-9a-f]{40}$ ]] || usage
  set -- --deployment-name "$name" --release-revision "$release_identity"
fi
[ ! -e "$output_dir" ] && [ ! -L "$output_dir" ] || { printf '%s\n' 'output directory already exists or is a symlink' >&2; exit 65; }
for command in jq python3 mkdir chmod rm mv; do command -v "$command" >/dev/null 2>&1 || { printf 'missing command: %s\n' "$command" >&2; exit 69; }; done

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
zero_dir="$output_dir/zero-resource"
validator_dir="$output_dir/validator-deployment"
manifest="$output_dir/hoodi-zero-release-inputs.json"
cleanup() { set +e; [ "${completed:-0}" = 1 ] || rm -rf -- "$output_dir"; }
completed=0
trap cleanup EXIT INT TERM

mkdir -m 700 "$output_dir"
zero_args=(--aws-account-id "$account" --aws-region "$aws_region" --name "$name" --output-dir "$zero_dir")
[ -z "$audit_replica_region" ] || zero_args+=(--audit-replica-region "$audit_replica_region")
for pair in "--github-repository:$github_repository" "--github-owner-id:$github_owner_id" "--github-repository-id:$github_repository_id" "--gitops-client-github-repository:$gitops_client_github_repository" "--gitops-client-github-owner-id:$gitops_client_github_owner_id" "--gitops-client-github-repository-id:$gitops_client_github_repository_id"; do key="${pair%%:*}"; value="${pair#*:}"; [ -z "$value" ] || zero_args+=("$key" "$value"); done
zero_args+=(--manage-config-recorder "$manage_config_recorder")
zero_args+=(--ci-evidence-archive-retention-mode "$ci_evidence_archive_retention_mode")
for zone in "${availability_zones[@]-}"; do
  [ -n "$zone" ] && zero_args+=(--availability-zone "$zone")
done
for principal in "${principals[@]-}"; do
  [ -n "$principal" ] && zero_args+=(--backend-principal-arn "$principal")
done
"$script_dir/prepare-zero-resource-inputs.sh" "${zero_args[@]}"
"$script_dir/prepare-hoodi-validator-deployment.sh" \
  --validator-set "$validator_set" \
  --validator-public-key "$validator_public_key" \
  --withdrawal-address "$withdrawal_address" \
  --aws-account-id "$account" \
  --aws-region "$aws_region" \
  --web3signer-image "$web3signer_image" \
  --postgres-image "$postgres_image" \
  --prysm-validator-image "$prysm_image" \
  --signing-fence-image "$fence_image" \
  --kubernetes-api-cidr "$kubernetes_api_cidr" \
  --output-dir "$validator_dir" "$@"

# Bind the real dashboard body into the baseline Terraform input. This creates
# no resources and does not assert that metrics ingestion has been deployed.
python3 -I -B "$script_dir/validator_monitoring_dashboard.py" \
  --deployment "$name" --region "$aws_region" \
  --validator-set "$validator_set" --public-key "$validator_public_key" \
  > "$zero_dir/validator-dashboard.json"
jq --rawfile dashboard "$zero_dir/validator-dashboard.json" \
  '.validator_monitoring_dashboard_body = $dashboard' \
  "$zero_dir/baseline.tfvars.json" > "$zero_dir/baseline.tfvars.json.tmp"
mv "$zero_dir/baseline.tfvars.json.tmp" "$zero_dir/baseline.tfvars.json"

jq -n \
  --arg account "$account" \
  --arg region "$aws_region" \
  --arg validator_set "$validator_set" \
  --arg zero_inputs "$zero_dir/zero-resource-inputs.json" \
  --arg validator_handoff "$validator_dir/validator-deployment-handoff.json" \
  '{schema_version:1,network:"hoodi",aws_account_id:$account,aws_region:$region,validator_set:$validator_set,zero_resource_inputs:$zero_inputs,validator_deployment_handoff:$validator_handoff,required_checkpoints:["verified release bundle","zero-resource infrastructure apply","immutable GitOps artifact publication and Argo bootstrap","isolated SSM ops-access saved plan and apply","interactive Vault recovery and custody onboarding","public deposit and activation evidence"]}' > "$manifest"
chmod 600 "$manifest"
completed=1
printf 'PASS: complete non-secret Hoodi zero-release inputs prepared in %s. Use zero-resource/ for infrastructure and validator-deployment/ only after private EKS access is created.\n' "$output_dir"
