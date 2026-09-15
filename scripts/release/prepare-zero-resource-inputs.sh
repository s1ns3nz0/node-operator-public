#!/usr/bin/env bash
set -euo pipefail
umask 077

# Creates the three non-secret Terraform input files accepted by `zero apply`.
# This is intentionally a preparation command: it never runs Terraform or
# contacts a cluster, registry, Vault, or custody system.
usage() {
  printf '%s\n' "usage: ${0##*/} --aws-account-id <12-digit-id> --output-dir <new-absolute-dir> [--aws-region <aws-region>] [--audit-replica-region <aws-region>] [--availability-zone <zone> --availability-zone <zone>] [--name <dns-name>] [--backend-principal-arn <same-account-role-arn>] [--manage-config-recorder true|false]" >&2
  exit 64
}

account=''; output_dir=''; name='node-operator'; aws_region='ap-northeast-2'; audit_replica_region=''; github_repository=''; github_owner_id=''; github_repository_id=''; gitops_client_github_repository=''; gitops_client_github_owner_id=''; gitops_client_github_repository_id=''; availability_zones=(); principals=(); manage_config_recorder=true
while [ "$#" -gt 0 ]; do
  case "$1" in
    --aws-account-id) account="${2:-}"; shift 2 ;;
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
    --backend-principal-arn) principals+=("${2:-}"); shift 2 ;;
    --manage-config-recorder) manage_config_recorder="${2:-}"; shift 2 ;;
    *) usage ;;
  esac
done
case "$manage_config_recorder" in true|false) ;; *) usage ;; esac
case "$account" in [0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]) ;; *) usage ;; esac
[[ "$aws_region" =~ ^[a-z]{2}-[a-z0-9-]+-[0-9]+$ ]] || usage
[ -n "$audit_replica_region" ] || { audit_replica_region='ap-northeast-1'; [ "$aws_region" = ap-northeast-1 ] && audit_replica_region='ap-northeast-2'; }
[[ "$audit_replica_region" =~ ^[a-z]{2}-[a-z0-9-]+-[0-9]+$ ]] && [ "$audit_replica_region" != "$aws_region" ] || usage
validate_github_binding() { local repo="$1" owner="$2" repo_id="$3"; [[ "$repo" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ && "$owner" =~ ^[1-9][0-9]*$ && "$repo_id" =~ ^[1-9][0-9]*$ ]] || usage; }
validate_github_binding "$github_repository" "$github_owner_id" "$github_repository_id"
validate_github_binding "$gitops_client_github_repository" "$gitops_client_github_owner_id" "$gitops_client_github_repository_id"
case "$name" in [a-z][a-z0-9-][a-z0-9-]*[a-z0-9]) [ "${#name}" -le 20 ] ;; *) usage ;; esac
case "$output_dir" in /*) ;; *) usage ;; esac
[ ! -e "$output_dir" ] && [ ! -L "$output_dir" ] || { printf '%s\n' 'output directory already exists or is a symlink' >&2; exit 65; }
command -v jq >/dev/null 2>&1 || { printf '%s\n' 'missing command: jq' >&2; exit 69; }
if [ "${#availability_zones[@]}" -eq 0 ]; then
  command -v aws >/dev/null 2>&1 || { printf '%s\n' 'missing command: aws; provide two --availability-zone values' >&2; exit 69; }
  # Capture the request first so AWS failures propagate, then populate the
  # array without mapfile (unavailable in the macOS system Bash 3.2).
  discovered_zones="$(aws ec2 describe-availability-zones --region "$aws_region" --filters Name=state,Values=available --query 'AvailabilityZones[].ZoneName' --output text)" || { printf '%s\n' 'availability-zone discovery failed; no inputs were created' >&2; exit 69; }
  selected_zones="$(printf '%s\n' "$discovered_zones" | tr '\t' '\n' | sort -u | sed -n '1,2p')"
  while IFS= read -r zone; do
    [ -z "$zone" ] || availability_zones+=("$zone")
  done <<<"$selected_zones"
fi
[ "${#availability_zones[@]}" -eq 2 ] && [ "${availability_zones[0]}" != "${availability_zones[1]}" ] || usage
for zone in "${availability_zones[@]}"; do [[ "$zone" == "$aws_region"? ]] || usage; done

role_pattern="^arn:aws:iam::${account}:role/[A-Za-z0-9+=,.@_/-]+$"
if [ "${#principals[@]}" -eq 0 ]; then
  command -v aws >/dev/null 2>&1 || { printf '%s\n' 'missing command: aws; provide --backend-principal-arn explicitly' >&2; exit 69; }
  identity="$(env -u AWS_ACCESS_KEY_ID -u AWS_SECRET_ACCESS_KEY -u AWS_SESSION_TOKEN -u AWS_SECURITY_TOKEN aws sts get-caller-identity --output json)"
  observed_account="$(jq -er '.Account | select(test("^[0-9]{12}$"))' <<<"$identity")" || { printf '%s\n' 'AWS identity response lacks a valid account ID' >&2; exit 65; }
  [ "$observed_account" = "$account" ] || { printf '%s\n' 'declared AWS account does not match the current AWS identity' >&2; exit 65; }
  observed_arn="$(jq -er '.Arn | strings' <<<"$identity")" || { printf '%s\n' 'AWS identity response lacks an ARN' >&2; exit 65; }
  case "$observed_arn" in
    "arn:aws:sts::${account}:assumed-role/"*/*)
      role_path="${observed_arn#arn:aws:sts::"${account}":assumed-role/}"
      principals=("arn:aws:iam::${account}:role/${role_path%/*}")
      ;;
    "arn:aws:iam::${account}:role/"*) principals=("$observed_arn") ;;
    *) printf '%s\n' 'current AWS identity is not an IAM role; provide one exact --backend-principal-arn' >&2; exit 65 ;;
  esac
fi
for principal in "${principals[@]}"; do
  [[ "$principal" =~ $role_pattern ]] || { printf '%s\n' 'backend principal must be an exact same-account IAM role ARN' >&2; exit 65; }
done

mkdir -m 700 "$output_dir"
bootstrap="$output_dir/bootstrap-state.tfvars.json"
foundation="$output_dir/foundation-network.tfvars.json"
baseline="$output_dir/baseline.tfvars.json"
metadata="$output_dir/zero-resource-inputs.json"

jq -n --arg account "$account" --arg name "$name" --arg region "$aws_region" --argjson principals "$(printf '%s\n' "${principals[@]}" | jq -R . | jq -s .)" \
  '{aws_account_id:$account,aws_region:$region,name:$name,state_bucket_name:null,backend_principal_arns:$principals}' > "$bootstrap"
jq -n --arg name "$name" --arg region "$aws_region" --argjson zones "$(printf '%s\n' "${availability_zones[@]}" | jq -R . | jq -s .)" '{aws_region:$region,name:$name,network_mode:"fresh",availability_zones:$zones}' > "$foundation"
jq -n --arg account "$account" --arg name "$name" --arg region "$aws_region" --arg apply_role "${principals[0]}" --arg audit_replica_region "$audit_replica_region" --arg github_repository "$github_repository" --arg github_owner_id "$github_owner_id" --arg github_repository_id "$github_repository_id" --arg gitops_client_github_repository "$gitops_client_github_repository" --arg gitops_client_github_owner_id "$gitops_client_github_owner_id" --arg gitops_client_github_repository_id "$gitops_client_github_repository_id" --argjson zones "$(printf '%s\n' "${availability_zones[@]}" | jq -R . | jq -s .)" --argjson manage_config_recorder "$manage_config_recorder" '
  {aws_account_id:$account,aws_region:$region,terraform_apply_role_arn:$apply_role,audit_replica_region:$audit_replica_region,availability_zones:$zones,name:$name,enable_gitops_client_ecr_publisher:true,enable_validator_runtime_ecr_mirror:true,enable_validator_client_ecr_mirror:true,enable_validator_log_collector_ecr_mirror:true,
   enable_vault_audit_relay_repository:true,
   manage_config_recorder:$manage_config_recorder,
   enable_temporary_ssm_ops_host:false,temporary_ssm_ops_host_termination_at:"",
   enable_argocd_bootstrap_runner:false,enable_argocd_bootstrap_cluster_admin:false,
   enable_vault_bootstrap_runner:false,enable_vault_bootstrap_cluster_admin:false}
  + {github_repository:$github_repository,github_owner_id:$github_owner_id,github_repository_id:$github_repository_id}
  + {gitops_client_github_repository:$gitops_client_github_repository,gitops_client_github_owner_id:$gitops_client_github_owner_id,gitops_client_github_repository_id:$gitops_client_github_repository_id}
' > "$baseline"
jq -n --arg account "$account" --arg name "$name" --arg region "$aws_region" --argjson zones "$(printf '%s\n' "${availability_zones[@]}" | jq -R . | jq -s .)" --arg bootstrap "$bootstrap" --arg foundation "$foundation" --arg baseline "$baseline" \
  '{schema_version:1,aws_account_id:$account,aws_region:$region,availability_zones:$zones,name:$name,bootstrap_config:$bootstrap,foundation_config:$foundation,baseline_config:$baseline}' > "$metadata"
chmod 600 "$bootstrap" "$foundation" "$baseline" "$metadata"
printf 'PASS: zero-resource inputs prepared in %s. Run node-operator-release.sh zero apply with the three generated config files.\n' "$output_dir"
