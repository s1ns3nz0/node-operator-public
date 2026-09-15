#!/usr/bin/env bash
set -euo pipefail
umask 077

usage() {
  printf '%s\n' "usage: ${0##*/} --baseline-work-dir ABSOLUTE_DIR --baseline-config ABSOLUTE_FILE --account ACCOUNT --region REGION --argocd-image IMAGE@DIGEST --vault-image IMAGE@DIGEST --client-chart-version 0.1.N --client-chart-digest sha256:DIGEST --vault-chart-version VERSION --vault-chart-digest sha256:DIGEST --cert-manager-chart-digest sha256:DIGEST --vault-approved-catalog ABSOLUTE_FILE --vault-artifact-index ABSOLUTE_FILE --vault-mirror-receipt ABSOLUTE_FILE --private-eks-session-handoff ABSOLUTE_FILE --subnet-id subnet-ID [--subnet-id subnet-ID]"
  exit 64
}

original_args=("$@")
work_dir=''; baseline_config=''; account=''; region=''; argocd_image=''; vault_image=''; client_version=''; client_digest=''; vault_version=''; vault_digest=''; cert_manager_digest=''; vault_catalog=''; vault_index=''; vault_receipt=''; private_eks_session=''; client_values=''; subnets=()
while [ "$#" -gt 0 ]; do
  case "$1" in
    --baseline-work-dir) work_dir="${2:-}"; shift 2 ;;
    --baseline-config) baseline_config="${2:-}"; shift 2 ;;
    --account) account="${2:-}"; shift 2 ;;
    --region) region="${2:-}"; shift 2 ;;
    --argocd-image) argocd_image="${2:-}"; shift 2 ;;
    --vault-image) vault_image="${2:-}"; shift 2 ;;
    --client-chart-version) client_version="${2:-}"; shift 2 ;;
    --client-chart-digest) client_digest="${2:-}"; shift 2 ;;
    --vault-chart-version) vault_version="${2:-}"; shift 2 ;;
    --vault-chart-digest) vault_digest="${2:-}"; shift 2 ;;
    --cert-manager-chart-digest) cert_manager_digest="${2:-}"; shift 2 ;;
    --vault-approved-catalog) vault_catalog="${2:-}"; shift 2 ;;
    --vault-artifact-index) vault_index="${2:-}"; shift 2 ;;
    --vault-mirror-receipt) vault_receipt="${2:-}"; shift 2 ;;
    --private-eks-session-handoff) private_eks_session="${2:-}"; shift 2 ;;
    --client-values) client_values="${2:-}"; shift 2 ;;
    --subnet-id) subnets+=("${2:-}"); shift 2 ;;
    *) usage ;;
  esac
done
case "$work_dir:$baseline_config:$account:$region:$argocd_image:$vault_image:$client_version:$client_digest:$vault_version:$vault_digest:$cert_manager_digest:$vault_catalog:$vault_index:$vault_receipt:$private_eks_session" in /*:/*:*:*:*:*:*:*:*:*:*:/*:/*:/*:/*) ;; *) usage ;; esac
[[ "$account" =~ ^[0-9]{12}$ ]] || usage
[[ "$region" =~ ^[a-z]{2}-[a-z0-9-]+-[0-9]+$ ]] || usage
[[ "$argocd_image" =~ ^${account}\.dkr\.ecr\.${region}\.amazonaws\.com/.+@sha256:[a-f0-9]{64}$ ]] || usage
[[ "$vault_image" =~ ^${account}\.dkr\.ecr\.${region}\.amazonaws\.com/.+@sha256:[a-f0-9]{64}$ ]] || usage
[[ "$client_version" =~ ^0\.1\.[0-9]+$ && "$client_digest" =~ ^sha256:[a-f0-9]{64}$ ]] || usage
[[ "$vault_version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ && "$vault_digest" =~ ^sha256:[a-f0-9]{64}$ ]] || usage
[[ "$cert_manager_digest" =~ ^sha256:[a-f0-9]{64}$ ]] || usage
[ "${#subnets[@]}" -gt 0 ] || usage
for subnet in "${subnets[@]}"; do [[ "$subnet" =~ ^subnet-[a-z0-9]+$ ]] || usage; done
for command in terraform jq aws python3 shasum base64; do command -v "$command" >/dev/null 2>&1 || { printf 'missing command: %s\n' "$command" >&2; exit 69; }; done
platform_stage_number=0
platform_stage() {
  platform_stage_number=$((platform_stage_number + 1))
  printf '\n▶ PLATFORM %02d/09  %s\n' "$platform_stage_number" "$1" >&2
}
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
replay="$script_dir/platform_bootstrap_replay.py"
[ -x "$replay" ] || { printf '%s\n' 'release bundle lacks the platform replay helper' >&2; exit 65; }
if [ "${PLATFORM_REPLAY_LOCKED:-}" != 1 ]; then
  exec "$replay" lock --work-dir "$work_dir" -- env PLATFORM_REPLAY_LOCKED=1 "$0" "${original_args[@]}"
fi
"$replay" assert-lock --work-dir "$work_dir" --fd "${PLATFORM_REPLAY_LOCK_FD:-}" || { printf '%s\n' 'platform replay lock was not inherited safely' >&2; exit 65; }
[ -d "$work_dir/baseline" ] && [ -f "$work_dir/baseline.backend.hcl" ] || { printf '%s\n' 'baseline work directory is not a zero-apply result' >&2; exit 65; }
[ -f "$baseline_config" ] && [ ! -L "$baseline_config" ] || { printf '%s\n' 'baseline config must be a regular file' >&2; exit 65; }
[ -f "$vault_catalog" ] && [ ! -L "$vault_catalog" ] || { printf '%s\n' 'Vault approved catalog must be a regular selected-release file' >&2; exit 65; }
[ -f "$vault_index" ] && [ ! -L "$vault_index" ] || { printf '%s\n' 'Vault artifact index must be a regular selected-release file' >&2; exit 65; }
[ -f "$vault_receipt" ] && [ ! -L "$vault_receipt" ] || { printf '%s\n' 'Vault mirror receipt must be a regular verified deployment file' >&2; exit 65; }
[ -f "$client_values" ] && [ ! -L "$client_values" ] || { printf '%s\n' 'deployment-bound client values must be a regular verified file' >&2; exit 65; }
deployment_name="$(jq -er '.name | select(type == "string" and test("^[a-z][a-z0-9-]{1,18}[a-z0-9]$"))' "$baseline_config")" || { printf '%s\n' 'baseline config lacks a safe deployment name' >&2; exit 65; }
session_verifier="$script_dir/verify-platform-private-eks-session.py"
[ -f "$session_verifier" ] && [ ! -L "$session_verifier" ] || { printf '%s\n' 'release bundle lacks the private EKS session verifier' >&2; exit 65; }
aws_profile="${AWS_PROFILE:-default}"
session_target="$(python3 "$session_verifier" --work-dir "$work_dir" --baseline-config "$baseline_config" --session "$private_eks_session" --account "$account" --region "$region" --profile "$aws_profile")" || { printf '%s\n' 'private EKS session verification failed before platform mutation' >&2; exit 65; }
IFS=$'\t' read -r session_cluster session_instance <<<"$session_target"
[ "$session_cluster" = "$deployment_name" ] && [[ "$session_instance" =~ ^i-[0-9a-f]+$ ]] || { printf '%s\n' 'private EKS session verifier returned an invalid target' >&2; exit 65; }

# The legacy ceremony has no digest fallback. Bind every Vault runtime image to
# the selected release index and the deployment-specific mirror receipt before
# producing even an Argo plan. The canonical renderer then derives the only
# Helm image overlay accepted by the Terraform precondition.
index_sha="$(shasum -a 256 "$vault_index" | awk '{print $1}')"
jq -e '
  type == "object" and .version == 1 and
  (.artifacts | type == "array") and
  ([.artifacts[] | select(type == "object") | .source] | length) == (.artifacts | length)
' "$vault_catalog" >/dev/null || { printf '%s\n' 'Vault approved catalog is malformed' >&2; exit 65; }
jq -e '
  type == "object" and .schema_version == 1 and
  (.release_revision | type == "string" and test("^[0-9a-f]{40}$")) and
  (.components | type == "object") and
  ((.components | keys | sort) == ["cert-manager-cainjector","cert-manager-chart","cert-manager-controller","cert-manager-startupapicheck","cert-manager-webhook","gitops-oci-mirror","vault-audit-relay","vault-bootstrap","vault-chart","vault-injector","vault-server"]) and
  (.components["vault-audit-relay"].verification == {method:"cosign-and-slsa",status:"passed"})
' "$vault_index" >/dev/null || { printf '%s\n' 'Vault artifact index is malformed or lacks approved audit relay publication' >&2; exit 65; }
jq -e --arg account "$account" --arg region "$region" --arg deployment "$deployment_name" --arg index_sha "$index_sha" '
  type == "object" and .schema_version == 1 and .status == "verified" and
  .aws_account_id == $account and .aws_region == $region and .deployment_name == $deployment and
  (.release_revision | type == "string" and test("^[0-9a-f]{40}$")) and
  .index_sha256 == $index_sha and (.artifacts | type == "object") and
  ((.artifacts | keys | sort) == ["cert-manager-cainjector","cert-manager-chart","cert-manager-controller","cert-manager-startupapicheck","cert-manager-webhook","vault-audit-relay","vault-bootstrap","vault-chart","vault-injector","vault-server"])
' "$vault_receipt" >/dev/null || { printf '%s\n' 'Vault mirror receipt is malformed or not bound to this deployment and selected index' >&2; exit 65; }
index_revision="$(jq -er '.release_revision' "$vault_index")"
[ "$(jq -er '.release_revision' "$vault_receipt")" = "$index_revision" ] || { printf '%s\n' 'Vault mirror receipt release revision differs from selected index' >&2; exit 65; }

# `output -raw` cannot represent the repository map. Query JSON and retain
# only the exact private Vault repository created by the baseline.
vault_repository="$(terraform -chdir="$work_dir/baseline" output -json private_gitops_ecr_repository_urls 2>/dev/null | jq -er '.vault | select(type == "string")' 2>/dev/null || true)"
relay_repository="$(terraform -chdir="$work_dir/baseline" output -raw vault_audit_relay_ecr_repository_url 2>/dev/null || true)"
case "$vault_repository" in "${account}.dkr.ecr.${region}.amazonaws.com/"*) ;; *) printf '%s\n' 'baseline did not expose the selected private Vault repository' >&2; exit 65 ;; esac
case "$relay_repository" in "${account}.dkr.ecr.${region}.amazonaws.com/"*) ;; *) printf '%s\n' 'baseline did not expose the selected private audit relay repository' >&2; exit 65 ;; esac
runtime_image() {
  local component="$1" repository="$2" digest image receipt_digest index_digest
  image="$(jq -er --arg component "$component" '.artifacts[$component].image_ref | select(type == "string")' "$vault_receipt")" || return 1
  receipt_digest="$(jq -er --arg component "$component" '.artifacts[$component].manifest_digest | select(type == "string" and test("^sha256:[a-f0-9]{64}$"))' "$vault_receipt")" || return 1
  index_digest="$(jq -er --arg component "$component" '.components[$component].manifest_digest | select(type == "string" and test("^sha256:[a-f0-9]{64}$"))' "$vault_index")" || return 1
  digest="${image##*@}"
  [ "$receipt_digest" = "$index_digest" ] && [ "$digest" = "$index_digest" ] && [ "$image" = "$repository@$index_digest" ] || return 1
  printf '%s' "$image"
}
vault_server_image="$(runtime_image vault-server "$vault_repository")" || { printf '%s\n' 'Vault server mirror authority is invalid' >&2; exit 65; }
vault_injector_image="$(runtime_image vault-injector "$vault_repository")" || { printf '%s\n' 'Vault injector mirror authority is invalid' >&2; exit 65; }
vault_relay_image="$(runtime_image vault-audit-relay "$relay_repository")" || { printf '%s\n' 'Vault audit relay mirror authority is invalid' >&2; exit 65; }
vault_toolchain_image="$(runtime_image vault-bootstrap "$vault_repository")" || { printf '%s\n' 'Vault bootstrap toolchain mirror authority is invalid' >&2; exit 65; }
[ "$vault_image" = "$vault_toolchain_image" ] || { printf '%s\n' 'Vault bootstrap image does not match release-bound mirror authority' >&2; exit 65; }
receipt_chart_digest="$(jq -er '.artifacts["vault-chart"].manifest_digest | select(type == "string" and test("^sha256:[a-f0-9]{64}$"))' "$vault_receipt")" || { printf '%s\n' 'Vault chart mirror authority is invalid' >&2; exit 65; }
receipt_chart_version="$(jq -er '.artifacts["vault-chart"].version | select(type == "string" and test("^[0-9]+\\.[0-9]+\\.[0-9]+$"))' "$vault_receipt")" || { printf '%s\n' 'Vault chart mirror authority is invalid' >&2; exit 65; }
index_chart_digest="$(jq -er '.components["vault-chart"].expected_oci_manifest_digest | select(type == "string" and test("^sha256:[a-f0-9]{64}$"))' "$vault_index")" || { printf '%s\n' 'Vault chart publication authority is invalid' >&2; exit 65; }
index_chart_version="$(jq -er '.components["vault-chart"].version | select(type == "string" and test("^[0-9]+\\.[0-9]+\\.[0-9]+$"))' "$vault_index")" || { printf '%s\n' 'Vault chart publication authority is invalid' >&2; exit 65; }
[ "$receipt_chart_digest" = "$index_chart_digest" ] && [ "$vault_digest" = "$index_chart_digest" ] && [ "$receipt_chart_version" = "$index_chart_version" ] && [ "$vault_version" = "$index_chart_version" ] || { printf '%s\n' 'Vault chart input does not match release-bound mirror authority' >&2; exit 65; }

input_dir="$work_dir/platform-bootstrap-inputs"; "$replay" directory --path "$input_dir"
argocd_input="$input_dir/argocd.tfvars.json"; vault_input="$input_dir/vault.tfvars.json"
vault_overlay="$input_dir/vault-image-overrides.json"
renderer="$script_dir/render-private-vault-values.py"
[ -x "$renderer" ] || { printf '%s\n' 'release bundle lacks canonical Vault image authority renderer' >&2; exit 65; }
python3 "$renderer" --approved-catalog "$vault_catalog" --account "$account" --region "$region" --vault-repository "$vault_repository" --server-image "$vault_server_image" --agent-image "$vault_server_image" --injector-image "$vault_injector_image" --output "$vault_overlay" --reuse-identical || { printf '%s\n' 'Vault image authority renderer rejected selected release inputs' >&2; exit 65; }
vault_overlay_b64="$(base64 < "$vault_overlay" | tr -d '\n')"
vault_catalog_b64="$(base64 < "$vault_catalog" | tr -d '\n')"
subnet_json="$(printf '%s\n' "${subnets[@]}" | jq -R . | jq -s .)"
jq -n --arg image "$argocd_image" --arg version "$client_version" --arg digest "$client_digest" --arg cert_digest "$cert_manager_digest" --argjson values "$(cat "$client_values")" --argjson subnets "$subnet_json" \
  '{enable_argocd_bootstrap_runner:true,enable_argocd_bootstrap_cluster_admin:true,argocd_bootstrap_image:$image,argocd_bootstrap_subnet_ids:$subnets,gitops_client_chart_version:$version,gitops_client_chart_oci_digest:$digest,gitops_client_chart_values:$values,cert_manager_chart_manifest_digest:$cert_digest}' | "$replay" materialize --output "$argocd_input"
jq -n --arg image "$vault_image" --arg version "$vault_version" --arg digest "$vault_digest" --arg server "$vault_server_image" --arg injector "$vault_injector_image" --arg relay "$vault_relay_image" --arg overlay "$vault_overlay_b64" --arg catalog "$vault_catalog_b64" --argjson subnets "$subnet_json" \
  '{enable_vault_bootstrap_runner:true,enable_vault_bootstrap_cluster_admin:true,vault_bootstrap_image:$image,vault_bootstrap_subnet_ids:$subnets,vault_chart_version:$version,vault_chart_manifest_digest:$digest,vault_runtime_images:{server:$server,agent:$server,injector:$injector,audit_relay:$relay},vault_image_values_overlay_base64:$overlay,vault_approved_catalog_base64:$catalog}' | "$replay" materialize --output "$vault_input"
"$replay" initialize --work-dir "$work_dir" --account "$account" --region "$region" --deployment "$deployment_name" --baseline-config "$baseline_config" --session "$private_eks_session" --argocd-input "$argocd_input" --vault-input "$vault_input" --vault-overlay "$vault_overlay"
phase() { "$replay" phase --work-dir "$work_dir" --phase "$1" --action "$2"; }
phase_status=''
read_phase() { phase_status="$(phase "$1" get)" || { printf '%s\n' 'platform replay phase lookup failed' >&2; exit 65; }; }
read_phase revoke_complete
if [ "$phase_status" = complete ]; then
  printf '%s\n' 'COMPLETED: platform bootstrap replay checkpoint is complete; no platform mutation was rerun.'
  exit 0
fi

platform_dir="$work_dir/platform-bootstrap-plans"; "$replay" directory --path "$platform_dir"
argocd_plan="$platform_dir/argocd.tfplan"; vault_plan="$platform_dir/vault.tfplan"
read_phase argocd_apply
if [ "$phase_status" != complete ]; then
  platform_stage 'Planning Argo CD bootstrap runner'
  "$replay" discard --path "$argocd_plan"
  "$script_dir/apply-argocd-bootstrap.sh" plan --baseline-work-dir "$work_dir" --baseline-config "$baseline_config" --bootstrap-input "$argocd_input" --plan-file "$argocd_plan"
fi
platform_stage 'Awaiting explicit Argo/Vault bootstrap approval'
if [ "${NODE_OPERATOR_AUTOMATED_CEREMONY:-0}" = 1 ]; then
  confirmation=PLATFORM-BOOTSTRAP
  printf '%s\n' 'Automated disposable-run ceremony enabled; reviewed Argo/Vault plans will be applied.' >&2
else
  printf 'Type PLATFORM-BOOTSTRAP to apply the reviewed Argo/Vault runner plans: ' >&2
  IFS= read -r confirmation
fi
[ "$confirmation" = PLATFORM-BOOTSTRAP ] || { printf '%s\n' 'platform bootstrap cancelled' >&2; exit 130; }
read_phase argocd_apply
if [ "$phase_status" != complete ]; then
  platform_stage 'Applying Argo CD bootstrap runner'
  phase argocd_apply intent
  "$script_dir/apply-argocd-bootstrap.sh" apply --baseline-work-dir "$work_dir" --baseline-config "$baseline_config" --bootstrap-input "$argocd_input" --plan-file "$argocd_plan"
  phase argocd_apply complete
fi

run_bootstrap_project() {
  local phase="$1" project="$2"
  [ -n "$project" ] || { printf '%s\n' 'bootstrap project name is unavailable' >&2; exit 65; }
  python3 "$script_dir/platform_bootstrap_build.py" --work-dir "$work_dir" --phase "$phase" --account "$account" --region "$region" --project "$project" --profile "$aws_profile"
}

read_phase argocd_build
if [ "$phase_status" != complete ]; then
  platform_stage 'Waiting for Argo CD and cert-manager bootstrap completion'
  phase argocd_build intent
  run_bootstrap_project argocd "$(terraform -chdir="$work_dir/baseline" output -raw argocd_bootstrap_project_name 2>/dev/null || true)"
  phase argocd_build complete
fi

read_phase tls_ready
if [ "$phase_status" != complete ]; then
  platform_stage 'Preparing Vault TLS before sealed Vault deployment'
  tls_manifest="$script_dir/../../docs/gitops/vault-tls-internal-ca.example.yaml"
  [ -f "$tls_manifest" ] && [ ! -L "$tls_manifest" ] || { printf '%s\n' 'reviewed Vault TLS manifest is unavailable' >&2; exit 65; }
  phase tls_ready intent
  env -u AWS_ACCESS_KEY_ID -u AWS_SECRET_ACCESS_KEY -u AWS_SESSION_TOKEN -u AWS_SECURITY_TOKEN \
  -u AWS_ACCESS_KEY -u AWS_SECRET_KEY -u AWS_DEFAULT_PROFILE -u AWS_WEB_IDENTITY_TOKEN_FILE -u AWS_ROLE_ARN -u AWS_ROLE_SESSION_NAME \
  -u AWS_CONTAINER_CREDENTIALS_RELATIVE_URI -u AWS_CONTAINER_CREDENTIALS_FULL_URI -u AWS_CONTAINER_AUTHORIZATION_TOKEN -u AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE \
  -u PRIVATE_EKS_SESSION -u KUBECONFIG \
    AWS_PROFILE="$aws_profile" AWS_REGION="$region" EKS_CLUSTER_NAME="$session_cluster" SSM_OPS_INSTANCE_ID="$session_instance" \
    "$script_dir/../ops/with-private-eks.sh" -- env PRIVATE_EKS_SESSION=1 AWS_PROFILE="$aws_profile" AWS_REGION="$region" EKS_CLUSTER_NAME="$session_cluster" SSM_OPS_INSTANCE_ID="$session_instance" "$script_dir/prepare-vault-bootstrap-tls.sh" --manifest "$tls_manifest"
  phase tls_ready complete
fi

# Argo apply changes the shared Terraform state. Generate the Vault plan only
# after that apply, and retain the Argo variables in its baseline overlay so
# Terraform does not plan to delete the already-applied Argo runner.
vault_baseline_config="$platform_dir/vault-baseline.tfvars.json"
jq -s '.[0] * .[1]' "$baseline_config" "$argocd_input" | "$replay" materialize --output "$vault_baseline_config"
read_phase vault_apply
if [ "$phase_status" != complete ]; then
  platform_stage 'Planning Vault bootstrap runner'
  "$replay" discard --path "$vault_plan"
  "$script_dir/apply-vault-bootstrap.sh" plan --baseline-work-dir "$work_dir" --baseline-config "$vault_baseline_config" --bootstrap-input "$vault_input" --plan-file "$vault_plan"
  platform_stage 'Applying Vault bootstrap runner'
  phase vault_apply intent
  "$script_dir/apply-vault-bootstrap.sh" apply --baseline-work-dir "$work_dir" --baseline-config "$vault_baseline_config" --bootstrap-input "$vault_input" --plan-file "$vault_plan"
  phase vault_apply complete
fi

read_phase vault_build
if [ "$phase_status" != complete ]; then
  platform_stage 'Waiting for Vault sealed-release bootstrap completion'
  phase vault_build intent
  run_bootstrap_project vault "$(terraform -chdir="$work_dir/baseline" output -raw vault_bootstrap_project_name 2>/dev/null || true)"
  phase vault_build complete
fi

# Remove the temporary runners and cluster-admin associations. The baseline
# configuration has all bootstrap flags disabled; only the explicitly named
# bootstrap resources may be deleted by this revoke plan.
platform_stage 'Revoking temporary runners and authority'
revoke_plan="$platform_dir/revoke.tfplan"
read_phase revoke_complete
if [ "$phase_status" != complete ]; then
  phase revoke_complete intent
  "$replay" discard --path "$revoke_plan"
  terraform -chdir="$work_dir/baseline" plan -input=false -var-file="$baseline_config" -out="$revoke_plan"
  terraform -chdir="$work_dir/baseline" show -json "$revoke_plan" | jq -e '
    all(.resource_changes[]?;
      (.change.actions | index("delete") | not) or
      ((.change.actions == ["delete"]) and (.address | test("^(aws_(codebuild_project|cloudwatch_log_group|eks_access_entry|iam_role|iam_role_policy|security_group)\\.(argocd_bootstrap|vault_bootstrap)\\[0\\]|aws_eks_access_policy_association\\.(argocd_bootstrap|vault_bootstrap_cluster_admin)\\[0\\]|aws_vpc_endpoint\\.required_interface\\[\\\"(eks|sts)\\\"\\]|aws_vpc_security_group_ingress_rule\\.(cluster_api_from_(argocd|vault)_bootstrap|endpoints_https_from_(argocd|vault)_bootstrap)\\[0\\])$")))
    )
  ' >/dev/null || { printf '%s\n' 'revoke plan contains an unexpected deletion; refusing cleanup' >&2; exit 70; }
  terraform -chdir="$work_dir/baseline" apply -input=false "$revoke_plan"
  phase revoke_complete complete
fi
printf '%s\n' 'PASS: Argo, cert-manager and Vault bootstrap runners completed; temporary authority and runners were revoked.'
