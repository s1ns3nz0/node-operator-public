#!/usr/bin/env bash
set -euo pipefail
umask 077

# v0.1.20 single-entry operator flow. This is an orchestration wrapper: the
# existing release and ceremony scripts remain the implementation boundary.
# Recovery shares and keystore passwords are collected by those scripts using
# silent prompts and are never accepted as command-line arguments here.

[ "$#" -eq 0 ] || { printf '%s\n' 'This release has one execution path and accepts no command-line options. Put non-secret overrides in ./env.' >&2; exit 64; }

bundle_root=''; env_file=''; env_file_line=0; env_file_dir=''

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
if [ -z "$bundle_root" ]; then
  repo_candidate="$(cd "$script_dir/../.." && pwd -P)"
  bundle_candidate="$(cd "$script_dir/../../.." && pwd -P)"
  if [ -f "$bundle_candidate/bundle-manifest.json" ]; then bundle_root="$bundle_candidate"; else bundle_root="$repo_candidate"; fi
fi
case "$bundle_root" in /*) ;; *) printf '%s\n' 'bundle root must be absolute' >&2; exit 64 ;; esac
if [ -d "$bundle_root/source" ] && [ -f "$bundle_root/bundle-manifest.json" ]; then
  source_root="$bundle_root/source"
elif [ -f "$bundle_root/scripts/release/hoodi-validator-release.sh" ]; then
  # Local repository mode is useful for dry-run and shell validation only.
  source_root="$bundle_root"
else
  printf '%s\n' 'bundle root must be a verified v0.1.20 release layout (or a repository for dry-run)' >&2; exit 65
fi

release="$source_root/scripts/release/hoodi-validator-release.sh"
prepare="$source_root/scripts/release/prepare-hoodi-zero-release-inputs.sh"
keystore="$source_root/scripts/ops/generate-hoodi-validator-keystore.sh"
deposit_validate="$source_root/scripts/ops/validate-hoodi-deposit-data.sh"
vault_tls="$source_root/scripts/release/prepare-vault-bootstrap-tls.sh"
resume_helper="$source_root/scripts/release/interactive-hoodi-resume.py"
artifact_inventory="$source_root/scripts/release/installer_artifact_inventory.py"
existing_validator_verify="$source_root/scripts/release/verify-existing-hoodi-validator.py"
collector_apply="$source_root/scripts/release/apply-validator-log-collector.py"
kyverno_apply="$source_root/scripts/release/apply-kyverno-bootstrap.py"
for file in "$release" "$prepare" "$keystore" "$deposit_validate" "$vault_tls" "$resume_helper" "$existing_validator_verify"; do [ -x "$file" ] || { printf 'missing executable in release bundle: %s\n' "$file" >&2; exit 65; }; done
[ -f "$artifact_inventory" ] || { printf '%s\n' 'release bundle lacks installer artifact authority inventory' >&2; exit 65; }
# Bind the release identity before either the fresh or resume path can invoke
# platform bootstrap.  The values producer must never inherit this from an
# ambient shell, and resume reaches bootstrap before run_post_platform.
release_revision="$(jq -er '.source_revision | select(test("^[0-9a-f]{40}$"))' "$bundle_root/bundle-manifest.json")" || {
  printf '%s\n' 'release bundle revision is invalid; platform bootstrap was not requested' >&2
  exit 65
}
artifact_authority_gate() {
  local account="$1" region="$2" deployment="$3" revision inventory
  revision="$(jq -er '.source_revision | select(test("^[0-9a-f]{40}$"))' "$bundle_root/bundle-manifest.json")" || { printf '%s\n' 'release bundle revision is invalid; no resources changed' >&2; return 65; }
  "$source_root/scripts/release/node-operator-release.sh" verify --bundle-root "$bundle_root" >/dev/null || { printf '%s\n' 'release bundle verification failed; no resources changed' >&2; return 65; }
  inventory="$(python3 "$artifact_inventory" --bundle-root "$bundle_root" --release-sha "$revision" --aws-account-id "$account" --aws-region "$region" --deployment-name "$deployment" --require-signer-probe)" || { printf '%s\n' 'required installer artifact authority is unresolved; no resources changed' >&2; return 65; }
  printf '%s\n' "$inventory"
}

# The inventory is the release-bound authority boundary.  Do not reconstruct
# destinations from catalog files, mutable tags, or an operator's source
# region.  A supplied source reference is accepted only when it is the exact
# approved immutable source for this selected deployment, then normalized to
# the reviewed private ECR destination.
artifact_record() {
  local component="$1"
  jq -cer --arg component "$component" '
    select(.schema_version == 1 and .complete == true and (.artifacts | type == "array")) |
    [.artifacts[] | select(.component == $component and .required == true)] as $matches |
    if ($matches | length) == 1 then $matches[0] else error("required artifact is absent or ambiguous") end |
    select((.destination | type == "string") and (.source | type == "string"))
  ' <<<"$artifact_authority_json"
}
canonical_image() {
  local component="$1" supplied="$2" record destination source
  record="$(artifact_record "$component")" || { printf 'canonical inventory entry is invalid: %s\n' "$component" >&2; return 65; }
  destination="$(jq -er '.destination' <<<"$record")"
  source="$(jq -er '.source' <<<"$record")"
  [[ "$destination" =~ ^${account}\.dkr\.ecr\.${region//./\.}\.amazonaws\.com/[a-z0-9][a-z0-9._/-]*@sha256:[a-f0-9]{64}$ ]] || { printf 'canonical inventory destination is invalid: %s\n' "$component" >&2; return 65; }
  [[ "$source" =~ ^[a-z0-9][a-z0-9._/-]*@sha256:[a-f0-9]{64}$ && "${destination##*@}" = "${source##*@}" ]] || { printf 'canonical inventory source is invalid: %s\n' "$component" >&2; return 65; }
  if [ -n "$supplied" ] && [ "$supplied" != "$destination" ] && [ "$supplied" != "$source" ]; then
    printf 'configured %s image conflicts with canonical artifact authority\n' "$component" >&2
    return 65
  fi
  printf '%s\n' "$destination"
}
load_authorized_artifacts() {
  artifact_authority_json="$(artifact_authority_gate "$account" "$region" "$deployment_name")" || return $?
  web3signer_image="$(canonical_image web3signer "$DEFAULT_WEB3SIGNER_IMAGE")" || return $?
  postgres_image="$(canonical_image postgres "$DEFAULT_POSTGRES_IMAGE")" || return $?
  prysm_image="$(canonical_image prysm-validator "$DEFAULT_PRYSM_IMAGE")" || return $?
  fence_image="$(canonical_image validator-signing-fence "$DEFAULT_FENCE_IMAGE")" || return $?
  argocd_bootstrap_image="$(canonical_image argocd-bootstrap "$DEFAULT_ARGOCD_BOOTSTRAP_IMAGE")" || return $?
  vault_bootstrap_image="$(canonical_image vault-bootstrap "$DEFAULT_VAULT_BOOTSTRAP_IMAGE")" || return $?
  client_chart_record="$(artifact_record node-operator-client-chart)" || { printf '%s\n' 'canonical inventory entry is invalid: node-operator-client-chart' >&2; return 65; }
  client_chart_image="$(jq -er '.destination' <<<"$client_chart_record")"
  client_chart_source="$(jq -er '.source' <<<"$client_chart_record")"
  client_chart_version="$(jq -er '.destination_tag' <<<"$client_chart_record")"
  client_chart_digest="${client_chart_image##*@}"
  [[ "$client_chart_image" =~ ^${account}\.dkr\.ecr\.${region//./\.}\.amazonaws\.com/[a-z0-9][a-z0-9._/-]*@sha256:[a-f0-9]{64}$ && "$client_chart_source" =~ ^[a-z0-9][a-z0-9._/-]*@sha256:[a-f0-9]{64}$ && "$client_chart_digest" = "${client_chart_source##*@}" && "$client_chart_version" =~ ^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$ ]] || { printf '%s\n' 'canonical inventory client chart entry is invalid' >&2; return 65; }
  if { [ -n "$DEFAULT_CLIENT_CHART_VERSION" ] && [ "$DEFAULT_CLIENT_CHART_VERSION" != "$client_chart_version" ]; } || { [ -n "$DEFAULT_CLIENT_CHART_DIGEST" ] && [ "$DEFAULT_CLIENT_CHART_DIGEST" != "$client_chart_digest" ]; }; then
    printf '%s\n' 'configured client chart reference conflicts with canonical artifact authority' >&2
    return 65
  fi
}
verify_private_image() {
  local image="$1" repository digest found
  repository="${image#*/}"; repository="${repository%@*}"; digest="${image##*@}"
  [[ "$image" =~ ^${account}\.dkr\.ecr\.${region//./\.}\.amazonaws\.com/[a-z0-9][a-z0-9._/-]*@sha256:[a-f0-9]{64}$ ]] || {
    printf 'bootstrap image must be a same-account private ECR digest: %s\n' "$image" >&2; return 65;
  }
  found="$(aws ecr describe-images --region "$region" --repository-name "$repository" --image-ids imageDigest="$digest" --query 'imageDetails[0].imageDigest' --output text 2>/dev/null || true)"
  [ "$found" = "$digest" ] || { printf 'required private ECR image is missing after the pre-EKS mirror: %s\n' "$image" >&2; return 65; }
}

# This is the only platform invocation path for both a new installation and a
# selected WORK_DIR recovery. Inputs are reconstructed from immutable release
# authority, the verified infrastructure receipt, and its fixed output paths.
run_platform_bootstrap() {
  local platform_work="$1" platform_inputs="$2" platform_session="$3"
  local vault_approved_catalog vault_artifact_index vault_mirror_receipt zero_inputs baseline_config
  local vault_chart_version vault_chart_digest cert_manager_chart_digest receipt_value index_value
  local client_repository client_found platform_script replay_helper replay_status client_values values_builder values_tmp
  local -a platform_subnets platform_args
  verify_private_image "$argocd_bootstrap_image" || return $?
  verify_private_image "$vault_bootstrap_image" || return $?
  vault_approved_catalog="$source_root/.ci/gitops/approved-oci-artifacts.json"
  vault_artifact_index="$bundle_root/rendered/installer-artifact-index.json"
  vault_mirror_receipt="$platform_work/vault-artifact-mirror-receipt.json"
  for authority in "$vault_approved_catalog" "$vault_artifact_index" "$vault_mirror_receipt"; do
    [ -f "$authority" ] && [ ! -L "$authority" ] || { printf '%s\n' 'release-bound Vault mirror authority is missing; platform plans were not requested' >&2; return 65; }
  done
  [ "$platform_inputs" = "$(dirname "$platform_work")/inputs/hoodi-zero-release-inputs.json" ] || { printf '%s\n' 'platform inputs are not the fixed sibling infrastructure receipt' >&2; return 65; }
  zero_inputs="$(dirname "$platform_inputs")/zero-resource/zero-resource-inputs.json"
  baseline_config="$(dirname "$platform_inputs")/zero-resource/baseline.tfvars.json"
  [ "$(jq -er '.zero_resource_inputs' "$platform_inputs")" = "$zero_inputs" ] || { printf '%s\n' 'infrastructure receipt does not name the fixed zero-resource inputs' >&2; return 65; }
  [ -f "$zero_inputs" ] && [ ! -L "$zero_inputs" ] && [ "$(jq -er '.baseline_config' "$zero_inputs")" = "$baseline_config" ] || { printf '%s\n' 'infrastructure receipt does not name the fixed baseline config' >&2; return 65; }
  [ -f "$baseline_config" ] && [ ! -L "$baseline_config" ] || { printf '%s\n' 'infrastructure receipt lacks a safe fixed baseline config' >&2; return 65; }
  [ -f "$platform_work/foundation-output.json" ] && [ ! -L "$platform_work/foundation-output.json" ] || { printf '%s\n' 'foundation output is unavailable or unsafe' >&2; return 65; }
  jq -e '.hoodi_subnet_ids | type == "array" and length > 0 and all(.[]; type == "string" and test("^subnet-[a-z0-9]+$"))' "$platform_work/foundation-output.json" >/dev/null || { printf '%s\n' 'foundation output lacks valid Hoodi private subnets for platform bootstrap' >&2; return 65; }
  platform_subnets=()
  while IFS= read -r subnet; do platform_subnets+=("$subnet"); done < <(jq -r '.hoodi_subnet_ids[]' "$platform_work/foundation-output.json")
  [ "${#platform_subnets[@]}" -gt 0 ] || { printf '%s\n' 'foundation output lacks Hoodi private subnets for platform bootstrap' >&2; return 65; }
  vault_chart_version="$(jq -er '.components["vault-chart"].version | select(type == "string")' "$vault_artifact_index")" || return 65
  vault_chart_digest="$(jq -er '.components["vault-chart"].expected_oci_manifest_digest | select(type == "string" and test("^sha256:[a-f0-9]{64}$"))' "$vault_artifact_index")" || return 65
  cert_manager_chart_digest="$(jq -er '.components["cert-manager-chart"].expected_oci_manifest_digest | select(type == "string" and test("^sha256:[a-f0-9]{64}$"))' "$vault_artifact_index")" || return 65
  receipt_value="$(jq -er '.artifacts["vault-chart"].version | select(type == "string")' "$vault_mirror_receipt")" || return 65
  index_value="$(jq -er '.artifacts["vault-chart"].manifest_digest | select(type == "string")' "$vault_mirror_receipt")" || return 65
  [ "$receipt_value" = "$vault_chart_version" ] && [ "$index_value" = "$vault_chart_digest" ] || { printf '%s\n' 'Vault chart receipt conflicts with the selected bundle index' >&2; return 65; }
  index_value="$(jq -er '.artifacts["cert-manager-chart"].manifest_digest | select(type == "string")' "$vault_mirror_receipt")" || return 65
  [ "$index_value" = "$cert_manager_chart_digest" ] || { printf '%s\n' 'cert-manager chart receipt conflicts with the selected bundle index' >&2; return 65; }
  if { [ -n "$DEFAULT_VAULT_CHART_VERSION" ] && [ "$DEFAULT_VAULT_CHART_VERSION" != "$vault_chart_version" ]; } || { [ -n "$DEFAULT_VAULT_CHART_DIGEST" ] && [ "$DEFAULT_VAULT_CHART_DIGEST" != "$vault_chart_digest" ]; } || { [ -n "$DEFAULT_CERT_MANAGER_CHART_DIGEST" ] && [ "$DEFAULT_CERT_MANAGER_CHART_DIGEST" != "$cert_manager_chart_digest" ]; }; then
    printf '%s\n' 'configured platform chart reference conflicts with canonical release authority' >&2; return 65
  fi
  client_repository="${client_chart_image#*/}"; client_repository="${client_repository%@*}"
  client_found="$(aws ecr describe-images --region "$region" --repository-name "$client_repository" --image-ids imageTag="$client_chart_version" --query 'imageDetails[0].imageDigest' --output text 2>/dev/null || true)"
  [ "$client_found" = "$client_chart_digest" ] || { printf 'client chart %s with digest %s is missing or mismatched in private ECR\n' "$client_chart_version" "$client_chart_digest" >&2; return 65; }
  platform_script="$source_root/scripts/release/run-platform-bootstrap.sh"
  replay_helper="$source_root/scripts/release/platform_bootstrap_replay.py"
  values_builder="$source_root/scripts/release/build-deployment-bound-chart-values-input.py"; client_values="$(dirname "$platform_inputs")/argocd-client-values.json"
  [ -x "$platform_script" ] && [ -x "$replay_helper" ] && [ -f "$values_builder" ] && [ ! -L "$values_builder" ] || { printf '%s\n' 'release bundle lacks a required platform bootstrap helper' >&2; return 65; }
  values_tmp="$(mktemp -d "$(dirname "$platform_inputs")/.client-values.XXXXXX")" || return 65
  trap 'rm -rf "$values_tmp"' RETURN
  python3 -B "$values_builder" --bundle "$bundle_root" --state "$platform_work" --work "$platform_work" --inputs "$(dirname "$zero_inputs")" --profile "${AWS_PROFILE:-default}" --release "$release_revision" --account "$account" --region "$region" --deployment "$deployment_name" --foundation "$platform_work/foundation-output.json" --baseline "$platform_work/baseline-output.json" --output "$values_tmp/candidate.json" || return 65
  if [ -e "$client_values" ] || [ -L "$client_values" ]; then cmp -s "$values_tmp/candidate.json" "$client_values" || { printf '%s\n' 'deployment-bound client values differ from the verified candidate' >&2; return 65; }; else ln "$values_tmp/candidate.json" "$client_values" || return 65; fi
  python3 - "$client_values" <<'PY' || { printf '%s\n' 'deployment-bound client values are unsafe' >&2; return 65; }
import os, stat, sys
info = os.lstat(sys.argv[1])
raise SystemExit(not (stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600 and info.st_uid == os.geteuid()))
PY
  platform_args=(--baseline-work-dir "$platform_work" --baseline-config "$baseline_config" --account "$account" --region "$region" --argocd-image "$argocd_bootstrap_image" --vault-image "$vault_bootstrap_image" --client-chart-version "$client_chart_version" --client-chart-digest "$client_chart_digest" --client-values "$client_values" --vault-chart-version "$vault_chart_version" --vault-chart-digest "$vault_chart_digest" --cert-manager-chart-digest "$cert_manager_chart_digest" --vault-approved-catalog "$vault_approved_catalog" --vault-artifact-index "$vault_artifact_index" --vault-mirror-receipt "$vault_mirror_receipt" --private-eks-session-handoff "$platform_session")
  for subnet in "${platform_subnets[@]}"; do platform_args+=(--subnet-id "$subnet"); done
  NODE_OPERATOR_AUTOMATED_CEREMONY="${NODE_OPERATOR_AUTOMATED_CEREMONY:-0}" "$platform_script" "${platform_args[@]}" || return $?
  replay_status="$(python3 "$replay_helper" phase --work-dir "$platform_work" --phase revoke_complete --action get)" || { printf '%s\n' 'platform bootstrap result has no valid durable replay checkpoint' >&2; return 70; }
  [ "$replay_status" = complete ] || { printf '%s\n' 'platform bootstrap did not record complete durable cleanup; do not continue to ceremonies' >&2; return 70; }
}
for command in aws jq find shasum python3 helm ruby; do command -v "$command" >/dev/null 2>&1 || { printf 'missing command: %s\n' "$command" >&2; exit 69; }; done

# Configuration is data, never shell input.  Path-bearing values accept only
# literal ~/ or $HOME/ prefixes; all other relative paths are resolved from
# the selected configuration file, not an unpacked temporary bundle.
expand_config_path() {
  local value="$1"
  case "$value" in
    '~') printf '%s\n' "$HOME" ;;
    '~/'*) printf '%s/%s\n' "$HOME" "${value#\~/}" ;;
    '$HOME') printf '%s\n' "$HOME" ;;
    '$HOME/'*) printf '%s/%s\n' "$HOME" "${value#\$HOME/}" ;;
    /*|'') printf '%s\n' "$value" ;;
    *) printf '%s/%s\n' "$env_file_dir" "$value" ;;
  esac
}
config_error() { printf 'configuration rejected at %s line %s\n' "$env_file" "$env_file_line" >&2; exit 64; }

# This public entrypoint deliberately ignores configuration files. Its defaults
# are derived from the authenticated AWS CLI profile, gh CLI, and git origin.
env_file=''
if [ -n "$env_file" ]; then
  env_file="$(cd "$(dirname "$env_file")" && pwd -P)/$(basename "$env_file")"
  config_source_path="${NODE_OPERATOR_CONFIG_SOURCE_PATH:-$env_file}"
  case "$config_source_path" in /*) ;; *) printf '%s\n' 'configuration provenance must be absolute' >&2; exit 65 ;; esac
  env_file_dir="$(dirname "$config_source_path")"
  printf 'Using non-secret configuration: %s\n' "$config_source_path" >&2
  while IFS='=' read -r key value; do
    env_file_line=$((env_file_line + 1))
    key="${key%%[[:space:]]*}"; value="${value##[[:space:]]}"
    case "$key" in ''|'#'*) continue ;; esac
    case "$key" in WORK_DIR) WORK_DIR="$(expand_config_path "$value")" ;; REGION) DEFAULT_REGION="$value" ;; AUDIT_REPLICA_REGION) DEFAULT_AUDIT_REPLICA_REGION="$value" ;; CI_EVIDENCE_ARCHIVE_RETENTION_MODE) DEFAULT_CI_EVIDENCE_ARCHIVE_RETENTION_MODE="$value" ;; GITHUB_REPOSITORY) DEFAULT_GITHUB_REPOSITORY="$value" ;; GITHUB_OWNER_ID) DEFAULT_GITHUB_OWNER_ID="$value" ;; GITHUB_REPOSITORY_ID) DEFAULT_GITHUB_REPOSITORY_ID="$value" ;; GITOPS_CLIENT_GITHUB_REPOSITORY) DEFAULT_GITOPS_CLIENT_GITHUB_REPOSITORY="$value" ;; GITOPS_CLIENT_GITHUB_OWNER_ID) DEFAULT_GITOPS_CLIENT_GITHUB_OWNER_ID="$value" ;; GITOPS_CLIENT_GITHUB_REPOSITORY_ID) DEFAULT_GITOPS_CLIENT_GITHUB_REPOSITORY_ID="$value" ;; DEPLOYMENT_NAME) DEFAULT_DEPLOYMENT_NAME="$value" ;; VALIDATOR_SET) DEFAULT_VALIDATOR_SET="$value" ;; VALIDATOR_PUBLIC_KEY) DEFAULT_VALIDATOR_KEY="$value" ;; WITHDRAWAL_ADDRESS) DEFAULT_WITHDRAWAL="$value" ;; EXISTING_KEYSTORE_DIR) DEFAULT_KEYSTORE_DIR="$(expand_config_path "$value")" ;; WEB3SIGNER_IMAGE) DEFAULT_WEB3SIGNER_IMAGE="$value" ;; POSTGRES_IMAGE) DEFAULT_POSTGRES_IMAGE="$value" ;; PRYSM_IMAGE) DEFAULT_PRYSM_IMAGE="$value" ;; FENCE_IMAGE) DEFAULT_FENCE_IMAGE="$value" ;; BACKEND_PRINCIPAL_ARN) DEFAULT_BACKEND_PRINCIPAL_ARN="$value" ;; ARGOCD_BOOTSTRAP_IMAGE) DEFAULT_ARGOCD_BOOTSTRAP_IMAGE="$value" ;; VAULT_BOOTSTRAP_IMAGE) DEFAULT_VAULT_BOOTSTRAP_IMAGE="$value" ;; CLIENT_CHART_VERSION) DEFAULT_CLIENT_CHART_VERSION="$value" ;; CLIENT_CHART_DIGEST) DEFAULT_CLIENT_CHART_DIGEST="$value" ;; CLIENT_CHART_SOURCE_REGION) DEFAULT_CLIENT_CHART_SOURCE_REGION="$value" ;; VAULT_CHART_VERSION) DEFAULT_VAULT_CHART_VERSION="$value" ;; VAULT_CHART_DIGEST) DEFAULT_VAULT_CHART_DIGEST="$value" ;; CERT_MANAGER_CHART_DIGEST) DEFAULT_CERT_MANAGER_CHART_DIGEST="$value" ;; DEPOSIT_TX_HASH) DEFAULT_DEPOSIT_TX_HASH="$value" ;; HOODI_PUBLIC_RPC_URL) DEFAULT_HOODI_PUBLIC_RPC_URL="$value" ;; HOODI_PUBLIC_BEACON_URL) DEFAULT_HOODI_PUBLIC_BEACON_URL="$value" ;; REQUIRED_FINALIZED_EPOCHS) DEFAULT_REQUIRED_FINALIZED_EPOCHS="$value" ;; *) config_error ;; esac
  done < "$env_file"
fi
if [ -n "${WORK_DIR:-}" ]; then
  # Resume is bound to its recorded deployment context and must not require a
  # new AWS or GitHub discovery query before its own integrity checks.
  runtime_defaults='{}'; DEFAULT_REGION=ap-northeast-2; DEFAULT_DEPLOYMENT_NAME=resume-placeholder
  DEFAULT_GITHUB_REPOSITORY=resume/placeholder; DEFAULT_GITHUB_OWNER_ID=1; DEFAULT_GITHUB_REPOSITORY_ID=1
  DEFAULT_GITOPS_CLIENT_GITHUB_REPOSITORY=resume/placeholder; DEFAULT_GITOPS_CLIENT_GITHUB_OWNER_ID=1; DEFAULT_GITOPS_CLIENT_GITHUB_REPOSITORY_ID=1
else
  defaults_helper="$source_root/scripts/release/interactive-hoodi-defaults.sh"
  [ -x "$defaults_helper" ] || { printf '%s\n' 'release bundle lacks interactive default discovery' >&2; exit 65; }
  runtime_defaults="$("$defaults_helper")" || exit $?
  DEFAULT_REGION="$(jq -er '.aws_region' <<<"$runtime_defaults")"
  DEFAULT_DEPLOYMENT_NAME="$(jq -er '.deployment_name' <<<"$runtime_defaults")"
  DEFAULT_GITHUB_REPOSITORY="$(jq -er '.github_repository' <<<"$runtime_defaults")"; DEFAULT_GITHUB_OWNER_ID="$(jq -er '.github_owner_id' <<<"$runtime_defaults")"; DEFAULT_GITHUB_REPOSITORY_ID="$(jq -er '.github_repository_id' <<<"$runtime_defaults")"
  DEFAULT_GITOPS_CLIENT_GITHUB_REPOSITORY="$(jq -er '.gitops_client_github_repository' <<<"$runtime_defaults")"; DEFAULT_GITOPS_CLIENT_GITHUB_OWNER_ID="$(jq -er '.gitops_client_github_owner_id' <<<"$runtime_defaults")"; DEFAULT_GITOPS_CLIENT_GITHUB_REPOSITORY_ID="$(jq -er '.gitops_client_github_repository_id' <<<"$runtime_defaults")"
fi
DEFAULT_KEYSTORE_DIR=''; DEFAULT_VALIDATOR_SET='hoodi-example'; DEFAULT_VALIDATOR_KEY=''; DEFAULT_WITHDRAWAL=''; DEFAULT_AUDIT_REPLICA_REGION=''; DEFAULT_CI_EVIDENCE_ARCHIVE_RETENTION_MODE=COMPLIANCE
validate_selected_github_identity() {
  local repository="$1" owner_id="$2" repository_id="$3"
  [[ "$repository" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ && "$owner_id" =~ ^[1-9][0-9]*$ && "$repository_id" =~ ^[1-9][0-9]*$ ]] || {
    printf '%s\n' 'GitHub trust requires an exact repository and both positive numeric owner/repository IDs; no AWS mutation requested.' >&2
    return 64
  }
}
validate_selected_github_identity "$DEFAULT_GITHUB_REPOSITORY" "$DEFAULT_GITHUB_OWNER_ID" "$DEFAULT_GITHUB_REPOSITORY_ID" || exit $?
validate_selected_github_identity "$DEFAULT_GITOPS_CLIENT_GITHUB_REPOSITORY" "$DEFAULT_GITOPS_CLIENT_GITHUB_OWNER_ID" "$DEFAULT_GITOPS_CLIENT_GITHUB_REPOSITORY_ID" || exit $?
DEFAULT_WEB3SIGNER_IMAGE=''; DEFAULT_POSTGRES_IMAGE=''; DEFAULT_PRYSM_IMAGE=''; DEFAULT_FENCE_IMAGE=''
DEFAULT_BACKEND_PRINCIPAL_ARN=''; DEFAULT_ARGOCD_BOOTSTRAP_IMAGE=''; DEFAULT_VAULT_BOOTSTRAP_IMAGE=''
DEFAULT_CLIENT_CHART_VERSION=''; DEFAULT_CLIENT_CHART_DIGEST=''; DEFAULT_CLIENT_CHART_SOURCE_REGION=ap-northeast-2
DEFAULT_VAULT_CHART_VERSION=''; DEFAULT_VAULT_CHART_DIGEST=''; DEFAULT_CERT_MANAGER_CHART_DIGEST=''
DEFAULT_DEPOSIT_TX_HASH=''; DEFAULT_HOODI_PUBLIC_RPC_URL=''; DEFAULT_HOODI_PUBLIC_BEACON_URL=https://ethereum-hoodi-beacon-api.publicnode.com
DEFAULT_REQUIRED_FINALIZED_EPOCHS=3
case "$DEFAULT_REQUIRED_FINALIZED_EPOCHS" in 1|2|3) ;; *) printf '%s\n' 'REQUIRED_FINALIZED_EPOCHS must be 1, 2, or 3' >&2; exit 64 ;; esac

[ -d "$bundle_root/source" ] && [ -f "$bundle_root/bundle-manifest.json" ] || {
  printf '%s\n' 'a verified v0.1.20 release bundle is required' >&2; exit 65;
}

prompt() { local label="$1" value; printf '%s: ' "$label" >&2; IFS= read -r value; printf '%s' "$value"; }
prompt_default() { local label="$1" fallback="$2" value; printf '%s [%s]: ' "$label" "$fallback" >&2; IFS= read -r value; printf '%s' "${value:-$fallback}"; }
prompt_secret() { local label="$1" value; printf '%s: ' "$label" >&2; IFS= read -r -s value; printf '\n' >&2; printf '%s' "$value"; }
if [ -t 2 ]; then ui_reset=$'\033[0m'; ui_cyan=$'\033[1;36m'; ui_green=$'\033[1;32m'; ui_yellow=$'\033[1;33m'; ui_red=$'\033[1;31m'; else ui_reset=''; ui_cyan=''; ui_green=''; ui_yellow=''; ui_red=''; fi
step_number=0
diagnostic_log=''; diagnostic_stage='startup'; diagnostic_stage_started=''
diagnostic_event() { [ -n "$diagnostic_log" ] || return 0; printf '%s stage=%s status=%s%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$diagnostic_stage" "$1" "${2:+ duration_seconds=$2}" >> "$diagnostic_log"; }
init_diagnostics() {
  local root="$1" mode="$2" directory stamp
  [ -d "$root" ] && [ ! -L "$root" ] || { printf '%s\n' 'diagnostic root is unavailable or unsafe' >&2; return 65; }
  directory="$root/diagnostics"
  [ ! -e "$directory" ] && [ ! -L "$directory" ] && mkdir -m 700 "$directory"
  [ -d "$directory" ] && [ ! -L "$directory" ] || { printf '%s\n' 'diagnostic directory is unavailable or unsafe' >&2; return 65; }
  chmod 700 "$directory"
  stamp="$(date -u +%Y%m%dT%H%M%SZ)"
  diagnostic_log="$(umask 077; mktemp "$directory/installer-$stamp.XXXXXX")" || return 65
  [ -f "$diagnostic_log" ] && [ ! -L "$diagnostic_log" ] && chmod 600 "$diagnostic_log" || return 65
  printf '%s stage=%s status=start mode=%s source_revision=%.12s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$diagnostic_stage" "$mode" "$release_revision" >> "$diagnostic_log"
  printf 'Diagnostic log: %s (%s)\n' "$diagnostic_log" "$mode" >&2
}
diagnostic_failed() { local status="$1" line="$2" now elapsed; [ -n "$diagnostic_log" ] || return 0; now="$(date +%s)"; elapsed=$((now - diagnostic_stage_started)); printf '%s stage=%s status=failed duration_seconds=%s source=%s line=%s exit_code=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$diagnostic_stage" "$elapsed" "${BASH_SOURCE[1]##*/}" "$line" "$status" >> "$diagnostic_log"; }
diagnostic_finish() { local status="$1" now elapsed; [ -n "$diagnostic_log" ] || return 0; now="$(date +%s)"; elapsed=0; [ -z "$diagnostic_stage_started" ] || elapsed=$((now - diagnostic_stage_started)); if [ "$status" -eq 0 ]; then diagnostic_event complete "$elapsed"; else printf '%s stage=%s status=failed duration_seconds=%s source=exit line=unavailable exit_code=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$diagnostic_stage" "$elapsed" "$status" >> "$diagnostic_log"; fi; }
step() { local now elapsed; now="$(date +%s)"; if [ -n "$diagnostic_stage_started" ]; then elapsed=$((now - diagnostic_stage_started)); diagnostic_event complete "$elapsed"; fi; diagnostic_stage="$1"; diagnostic_stage_started="$now"; diagnostic_event start; step_number=$((step_number + 1)); printf '\n%s━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%s\n%s◆ STEP %02d/10%s  %s%s%s\n%s━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%s\n' "$ui_cyan" "$ui_reset" "$ui_cyan" "$step_number" "$ui_reset" "$ui_green" "$1" "$ui_reset" "$ui_cyan" "$ui_reset" >&2; }
display_digest() { local digest; case "$1" in *@sha256:????????????????????????????????????????????????????????????????) digest="${1##*@sha256:}"; printf '%s@sha256:%s...%s' "${1%@*}" "${digest:0:12}" "${digest: -8}" ;; *) printf '%s' "$1" ;; esac; }
absolute_new_dir() { case "$1" in /*) ;; *) printf '%s\n' 'path must be absolute' >&2; exit 64 ;; esac; [ ! -e "$1" ] && [ ! -L "$1" ] || { printf 'path already exists: %s\n' "$1" >&2; exit 65; }; }

advance_lifecycle() {
  python3 -I -B "$resume_helper" phase --work-dir "$output_dir" --manifest "$bundle_root/bundle-manifest.json" --phase "$1" || {
    printf '%s\n' 'lifecycle checkpoint could not be committed; stop and reconcile this WORK_DIR' >&2; return 75;
  }
  lifecycle_phase="$1"
  [ -z "$diagnostic_log" ] || printf '%s stage=%s status=checkpoint phase=%s source_revision=%.12s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$diagnostic_stage" "$lifecycle_phase" "$release_revision" >> "$diagnostic_log"
}

run_observation_phase() {
  observation_complete=false
  if [ "$lifecycle_phase" = complete ]; then
    python3 -I -B "$resume_helper" read --work-dir "$output_dir" --manifest "$bundle_root/bundle-manifest.json" >/dev/null || return 75
    observation_complete=true
  fi
  if [ "$lifecycle_phase" = activated ]; then advance_lifecycle observing || return $?; fi
  step 'Observing finalized validator duties and archived signing activity'
  if ! "${selected_tunnel_env[@]}" "$source_root/scripts/ops/with-private-eks.sh" -- env PRIVATE_EKS_SESSION=1 \
    python3 -I -B "$source_root/scripts/release/run-hoodi-validator-observation.py" \
    --bundle-root "$bundle_root" --work-dir "$output_dir" --public-beacon-url "$DEFAULT_HOODI_PUBLIC_BEACON_URL" \
    --required-finalized-epochs "$DEFAULT_REQUIRED_FINALIZED_EPOCHS"; then
    printf '%s\n' 'PENDING: finalized-duty, archive, Vault challenge, or delivery-metadata gate did not pass; lifecycle remains unchanged.' >&2
    return 75
  fi
  if [ "$observation_complete" = false ]; then advance_lifecycle complete || return $?; fi
  printf '%s\n' 'PASS: finalized-duty, archived signer/fence, Vault challenge, and delivery-metadata gates currently pass.' >&2
  return 0
}

run_post_platform() {
lifecycle_phase="${1:-platform-complete}"
case "$lifecycle_phase" in
  activation-started)
    python3 -I -B "$resume_helper" reconcile-activation --work-dir "$output_dir" --manifest "$bundle_root/bundle-manifest.json" || {
      printf 'PENDING: activation outcome has no valid bound receipt; activation was not replayed. WORK_DIR=%s\n' "$output_dir" >&2
      return 75
    }
    lifecycle_phase=activated
    printf '%s\n' 'PENDING: saved activation lower bound was reconciled without reactivation; finalized duty and log evidence remain required.' >&2
    ;;
  vault-started)
    [ -f "$output_dir/vault-recovery/vault-initialization-checkpoint.json" ] && [ ! -L "$output_dir/vault-recovery/vault-initialization-checkpoint.json" ] || {
      printf 'PENDING: outcome of vault-started must be reconciled; no completed initialization checkpoint is available. WORK_DIR=%s\n' "$output_dir" >&2; return 75;
    } ;;
  complete|activated|observing) ;;
  platform-complete|vault-complete|collector-complete|audit-started|audit-complete|custody-started|custody-complete|runtime-complete|activation-pending) ;;
  *) printf 'unsupported continuation phase: %s\n' "$lifecycle_phase" >&2; return 65 ;;
esac
# Bind every post-platform private tunnel to the same live session accepted by
# platform bootstrap. Do this before opening either EKS or Vault tunnels, with
# ambient credential/session selectors removed only at this outer boundary.
platform_session_verifier="$source_root/scripts/release/verify-platform-private-eks-session.py"
[ -x "$platform_session_verifier" ] || { printf '%s\n' 'release bundle lacks the private EKS session verifier' >&2; exit 65; }
selected_profile="${AWS_PROFILE:-default}"
selected_baseline="$output_dir/inputs/zero-resource/baseline.tfvars.json"
session_target="$(env -u AWS_ACCESS_KEY_ID -u AWS_SECRET_ACCESS_KEY -u AWS_SESSION_TOKEN -u AWS_SECURITY_TOKEN \
  -u AWS_ACCESS_KEY -u AWS_SECRET_KEY -u AWS_DEFAULT_PROFILE -u AWS_WEB_IDENTITY_TOKEN_FILE -u AWS_ROLE_ARN -u AWS_ROLE_SESSION_NAME \
  -u AWS_CONTAINER_CREDENTIALS_RELATIVE_URI -u AWS_CONTAINER_CREDENTIALS_FULL_URI -u AWS_CONTAINER_AUTHORIZATION_TOKEN -u AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE \
  -u PRIVATE_EKS_SESSION -u PRIVATE_VAULT_SESSION -u PRIVATE_VAULT_TARGET -u KUBECONFIG -u BASH_ENV -u ENV \
  -u VAULT_ADDR -u VAULT_CACERT -u VAULT_TLS_SERVER_NAME -u VAULT_SKIP_VERIFY -u VAULT_NAMESPACE -u VAULT_TOKEN \
  AWS_PROFILE="$selected_profile" AWS_REGION="$region" AWS_DEFAULT_REGION="$region" AWS_EC2_METADATA_DISABLED=true python3 "$platform_session_verifier" --work-dir "$output_dir/deployment-work" --baseline-config "$selected_baseline" --session "$session" --account "$account" --region "$region" --profile "$selected_profile")" || { printf '%s\n' 'post-platform private EKS session verification failed before Vault or runtime mutation' >&2; exit 65; }
IFS=$'\t' read -r selected_cluster selected_instance <<<"$session_target"
[ "$selected_cluster" = "$deployment_name" ] && [[ "$selected_instance" =~ ^i-[0-9a-f]+$ ]] || { printf '%s\n' 'post-platform session verifier returned an invalid selected target' >&2; exit 65; }
selected_tunnel_env=(env -u AWS_ACCESS_KEY_ID -u AWS_SECRET_ACCESS_KEY -u AWS_SESSION_TOKEN -u AWS_SECURITY_TOKEN -u AWS_ACCESS_KEY -u AWS_SECRET_KEY -u AWS_DEFAULT_PROFILE -u AWS_WEB_IDENTITY_TOKEN_FILE -u AWS_ROLE_ARN -u AWS_ROLE_SESSION_NAME -u AWS_CONTAINER_CREDENTIALS_RELATIVE_URI -u AWS_CONTAINER_CREDENTIALS_FULL_URI -u AWS_CONTAINER_AUTHORIZATION_TOKEN -u AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE -u PRIVATE_EKS_SESSION -u PRIVATE_VAULT_SESSION -u PRIVATE_VAULT_TARGET -u KUBECONFIG -u BASH_ENV -u ENV -u VAULT_ADDR -u VAULT_CACERT -u VAULT_TLS_SERVER_NAME -u VAULT_SKIP_VERIFY -u VAULT_NAMESPACE -u VAULT_TOKEN AWS_PROFILE="$selected_profile" AWS_REGION="$region" AWS_DEFAULT_REGION="$region" AWS_EC2_METADATA_DISABLED=true EKS_CLUSTER_NAME="$selected_cluster" SSM_OPS_INSTANCE_ID="$selected_instance")

if [ "$lifecycle_phase" = activated ] || [ "$lifecycle_phase" = observing ] || [ "$lifecycle_phase" = complete ]; then
  run_observation_phase
  return $?
fi

if [ "$lifecycle_phase" = vault-started ]; then
  "${selected_tunnel_env[@]}" PRIVATE_VAULT_TARGET=pod/vault-0 "$source_root/scripts/ops/with-private-vault.sh" -- env PRIVATE_VAULT_SESSION=1 "$source_root/scripts/ops/recover-and-bootstrap-hoodi-vault-v2.sh" --validator-set "$validator_set" --recovery-output-dir "$output_dir/vault-recovery" --verify-initialization-completion || {
    printf '%s\n' 'PENDING: recorded Vault initialization completion could not be verified; no administrator ceremony was replayed.' >&2; return 75;
  }
  advance_lifecycle vault-complete || return $?
fi

if [ "$lifecycle_phase" = platform-complete ]; then
step 'Running Vault v2 recovery and validator custody'
printf '%s\n' 'Next ceremony: Vault v2 recovery. Recovery shares will be requested silently by the delegated script.' >&2
vault_recovery_output="$output_dir/vault-recovery"
advance_lifecycle vault-started || return $?
"${selected_tunnel_env[@]}" PRIVATE_VAULT_TARGET=pod/vault-0 "$source_root/scripts/ops/with-private-vault.sh" -- env PRIVATE_VAULT_SESSION=1 NODE_OPERATOR_AUTOMATED_CEREMONY="${NODE_OPERATOR_AUTOMATED_CEREMONY:-0}" "$source_root/scripts/ops/recover-and-bootstrap-hoodi-vault-v2.sh" --validator-set "$validator_set" --recovery-output-dir "$vault_recovery_output"
advance_lifecycle vault-complete || return $?
fi

# The sealed first-install gate deliberately accepts Running-but-not-Ready
# servers. After the operator ceremony, custody may proceed only once the
# actual server Pods are Ready and their TLS status reports initialized/unsealed.
"${selected_tunnel_env[@]}" "$source_root/scripts/ops/with-private-eks.sh" -- env PRIVATE_EKS_SESSION=1 "$source_root/scripts/ops/verify-hoodi-vault-readiness.sh" --mode post-init-ready

if [ "$lifecycle_phase" = audit-started ]; then
  python3 -I -B "$resume_helper" reconcile-audit-complete --work-dir "$output_dir" --manifest "$bundle_root/bundle-manifest.json" || { printf '%s\n' 'PENDING: audit ceremony outcome is unknown; do not replay administrator ceremony.' >&2; return 75; }
  lifecycle_phase=audit-complete
fi
if [ "$lifecycle_phase" = vault-complete ]; then
  step 'Installing verified private Kyverno before dependent policy consumers'
  "${selected_tunnel_env[@]}" python3 -I -B "$kyverno_apply" --bundle-root "$bundle_root" --state-dir "$output_dir" --work-dir "$output_dir/deployment-work" --inputs-dir "$output_dir/inputs" --session "$session" --baseline-config "$selected_baseline" --account "$account" --region "$region" --deployment "$deployment_name" --profile "$selected_profile" --release-sha "$release_revision" || return 65
  step 'Applying verified validator log collector'
  "${selected_tunnel_env[@]}" python3 -I -B "$collector_apply" --bundle-root "$bundle_root" --state-dir "$output_dir" --work-dir "$output_dir/deployment-work" --inputs-dir "$output_dir/inputs" --session "$session" --baseline-config "$selected_baseline" --account "$account" --region "$region" --deployment "$deployment_name" --validator-set "$validator_set" --profile "$selected_profile" --release-sha "$release_revision" || return 65
  advance_lifecycle collector-complete || return $?
fi
if [ "$lifecycle_phase" = collector-complete ]; then
  audit_dir="$output_dir/audit"
  if [ ! -e "$audit_dir" ] && [ ! -L "$audit_dir" ]; then mkdir -m 700 "$audit_dir" || return 65; fi
  python3 - "$audit_dir" <<'PY' || return 65
import os, stat, sys
info = os.lstat(sys.argv[1])
raise SystemExit(not (stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700 and info.st_uid == os.geteuid()))
PY
  audit_operation="$(python3 -I -B "$resume_helper" prepare-audit --work-dir "$output_dir" --manifest "$bundle_root/bundle-manifest.json")" || return 65
  audit_operation_id="$(jq -er '.operation_id | select(test("^[0-9a-f]{32}$"))' <<<"$audit_operation")" || return 65
  advance_lifecycle audit-started || return $?
  step 'Configuring Vault audit devices before custody'
  "${selected_tunnel_env[@]}" PRIVATE_VAULT_TARGET=pod/vault-0 "$source_root/scripts/ops/with-private-vault.sh" -- env PRIVATE_VAULT_SESSION=1 AUDIT_RECEIPT="$audit_dir/audit-challenge.json" AUDIT_ACCOUNT="$account" AUDIT_REGION="$region" AUDIT_DEPLOYMENT="$deployment_name" AUDIT_RELEASE_REVISION="$release_revision" AUDIT_OPERATION_ID="$audit_operation_id" "$source_root/scripts/ops/recover-and-configure-private-vault-validator-audit.sh" || return $?
  python3 -I -B "$resume_helper" reconcile-audit-complete --work-dir "$output_dir" --manifest "$bundle_root/bundle-manifest.json" || return 75
  lifecycle_phase=audit-complete
fi

if [ "$lifecycle_phase" = custody-started ]; then
  # A completed onboarding receipt can recover the narrow crash window after
  # token cleanup. Missing or mismatched proof never triggers another ceremony.
  python3 -I -B "$resume_helper" reconcile-custody-complete --work-dir "$output_dir" --manifest "$bundle_root/bundle-manifest.json" || {
    printf '%s\n' 'PENDING: custody completion is unproven; the existing ceremony was not replayed.' >&2; return 75;
  }
  lifecycle_phase=custody-complete
fi

if [ "$lifecycle_phase" = audit-complete ]; then
custody_operation="$(python3 -I -B "$resume_helper" prepare-custody --work-dir "$output_dir" --manifest "$bundle_root/bundle-manifest.json" --validator-set "$validator_set")" || return 65
custody_operation_id="$(jq -er '.operation_id | select(test("^[0-9a-f]{32}$"))' <<<"$custody_operation")" || return 65
custody_result_output="$(jq -er '.result_output | select(startswith("/"))' <<<"$custody_operation")" || return 65
advance_lifecycle custody-started || return $?
"$release" custody apply --bundle-root "$bundle_root" --inputs "$inputs" --private-eks-session-handoff "$session" --keystore-dir "$keystore_dir_for_custody" --ceremony-dir "$output_dir/ceremony" --custody-result-output "$custody_result_output" --custody-operation-id "$custody_operation_id"
python3 -I -B "$resume_helper" reconcile-custody-complete --work-dir "$output_dir" --manifest "$bundle_root/bundle-manifest.json" || return 75
lifecycle_phase=custody-complete
fi

if [ "$lifecycle_phase" = custody-complete ]; then
step 'Applying Vault-backed validator runtime'
runtime_manifest="$(dirname "$inputs")/validator-deployment/runtime.yaml"
client_manifest="$(dirname "$inputs")/validator-deployment/client-and-fence.yaml"
[ -f "$runtime_manifest" ] && [ ! -L "$runtime_manifest" ] && [ -f "$client_manifest" ] && [ ! -L "$client_manifest" ] || {
  printf '%s\n' 'staged validator runtime manifests are missing' >&2
  exit 65
}
baseline_output="$output_dir/deployment-work/baseline-output.json"
storage_class_template="$source_root/deploy/validator/storage-class.yaml"
storage_class_helper="$source_root/scripts/ops/ensure-validator-encrypted-storageclass.sh"
runtime_apply_helper="$source_root/scripts/release/apply-hoodi-validator-runtime.sh"
[ -f "$baseline_output" ] && [ ! -L "$baseline_output" ] && [ -f "$storage_class_template" ] && [ ! -L "$storage_class_template" ] && [ -x "$storage_class_helper" ] && [ -x "$runtime_apply_helper" ] || {
  printf '%s\n' 'verified baseline EBS output or validator StorageClass helper is unavailable; runtime was not applied' >&2
  exit 65
}
validator_ebs_kms_key_arn="$(jq -er '.ebs_kms_key_arn.value | select(type == "string" and test("^arn:aws:kms:[a-z0-9-]+:[0-9]{12}:key/[^/]+$"))' "$baseline_output")" || {
  printf '%s\n' 'verified baseline output lacks a valid EBS CMK ARN; runtime was not applied' >&2
  exit 65
}
printf '%s\n' 'Synchronizing the public Vault CA trust anchor and applying non-secret manifests.' >&2
# The custody receipt proves secret onboarding and cleanup, not Kubernetes
# publication. Reapply this non-secret ConfigMap on every runtime-stage retry.
known_clients_file="$output_dir/ceremony/known-clients.txt"
[ -f "$known_clients_file" ] && [ ! -L "$known_clients_file" ] || { printf '%s\n' 'verified public known-clients output is missing; runtime was not applied' >&2; return 65; }
"${selected_tunnel_env[@]}" "$source_root/scripts/ops/with-private-eks.sh" -- env PRIVATE_EKS_SESSION=1 "$storage_class_helper" --template "$storage_class_template" --kms-key-arn "$validator_ebs_kms_key_arn"
"${selected_tunnel_env[@]}" "$source_root/scripts/ops/with-private-eks.sh" -- env PRIVATE_EKS_SESSION=1 kubectl -n validator-operations create configmap "validator-${validator_set}-known-clients" --from-file="known-clients=$known_clients_file" --dry-run=client -o yaml | "${selected_tunnel_env[@]}" "$source_root/scripts/ops/with-private-eks.sh" -- env PRIVATE_EKS_SESSION=1 kubectl apply -f - >/dev/null
"${selected_tunnel_env[@]}" "$source_root/scripts/ops/with-private-eks.sh" -- env PRIVATE_EKS_SESSION=1 "$source_root/scripts/ops/ensure-vault-agent-ca.sh" --namespace validator-operations --namespace node-operator
runtime_client_manifest="$output_dir/deployment-work/client-and-fence-runtime.yaml"
"${selected_tunnel_env[@]}" "$source_root/scripts/ops/with-private-eks.sh" -- env PRIVATE_EKS_SESSION=1 "$runtime_apply_helper" --runtime "$runtime_manifest" --client "$client_manifest" --rendered-client "$runtime_client_manifest" --beacon-service "$source_root/deploy/prysm/service.yaml" --validator-set "$validator_set"
printf '%s\n' 'PASS: Vault-backed runtime is staged; signer, validator client, and fence remain at their guarded replica counts.' >&2
advance_lifecycle runtime-complete || return $?
fi

if [ "$lifecycle_phase" = runtime-complete ]; then
step 'Collecting signer and Beacon evidence'
[ ! -L "$output_dir/evidence" ] || return 65
mkdir -p -m 700 "$output_dir/evidence"
"$release" evidence signer --bundle-root "$bundle_root" --inputs "$inputs" --private-eks-session-handoff "$session" --output-dir "$output_dir/evidence/signer"
"$release" evidence beacon --bundle-root "$bundle_root" --inputs "$inputs" --private-eks-session-handoff "$session" --output-dir "$output_dir/evidence/beacon"
advance_lifecycle activation-pending || return $?
fi

printf 'Generated and validated deposit attestation: %s\n' "$deposit_attestation" >&2
printf '%s\n' 'Activation requires independently reviewed public deposit, private Beacon, and signer evidence. Enter paths only; secret material is not accepted.' >&2
step 'Guarded validator activation'
if [ "${NODE_OPERATOR_AUTOMATED_CEREMONY:-0}" = 1 ] && [ -n "$DEFAULT_DEPOSIT_TX_HASH" ] && [ -n "$DEFAULT_HOODI_PUBLIC_RPC_URL" ]; then
  external_dir="$output_dir/evidence/public"; [ ! -L "$external_dir" ] || return 65; mkdir -p -m 700 "$external_dir"
  withdrawal_credentials="$(jq -er '.withdrawal_credentials' "$deposit_attestation")"
  "$source_root/scripts/ops/observe-external-hoodi-validator.sh" --validator-set "$validator_set" --validator-public-key "$validator_key" --correlation-id "$(printf '%s' "$validator_set-$deployment_name" | shasum -a 256 | cut -c1-32)" --output-dir "$external_dir" --deposit-tx "$DEFAULT_DEPOSIT_TX_HASH" --withdrawal-credentials "$withdrawal_credentials" --public-rpc-url "$DEFAULT_HOODI_PUBLIC_RPC_URL" >/dev/null
  public_deposit="$(find "$external_dir" -type f -name '*public-rpc*.json' -print | LC_ALL=C sort | tail -n 1)"
  private_evidence="$(find "$output_dir/evidence/beacon" -type f -name 'uc-3-private-beacon-*.json' -print | LC_ALL=C sort | tail -n 1)"
  signer_evidence="$(find "$output_dir/evidence/signer" -type f -name "signer-public-key-${validator_set}-*.json" -print | LC_ALL=C sort | tail -n 1)"
  confirm_key="$validator_key"; confirm_withdrawal="$withdrawal"
  [ -n "$public_deposit" ] && [ -n "$private_evidence" ] && [ -n "$signer_evidence" ] || { printf '%s\n' 'automated activation evidence collection was incomplete' >&2; exit 65; }
  printf '%s\n' 'Automated disposable-run mode: public receipt, Beacon, and signer evidence were collected; activating the existing Hoodi validator.' >&2
else
  public_deposit="$(prompt 'Absolute public deposit verification JSON')"
  private_evidence="$(prompt 'Absolute private Beacon evidence JSON')"
  signer_evidence="$(prompt 'Absolute signer evidence JSON')"
  confirm_key="$(prompt 'Confirm validator public key (0x...)')"
  confirm_withdrawal="$(prompt 'Confirm withdrawal address (0x...)')"
fi
activation_context="$(python3 -I -B "$resume_helper" prepare-activation --work-dir "$output_dir" --manifest "$bundle_root/bundle-manifest.json")" || return 75
activation_operation="$(jq -er '.operation_id | select(test("^[0-9a-f]{32}$"))' <<<"$activation_context")" || return 65
activation_receipt="$(jq -er '.receipt_output' <<<"$activation_context")" || return 65
activation_revision="$(jq -er '.release_revision | select(test("^[0-9a-f]{40}$"))' <<<"$activation_context")" || return 65
[ "$(jq -er '.deployment_name' <<<"$activation_context")" = "$deployment_name" ] || return 65
advance_lifecycle activation-started || return $?
"$release" activate apply --bundle-root "$bundle_root" --inputs "$inputs" --private-eks-session-handoff "$session" --deposit-attestation "$deposit_attestation" --public-deposit-verification "$public_deposit" --private-evidence "$private_evidence" --signer-evidence "$signer_evidence" --confirm-public-key "$confirm_key" --confirm-withdrawal-address "$confirm_withdrawal" --activation-receipt "$activation_receipt" --deployment-name "$deployment_name" --release-revision "$activation_revision" --operation-id "$activation_operation"
python3 -I -B "$resume_helper" reconcile-activation --work-dir "$output_dir" --manifest "$bundle_root/bundle-manifest.json" || {
  printf '%s\n' 'PENDING: activation returned but its bound receipt could not be committed; do not repeat activation.' >&2
  return 75
}
lifecycle_phase=activated
run_observation_phase
return $?
}

# WORK_DIR is an explicit recovery selector. Legacy infrastructure receipts
# stop at platform completion; a bound continuation reuses the selected key
# and durable lifecycle phase without generating a key or depositing again.
if [ -n "${WORK_DIR:-}" ]; then
  [ -d "$WORK_DIR" ] && [ ! -L "$WORK_DIR" ] || { printf '%s\n' 'WORK_DIR is unavailable or unsafe' >&2; exit 65; }
  context="$(python3 "$resume_helper" read --work-dir "$WORK_DIR" --manifest "$bundle_root/bundle-manifest.json")" || exit $?
  init_diagnostics "$WORK_DIR" resume || exit $?
  trap 'diagnostic_failed "$?" "$LINENO"' ERR
  [ -t 0 ] && [ -t 1 ] || { printf '%s\n' 'infrastructure recovery requires an interactive terminal' >&2; exit 69; }
  account="$(jq -er '.aws_account_id' <<<"$context")"; region="$(jq -er '.aws_region' <<<"$context")"; deployment_name="$(jq -er '.deployment_name' <<<"$context")"; phase="$(jq -er '.phase' <<<"$context")"
  identity="$(aws sts get-caller-identity --output json)"; observed="$(jq -er '.Account | select(test("^[0-9]{12}$"))' <<<"$identity")" || { printf '%s\n' 'AWS identity did not return an account' >&2; exit 65; }
  [ "$observed" = "$account" ] || { printf '%s\n' 'saved deployment account differs from current AWS identity' >&2; exit 65; }
  load_authorized_artifacts || exit $?
  printf 'Resume verified deployment for account %s, Region %s, deployment %s at phase %s. Type RESUME to continue: ' "$account" "$region" "$deployment_name" "$phase" >&2
  IFS= read -r confirmation; [ "$confirmation" = RESUME ] || { printf '%s\n' 'infrastructure recovery cancelled' >&2; exit 0; }
  lock="$WORK_DIR/.interactive-resume.lock"; mkdir "$lock" 2>/dev/null || { printf '%s\n' 'another recovery invocation holds the WORK_DIR lock' >&2; exit 75; }; trap 'status=$?; diagnostic_finish "$status"; rmdir "$lock" 2>/dev/null || true; exit "$status"' EXIT
  context="$(python3 "$resume_helper" read --work-dir "$WORK_DIR" --manifest "$bundle_root/bundle-manifest.json")" || { printf '%s\n' 'recovery context changed while awaiting confirmation; no mutation requested' >&2; exit 65; }
  [ "$(jq -er '.phase' <<<"$context")" = "$phase" ] || { printf '%s\n' 'recovery phase changed while awaiting confirmation; no mutation requested' >&2; exit 65; }
  # Re-read the bundle-bound receipt after the explicit confirmation. A stale
  # or changed authority can never be used to resume an old platform stage.
  load_authorized_artifacts || exit $?
  inputs="$WORK_DIR/$(jq -er '.inputs_rel' <<<"$context")"; work="$WORK_DIR/$(jq -er '.work_rel' <<<"$context")"; session="$WORK_DIR/$(jq -er '.session_rel' <<<"$context")"
  if jq -e '.continuation | type == "object"' <<<"$context" >/dev/null; then
    output_dir="$WORK_DIR"
    keystore_dir_for_custody="$(jq -er '.continuation.keystore_dir' <<<"$context")"
    validator_key="$(jq -er '.continuation.public_key' <<<"$context")"
    deposit_attestation="$WORK_DIR/$(jq -er '.continuation.deposit_attestation_rel' <<<"$context")"
    validator_set="$(jq -er '.validator_set' "$inputs")"
    withdrawal="$(jq -er '.withdrawal_address | select(test("^0x[0-9a-fA-F]{40}$"))' "$deposit_attestation")"
    python3 -I -B "$source_root/scripts/ops/verify-custody-validator-key.py" --keystore-dir "$keystore_dir_for_custody" --expected-public-key "$validator_key" >/dev/null || exit 65
    python3 -I -B "$source_root/scripts/release/custody_verifier_runtime.py" verify --work-dir "$WORK_DIR" --bundle-root "$bundle_root" --expected-public-key "$validator_key" >/dev/null || { printf '%s\n' 'saved custody verification runtime is no longer valid; no ceremony resumed' >&2; exit 65; }
    run_post_platform "$phase"
    exit $?
  fi
  if [ "$phase" = infrastructure ]; then
    "$release" deploy apply --bundle-root "$bundle_root" --inputs "$inputs" --work-dir "$work" --private-eks-session-handoff "$session" --allow-create
    python3 "$resume_helper" phase --work-dir "$WORK_DIR" --manifest "$bundle_root/bundle-manifest.json" --phase infrastructure-complete || { printf '%s\n' 'infrastructure apply outcome is uncertain; do not retry automatically' >&2; exit 70; }
    phase=infrastructure-complete
  fi
  if [ "$phase" = platform-complete ]; then
    printf '%s\n' 'PASS: platform-only recovery was already complete; custody and activation were not replayed.' >&2
    exit 0
  fi
  if [ "$phase" = platform-started ]; then
    replay_helper="$source_root/scripts/release/platform_bootstrap_replay.py"
    [ -x "$replay_helper" ] || { printf '%s\n' 'platform-started recovery lacks its durable replay helper; refusing blind restart' >&2; exit 65; }
    python3 "$replay_helper" phase --work-dir "$work" --phase revoke_complete --action get >/dev/null || { printf '%s\n' 'platform-started receipt has no valid bound replay checkpoint; refusing blind restart' >&2; exit 65; }
  elif [ "$phase" = infrastructure-complete ]; then
    python3 "$resume_helper" phase --work-dir "$WORK_DIR" --manifest "$bundle_root/bundle-manifest.json" --phase platform-started || { printf '%s\n' 'platform start checkpoint is uncertain; platform was not invoked' >&2; exit 70; }
  else
    printf '%s\n' 'resume phase is not eligible for platform recovery' >&2; exit 65
  fi
  run_platform_bootstrap "$work" "$inputs" "$session" || exit $?
  python3 "$resume_helper" phase --work-dir "$WORK_DIR" --manifest "$bundle_root/bundle-manifest.json" --phase platform-complete || { printf '%s\n' 'platform completion checkpoint is uncertain; do not continue to ceremonies' >&2; exit 70; }
  printf '%s\n' 'PASS: platform-only recovery completed. Vault initialization, custody, keys, deposit, and activation were not replayed.' >&2
  exit 0
fi

[ -t 0 ] && [ -t 1 ] || { printf '%s\n' 'execute mode requires an interactive terminal' >&2; exit 69; }

step 'Deriving deployment context'
region="$DEFAULT_REGION"; account="$(jq -er '.aws_account_id' <<<"$runtime_defaults")"; identity="$(jq -c '{Arn: .caller_arn}' <<<"$runtime_defaults")"
export AWS_PROFILE="$(jq -er '.aws_profile' <<<"$runtime_defaults")" AWS_REGION="$region" AWS_DEFAULT_REGION="$region"
unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AWS_SECURITY_TOKEN AWS_WEB_IDENTITY_TOKEN_FILE AWS_ROLE_ARN AWS_ROLE_SESSION_NAME
validator_set="$DEFAULT_VALIDATOR_SET"; deployment_name="$DEFAULT_DEPLOYMENT_NAME"
[[ "$deployment_name" =~ ^[a-z][a-z0-9-]{1,18}[a-z0-9]$ ]] || { printf '%s\n' 'generated deployment name is invalid' >&2; exit 65; }
withdrawal="$(prompt 'Enter user-owned withdrawal address (0x...)')"
withdrawal_confirmation="$(prompt 'Re-enter the withdrawal address to confirm custody')"
[ "$withdrawal" = "$withdrawal_confirmation" ] && [[ "$withdrawal" =~ ^0x[0-9a-fA-F]{40}$ ]] || { printf '%s\n' 'withdrawal address confirmation did not match a valid address' >&2; exit 64; }
audit_replica_region=ap-northeast-1; [ "$region" = ap-northeast-1 ] && audit_replica_region=ap-northeast-2
printf 'Deployment context: account=%s primary=%s audit-replica=%s name=%s repository=%s\n' "$account" "$region" "$audit_replica_region" "$deployment_name" "$DEFAULT_GITHUB_REPOSITORY" >&2
load_authorized_artifacts || exit $?
printf 'Using canonical release-authorized artifacts:\n  Web3Signer %s\n  PostgreSQL %s\n  Prysm %s\n  Fence %s\n' "$(display_digest "$web3signer_image")" "$(display_digest "$postgres_image")" "$(display_digest "$prysm_image")" "$(display_digest "$fence_image")" >&2
# A shared default role would tie independent deployments to the lifecycle of
# whichever deployment first created it. Explicit external role ARNs remain
# supported, but are never retagged or claimed by this installer.
backend_role_explicit=false
[ -z "$DEFAULT_BACKEND_PRINCIPAL_ARN" ] || backend_role_explicit=true
DEFAULT_BACKEND_PRINCIPAL_ARN="${DEFAULT_BACKEND_PRINCIPAL_ARN:-arn:aws:iam::${account}:role/${deployment_name}-${region}-tfstate}"
if [ -n "$DEFAULT_BACKEND_PRINCIPAL_ARN" ]; then
  case "$DEFAULT_BACKEND_PRINCIPAL_ARN" in
    "arn:aws:iam::${account}:role/"*) ;;
    *) printf '%s\n' 'BACKEND_PRINCIPAL_ARN must be a same-account IAM role ARN' >&2; exit 65 ;;
  esac
  backend_role_name="${DEFAULT_BACKEND_PRINCIPAL_ARN##*/}"
  backend_role_created=false
  backend_role_managed=false
  if backend_role_lookup="$(aws iam get-role --role-name "$backend_role_name" --query 'Role.Arn' --output text 2>&1)"; then
    [ "$backend_role_lookup" = "$DEFAULT_BACKEND_PRINCIPAL_ARN" ] || { printf '%s\n' 'existing backend role ARN differs from configured identity' >&2; exit 65; }
    if [ "$backend_role_explicit" = false ]; then
      # A coincidentally matching name is not authorization to grant another
      # deployment's IAM role access to this new state backend.
      aws iam list-role-tags --role-name "$backend_role_name" --output json |
        jq -e --arg deployment "$deployment_name" --arg region "$region" '
          (.Tags | map({key: .Key, value: .Value}) | from_entries) |
          .Project == "node-operator" and .Deployment == $deployment and
          .DeploymentRegion == $region and
          (.ManagedBy == "terraform" or .ManagedBy == "node-operator-installer")
        ' >/dev/null || { printf '%s\n' 'default backend role name is already owned elsewhere; provide an explicitly reviewed BACKEND_PRINCIPAL_ARN or use a new deployment name' >&2; exit 65; }
      backend_role_managed=true
    fi
  elif [[ "$backend_role_lookup" == *'(NoSuchEntity)'* ]]; then
    printf 'Provisioning temporary Terraform backend role: %s\n' "$DEFAULT_BACKEND_PRINCIPAL_ARN" >&2
    caller_arn="$(jq -er '.Arn' <<<"$identity")"
    case "$caller_arn" in
      arn:aws:iam::${account}:user/*) trust_principal="$caller_arn" ;;
      arn:aws:sts::${account}:assumed-role/*/*) trust_principal="arn:aws:iam::${account}:role/${caller_arn#arn:aws:sts::${account}:assumed-role/}"; trust_principal="${trust_principal%/*}" ;;
      *) printf '%s\n' 'current AWS identity cannot be used as a backend-role trust principal' >&2; exit 65 ;;
    esac
    trust_document="$(jq -cn --arg principal "$trust_principal" '{Version:"2012-10-17",Statement:[{Sid:"AllowInteractiveBootstrapCaller",Effect:"Allow",Principal:{AWS:$principal},Action:"sts:AssumeRole"}]}')"
    aws iam create-role --role-name "$backend_role_name" --assume-role-policy-document "$trust_document" --description 'Node Operator Terraform bootstrap state access' \
      --max-session-duration 3600 --tags Key=Project,Value=node-operator "Key=Deployment,Value=$deployment_name" "Key=DeploymentRegion,Value=$region" Key=ManagedBy,Value=node-operator-installer Key=TemporaryBackend,Value=true >/dev/null
    backend_role_created=true
    backend_role_managed=true
    printf 'Created backend role %s with trust restricted to the current AWS identity.\n' "$backend_role_name" >&2
  else
    printf '%s\n' 'cannot inspect backend role; discovery failure is not an absent role' >&2
    exit 69
  fi
fi
# The signing-fence policy targets the private EKS API endpoint, which does not
# exist until foundation/EKS creation. A guarded deploy step replaces this
# staging sentinel with the endpoint's resolved private IPv4 before any
# validator manifest is applied.
api_cidr='127.0.0.1/32'
if [ -n "${NODE_OPERATOR_SOURCE_REPOSITORY_ROOT:-}" ]; then
  default_output_dir="${NODE_OPERATOR_RUNS_DIR:-$HOME/node-operator-runs}/node-operator-run-$(date -u +%Y%m%dT%H%M%SZ)"
else
  default_output_dir="${PWD}/node-operator-run-$(date -u +%Y%m%dT%H%M%SZ)"
fi
output_dir="$default_output_dir"
absolute_new_dir "$output_dir"
protected_repository_root="${NODE_OPERATOR_SOURCE_REPOSITORY_ROOT:-}"
if [ -n "$protected_repository_root" ]; then
  protected_repository_root="$(cd "$protected_repository_root" && pwd -P)"
  case "$output_dir" in
    "$protected_repository_root"|"$protected_repository_root"/*) printf '%s\n' 'working directory must be outside the source repository' >&2; exit 64 ;;
  esac
fi
mkdir -m 700 "$output_dir"
init_diagnostics "$output_dir" fresh || exit $?
trap 'diagnostic_failed "$?" "$LINENO"' ERR
trap 'status=$?; diagnostic_finish "$status"; unset confirmation validator_key expected_key withdrawal web3signer_image postgres_image prysm_image fence_image ecr_auth source_image; rm -f "$output_dir/.interactive-inputs.tmp" 2>/dev/null || true; exit "$status"' EXIT

step 'Preparing and validating validator key'
printf '%s\n' 'Existing key is reused when configured; otherwise a new Hoodi ceremony runs.' >&2
mkdir -m 700 "$output_dir/custody"
keystore_dir_for_custody="$output_dir/custody/validator_keys"
existing_keystore_dir="$DEFAULT_KEYSTORE_DIR"
if [ -z "$existing_keystore_dir" ]; then
  existing_keystore_dir="$(prompt_default 'Existing validator keystore directory (blank to generate a new key)' '')"
fi
if [ -n "$existing_keystore_dir" ]; then
  case "$existing_keystore_dir" in /*) ;; *) printf '%s\n' 'existing keystore directory must be absolute' >&2; exit 64 ;; esac
  [ -d "$existing_keystore_dir" ] && [ ! -L "$existing_keystore_dir" ] || { printf '%s\n' 'existing keystore directory must be a real directory' >&2; exit 65; }
  existing_keystore_dir="$(cd "$existing_keystore_dir" && pwd -P)"
  if [ -n "$protected_repository_root" ]; then
    case "$existing_keystore_dir" in
      "$protected_repository_root"|"$protected_repository_root"/*) printf '%s\n' 'existing keystore directory must be outside the source repository' >&2; exit 64 ;;
    esac
  fi
  existing_keystore="$(find "$existing_keystore_dir" -maxdepth 1 -type f -name 'keystore-*.json' -print)"
  existing_deposit="$(find "$existing_keystore_dir" -maxdepth 1 -type f -name 'deposit_data-*.json' -print)"
  [ "$(printf '%s\n' "$existing_keystore" | sed '/^$/d' | wc -l | tr -d ' ')" = 1 ] || { printf '%s\n' 'existing keystore directory must contain exactly one keystore-*.json' >&2; exit 65; }
  [ "$(printf '%s\n' "$existing_deposit" | sed '/^$/d' | wc -l | tr -d ' ')" = 1 ] || { printf '%s\n' 'existing keystore directory must contain exactly one deposit_data-*.json' >&2; exit 65; }
  keystore_dir_for_custody="$existing_keystore_dir"
  deposit_data="$existing_deposit"
  printf '%s\n' 'Using the existing validator keystore; no private key material will be copied.' >&2
else
  HOODI_WITHDRAWAL_ADDRESS="$withdrawal" "$keystore" --output-dir "$output_dir/custody"
  deposit_data="$(find "$output_dir/custody" -maxdepth 2 -type f -name 'deposit_data-*.json' -print)"
  [ "$(printf '%s\n' "$deposit_data" | sed '/^$/d' | wc -l | tr -d ' ')" = 1 ] || { printf '%s\n' 'key ceremony did not produce exactly one deposit-data file' >&2; exit 65; }
  keystore_dir_for_custody="$output_dir/custody/validator_keys"
fi
mkdir -m 700 "$output_dir/custody/public-attestation"
"$deposit_validate" --deposit-data "$deposit_data" --withdrawal-address "$withdrawal" --output-dir "$output_dir/custody/public-attestation" >/dev/null
deposit_attestation="$output_dir/custody/public-attestation/uc-1-deposit-attestation.json"
validator_key="$(jq -er '.validator_public_key' "$deposit_attestation" | tr '[:upper:]' '[:lower:]')"
if [ -n "$DEFAULT_VALIDATOR_KEY" ]; then
  expected_key="$(printf '%s' "$DEFAULT_VALIDATOR_KEY" | tr '[:upper:]' '[:lower:]')"
  [ "$validator_key" = "$expected_key" ] || { printf '%s\n' 'generated validator public key does not match VALIDATOR_PUBLIC_KEY; refusing to continue' >&2; exit 65; }
fi
custody_key_guard="$source_root/scripts/ops/verify-custody-validator-key.py"
[ -x "$custody_key_guard" ] || { printf '%s\n' 'release bundle lacks the custody validator-key identity guard' >&2; exit 65; }
python3 "$custody_key_guard" --keystore-dir "$keystore_dir_for_custody" --expected-public-key "$validator_key" >/dev/null || {
  printf '%s\n' 'validator keystore metadata does not match the validated deposit public key' >&2; exit 65;
}

step 'Preparing offline custody verification before infrastructure and Vault ceremonies'
custody_runtime="$source_root/scripts/release/custody_verifier_runtime.py"
[ -f "$custody_runtime" ] && [ ! -L "$custody_runtime" ] || { printf '%s\n' 'release bundle lacks custody verifier runtime preparation' >&2; exit 65; }
python3 -I -B "$custody_runtime" prepare --work-dir "$output_dir" --bundle-root "$bundle_root" --expected-public-key "$validator_key" >/dev/null || {
  printf '%s\n' 'custody verifier preflight failed; infrastructure and Vault ceremonies were not started' >&2; exit 65;
}

# Hoodi registration is an operator-owned, on-chain action. The installer
# prepares and validates public deposit data but never handles a wallet,
# broadcasts a transaction, or accepts a private key. Keep this guidance next
# to the key ceremony so a fresh operator cannot mistake custody onboarding for
# testnet registration.
registration_timestamp="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
printf '\n%s╭────────────────────────────────────────────────────────────╮%s\n' "$ui_cyan" "$ui_reset" >&2
printf '%s│ HOODI TESTNET REGISTRATION  %s│%s\n' "$ui_cyan" "$registration_timestamp" "$ui_reset" >&2
printf '%s╰────────────────────────────────────────────────────────────╯%s\n' "$ui_cyan" "$ui_reset" >&2
if [ -n "$existing_keystore_dir" ]; then
  registration_evidence="$output_dir/custody/existing-hoodi-validator-registration.json"
  withdrawal_credentials="$(jq -er '.withdrawal_credentials' "$deposit_attestation" | tr '[:upper:]' '[:lower:]')"
  "$existing_validator_verify" --validator-public-key "$validator_key" --withdrawal-credentials "$withdrawal_credentials" --beacon-url "$DEFAULT_HOODI_PUBLIC_BEACON_URL" --output "$registration_evidence"
  printf '%s✓%s REGISTRATION_VERIFIED: existing Hoodi validator is finalized public registration evidence only; signing_allowed=false.\n' "$ui_green" "$ui_reset" >&2
  printf '   Evidence: %s\n' "$registration_evidence" >&2
  printf '%s\n' 'No deposit is requested for this existing key. Activation still requires the separate public deposit receipt, private Beacon, signer, and slashing-protection gates.' >&2
else
  printf '%s1.%s Review the public attestation: %s\n' "$ui_yellow" "$ui_reset" "$deposit_attestation" >&2
  printf '%s2.%s Open the official Hoodi Launchpad and upload the matching deposit_data JSON:\n' "$ui_yellow" "$ui_reset" >&2
  printf '   https://hoodi.launchpad.ethereum.org/\n' >&2
  printf '%s3.%s Confirm network=Hoodi, amount=32 HoodiETH, validator public key, and withdrawal credentials match the attestation.\n' "$ui_yellow" "$ui_reset" >&2
  printf '%s4.%s Connect your own Hoodi wallet and submit exactly one 32 HoodiETH deposit through the Launchpad.\n' "$ui_yellow" "$ui_reset" >&2
  printf '%s5.%s Save the mined transaction hash; it is required for public receipt verification before activation.\n' "$ui_yellow" "$ui_reset" >&2
  printf '%s!%s Do not paste mnemonics, keystore passwords, private keys, or wallet credentials into this shell, Git, CI, or Vault.\n' "$ui_red" "$ui_reset" >&2
  printf '   Deposit data directory: %s\n' "$(dirname "$deposit_data")" >&2
  printf '   Registration is intentionally manual and must be completed with your own Hoodi wallet.\n' >&2
while :; do
  registration_confirmation="$(prompt 'Have you completed and confirmed the 32 HoodiETH deposit? [yes/no]')"
  case "$(printf '%s' "$registration_confirmation" | tr '[:upper:]' '[:lower:]')" in
    yes|y|예|완료)
      printf '%s✓%s Hoodi deposit completion acknowledged; continuing to infrastructure and Vault setup.\n' "$ui_green" "$ui_reset" >&2
      break
      ;;
    no|n|'')
      printf '%s✖%s Hoodi registration not confirmed; stopping before infrastructure/Vault changes.\n' "$ui_red" "$ui_reset" >&2
      exit 0
      ;;
    *)
      printf '%s!%s Please answer yes or no.\n' "$ui_yellow" "$ui_reset" >&2
      ;;
  esac
done
fi

zones=()
while IFS= read -r zone; do
  [ -n "$zone" ] && zones+=("$zone")
done < <(aws ec2 describe-availability-zones --region "$region" --filters Name=state,Values=available --query 'AvailabilityZones[].ZoneName' --output text | tr '\t' '\n' | sort | sed -n '1,2p')
[ "${#zones[@]}" -eq 2 ] || { printf '%s\n' 'could not discover two available Availability Zones' >&2; exit 65; }
# AWS Config permits only one recorder and delivery channel per Region. Reuse
# an existing account-wide recorder rather than attempting a second one.  A
# failed or ambiguous read must not be treated as permission to create one.
discover_config_recorder_management() {
  local config_recorder_count
  if ! config_recorder_count="$(aws configservice describe-configuration-recorders --region "$region" --query 'length(ConfigurationRecorders)' --output text)"; then
    printf '%s\n' 'could not inspect the regional AWS Config recorder; refusing to assume it is absent' >&2
    return 69
  fi
  case "$config_recorder_count" in
    0) printf '%s\n' true ;;
    1) printf '%s\n' false ;;
    *)
      printf '%s\n' 'AWS Config recorder inventory was malformed or ambiguous; refusing to manage a recorder' >&2
      return 65
      ;;
  esac
}
manage_config_recorder="$(discover_config_recorder_management)" || exit $?
if [ "$manage_config_recorder" = false ]; then
  printf '%s\n' 'Reusing the existing regional AWS Config recorder; no duplicate recorder will be created.' >&2
fi
prepare_args=(--aws-account-id "$account" --aws-region "$region" --name "$deployment_name" --availability-zone "${zones[0]}" --availability-zone "${zones[1]}" --validator-set "$validator_set" --validator-public-key "$validator_key" --withdrawal-address "$withdrawal" --web3signer-image "$web3signer_image" --postgres-image "$postgres_image" --prysm-validator-image "$prysm_image" --signing-fence-image "$fence_image" --kubernetes-api-cidr "$api_cidr" --output-dir "$output_dir/inputs")
prepare_args+=(--audit-replica-region "$audit_replica_region")
for pair in "--github-repository:$DEFAULT_GITHUB_REPOSITORY" "--github-owner-id:$DEFAULT_GITHUB_OWNER_ID" "--github-repository-id:$DEFAULT_GITHUB_REPOSITORY_ID" "--gitops-client-github-repository:$DEFAULT_GITOPS_CLIENT_GITHUB_REPOSITORY" "--gitops-client-github-owner-id:$DEFAULT_GITOPS_CLIENT_GITHUB_OWNER_ID" "--gitops-client-github-repository-id:$DEFAULT_GITOPS_CLIENT_GITHUB_REPOSITORY_ID"; do key="${pair%%:*}"; value="${pair#*:}"; [ -z "$value" ] || prepare_args+=("$key" "$value"); done
prepare_args+=(--manage-config-recorder "$manage_config_recorder")
prepare_args+=(--ci-evidence-archive-retention-mode "$DEFAULT_CI_EVIDENCE_ARCHIVE_RETENTION_MODE")
# Bind workload log labels to this verified bundle, never a caller environment
# override or the unrelated HEAD of a local development checkout.
prepare_args+=(--release-revision "$release_revision")
[ -n "$DEFAULT_BACKEND_PRINCIPAL_ARN" ] && prepare_args+=(--backend-principal-arn "$DEFAULT_BACKEND_PRINCIPAL_ARN")
"$prepare" "${prepare_args[@]}"
inputs="$output_dir/inputs/hoodi-zero-release-inputs.json"
session="$output_dir/private-eks-session.json"
python3 "$resume_helper" record --work-dir "$output_dir" --manifest "$bundle_root/bundle-manifest.json" --account "$account" --region "$region" --deployment "$deployment_name" --inputs "$inputs" --work "$output_dir/deployment-work" --session "$session" || { printf '%s\n' 'could not record safe infrastructure recovery context' >&2; exit 65; }

step 'Applying zero-resource foundation and private EKS'
"$release" deploy apply --bundle-root "$bundle_root" --inputs "$inputs" --work-dir "$output_dir/deployment-work" --private-eks-session-handoff "$session" --allow-create
python3 "$resume_helper" phase --work-dir "$output_dir" --manifest "$bundle_root/bundle-manifest.json" --phase infrastructure-complete || { printf '%s\n' 'infrastructure completion checkpoint is uncertain; stop and reconcile this WORK_DIR' >&2; exit 70; }

if [ "${backend_role_managed:-false}" = true ]; then
  bootstrap_output="$output_dir/deployment-work/bootstrap-output.json"
  [ -f "$bootstrap_output" ] || { printf '%s\n' 'bootstrap did not emit state outputs for backend-role policy binding' >&2; exit 65; }
  backend_policy_file="$output_dir/backend-role-policy.json"
  jq -n \
    --arg bucket "$(jq -er '.bucket' "$bootstrap_output")" \
    --arg table "$(jq -er '.dynamodb_table' "$bootstrap_output")" \
    --arg kms "$(jq -er '.kms_key_id' "$bootstrap_output")" \
    --arg region "$region" --arg account "$account" \
    '{Version:"2012-10-17",Statement:[
      {Sid:"StateBucket",Effect:"Allow",Action:["s3:ListBucket"],Resource:("arn:aws:s3:::" + $bucket)},
      {Sid:"StateObjects",Effect:"Allow",Action:["s3:GetObject","s3:PutObject","s3:DeleteObject"],Resource:("arn:aws:s3:::" + $bucket + "/*")},
      {Sid:"StateLock",Effect:"Allow",Action:["dynamodb:DescribeTable","dynamodb:GetItem","dynamodb:PutItem","dynamodb:DeleteItem","dynamodb:UpdateItem"],Resource:("arn:aws:dynamodb:" + $region + ":" + $account + ":table/" + $table)},
      {Sid:"StateKey",Effect:"Allow",Action:["kms:Decrypt","kms:Encrypt","kms:ReEncrypt*","kms:GenerateDataKey","kms:DescribeKey"],Resource:$kms}
    ]}' > "$backend_policy_file"
  aws iam put-role-policy --role-name "$backend_role_name" --policy-name NodeOperatorBootstrapStateAccess --policy-document "file://$backend_policy_file"
  rm -f "$backend_policy_file"
  printf '%s\n' 'Bound least-privilege state access to the installer-owned backend role.' >&2
fi

step 'Publishing platform artifacts and bootstrapping GitOps/Vault'
python3 "$resume_helper" phase --work-dir "$output_dir" --manifest "$bundle_root/bundle-manifest.json" --phase platform-started || { printf '%s\n' 'platform start checkpoint is uncertain; platform was not invoked' >&2; exit 70; }
run_platform_bootstrap "$output_dir/deployment-work" "$inputs" "$session" || exit $?
python3 "$resume_helper" phase --work-dir "$output_dir" --manifest "$bundle_root/bundle-manifest.json" --phase platform-complete || { printf '%s\n' 'platform completion checkpoint is uncertain; do not continue to ceremonies' >&2; exit 70; }

python3 -I -B "$resume_helper" bind-continuation --work-dir "$output_dir" --manifest "$bundle_root/bundle-manifest.json" --keystore-dir "$keystore_dir_for_custody" --public-key "$validator_key" --deposit-attestation "$deposit_attestation" || {
  printf '%s\n' 'could not bind custody continuation to this deployment; no Vault ceremony started' >&2; exit 65;
}
run_post_platform
