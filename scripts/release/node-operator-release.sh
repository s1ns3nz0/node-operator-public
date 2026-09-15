#!/usr/bin/env bash
set -euo pipefail
set -E
umask 077

if [ -t 2 ]; then
  ui_reset=$'\033[0m'; ui_blue=$'\033[1;34m'; ui_green=$'\033[1;32m'; ui_red=$'\033[1;31m'; ui_yellow=$'\033[1;33m';
else
  ui_reset=''; ui_blue=''; ui_green=''; ui_red=''; ui_yellow=''
fi
release_stage='startup'; release_failed=0; release_last_command=''
trap 'release_last_command="$BASH_COMMAND"' DEBUG
release_stage() { release_stage="$1"; printf '\n%s▶ %s%s  %s%s%s\n' "$ui_blue" "$2" "$ui_reset" "$ui_blue" "$1" "$ui_reset" >&2; }
release_error() { rc=$?; release_failed=1; printf '%s✖ failed:%s stage=%s exit=%s\n  command: %s\n' "$ui_red" "$ui_reset" "$release_stage" "$rc" "$BASH_COMMAND" >&2; return "$rc"; }
trap release_error ERR
release_failure() {
  rc=$?
  [ "$rc" -eq 0 ] || [ "$release_failed" -eq 1 ] || printf '\n%s✖ RELEASE FAILED%s  %s (exit %s)\n  last command: %s\n' "$ui_red" "$ui_reset" "$release_stage" "$rc" "$release_last_command" >&2
}
trap release_failure EXIT

usage() {
  cat <<'USAGE'
usage:
  node-operator-release.sh verify --bundle-root DIRECTORY
  node-operator-release.sh bootstrap plan|apply --bundle-root DIRECTORY --config FILE
  node-operator-release.sh zero apply --bundle-root DIRECTORY \
    (--inputs FILE | --bootstrap-config FILE --foundation-config FILE --baseline-config FILE) \
    --work-dir EMPTY_ABSOLUTE_DIRECTORY
  node-operator-release.sh zero prepare-artifacts --bundle-root DIRECTORY --inputs FILE \
    --work-dir DIRECTORY [--include-publishers]
  node-operator-release.sh zero verify-recorder --bundle-root DIRECTORY --inputs FILE --work-dir DIRECTORY

`verify` validates every archived source/rendered file against bundle-manifest.json.
`bootstrap` preserves the existing non-secret baseline Terraform interface.
`zero apply` is the fresh-account infrastructure path: it creates and migrates
bootstrap state, applies foundation-network, and applies the baseline using the
foundation output. It does not create SSM operations access, initialize or
restore Vault, publish GitOps artifacts, read a Secret, or activate a validator.
`zero verify-recorder` only re-reads deployment-owned remote Terraform and AWS
Config state to authorize a same-directory recorder-management retry.
`zero prepare-artifacts` creates only the exact private ECR/KMS prerequisites
from the same remote baseline state before any foundation/VPC work. It does not
create network, EKS, or workload resources. With --include-publishers, the
reviewed deployment-scoped GitHub publisher roles and inline policies are also
prepared; their feature flags must be enabled in the supplied baseline inputs.
Run the default prerequisite pass first so repository ARNs are concrete before
the publisher pass. Both passes use the same remote baseline Terraform state.
USAGE
}

fail() { printf 'release bootstrap: %s\n' "$*" >&2; exit 1; }
require_command() { command -v "$1" >/dev/null 2>&1 || fail "required command is unavailable: $1"; }

command_name="${1:-}"
[ -n "$command_name" ] || { usage; exit 64; }
shift

bundle_root=""; config=""; operation=""
bootstrap_config=""; foundation_config=""; baseline_config=""; inputs=""; work_dir=""
include_publishers=false
while [ "$#" -gt 0 ]; do
  case "$1" in
    --bundle-root) bundle_root="${2:-}"; shift 2 ;;
    --config) config="${2:-}"; shift 2 ;;
    --bootstrap-config) bootstrap_config="${2:-}"; shift 2 ;;
    --foundation-config) foundation_config="${2:-}"; shift 2 ;;
    --baseline-config) baseline_config="${2:-}"; shift 2 ;;
    --inputs) inputs="${2:-}"; shift 2 ;;
    --work-dir) work_dir="${2:-}"; shift 2 ;;
    --include-publishers) include_publishers=true; shift ;;
    plan|apply|verify-recorder|prepare-artifacts) operation="$1"; shift ;;
    *) usage; fail "unsupported argument: $1" ;;
  esac
done

if [ "$include_publishers" = true ]; then
  [ "$command_name" = zero ] && [ "$operation" = prepare-artifacts ] || fail "--include-publishers requires zero prepare-artifacts"
fi

[ -n "$bundle_root" ] || fail "--bundle-root is required"
[ -d "$bundle_root/source" ] || fail "bundle root must contain source/"
[ -f "$bundle_root/bundle-manifest.json" ] || fail "bundle root must contain bundle-manifest.json"
require_command jq
require_command shasum
require_command grep

verify_bundle() {
  release_stage 'bundle verification' '1/4'
  local bad=0 path expected actual
  while IFS=$'\t' read -r path expected; do
    [ -f "$bundle_root/$path" ] || { printf 'missing archived path: %s\n' "$path" >&2; bad=1; continue; }
    actual="$(shasum -a 256 "$bundle_root/$path" | awk '{print $1}')"
    [ "$actual" = "$expected" ] || { printf 'digest mismatch: %s\n' "$path" >&2; bad=1; }
  done < <(jq -r '.entries[] | [.path, .sha256] | @tsv' "$bundle_root/bundle-manifest.json")
  [ "$bad" -eq 0 ] || fail "bundle verification failed"
  jq -e '.schema_version == "v1" and .network == "hoodi" and .client_chart == {name:"node-operator-client",version_pattern:"^0\\.1\\.[0-9]+$",immutable_digest_required:true} and (.bootstrap.forbidden_inputs | length > 0)' \
    "$bundle_root/source/release/hoodi-release-contract.json" >/dev/null || fail "release contract is invalid"
  printf 'PASS release bundle and Hoodi contract verified.\n'
}

reject_privileged_baseline_inputs() {
  local input="$1"
  if grep -E -n '^[[:space:]]*enable_temporary_ssm_ops_host[[:space:]]*=[[:space:]]*true([[:space:]]|$)' "$input" >/dev/null; then
    fail "SSM operations access belongs to the isolated ops-access command"
  fi
  if grep -E -n '^[[:space:]]*enable_(argocd|vault)_bootstrap_cluster_admin[[:space:]]*=[[:space:]]*true([[:space:]]|$)' "$input" >/dev/null; then
    fail "temporary cluster-admin bootstrap requires its separately approved phase"
  fi
}

require_nonsecret_file() {
  local input="$1"
  [ -f "$input" ] && [ ! -L "$input" ] || fail "configuration must name a regular non-secret file"
  if grep -E -n -i '(vault[_-]?token|recovery[_-]?key|mnemonic|keystore|private[_-]?key|secret[_-]?access[_-]?key|aws_secret_access_key)[[:space:]]*=' "$input" >/dev/null; then
    fail "configuration contains a prohibited credential field"
  fi
}

write_backend_config() {
  local backend_json="$1" state_key="$2" destination="$3"
  jq -er --arg key "$state_key" '
    .bucket as $bucket | .region as $region | .dynamodb_table as $table | .kms_key_id as $kms |
    [$bucket, $region, $table, $kms] | all(type == "string" and length > 0) and
    ($key | test("^node-operator/[a-z0-9][a-z0-9-]{0,62}/terraform\\.tfstate$"))
  ' "$backend_json" >/dev/null || fail "bootstrap output is not a complete backend contract"
  jq -r --arg key "$state_key" '
    "bucket = \"\(.bucket)\"\n" + "key = \"\($key)\"\n" +
    "region = \"\(.region)\"\n" + "dynamodb_table = \"\(.dynamodb_table)\"\n" +
    "encrypt = true\n" + "kms_key_id = \"\(.kms_key_id)\"\n"
  ' "$backend_json" > "$destination"
  chmod 600 "$destination"
}

write_bootstrap_backend_config() {
  local bucket="$1" table="$2" region="$3" destination="$4"
  printf 'bucket = "%s"\nkey = "node-operator/bootstrap-state/terraform.tfstate"\nregion = "%s"\ndynamodb_table = "%s"\nencrypt = true\n' "$bucket" "$region" "$table" > "$destination"
  chmod 600 "$destination"
}

bootstrap_remote_state_exists() {
  local bucket="$1" region="$2"
  # list-buckets is the authoritative own-bucket check; do not turn a 403 or
  # a service failure from head-bucket into a fresh bootstrap decision.
  local bucket_inventory
  bucket_inventory="$(aws s3api list-buckets --output json)" || return 2
  if jq -e --arg bucket "$bucket" 'any(.Buckets[]?; .Name == $bucket)' <<<"$bucket_inventory" >/dev/null; then :; else
    local inventory_status=$?
    [ "$inventory_status" -eq 1 ] && return 1
    return 2
  fi
  local objects
  objects="$(aws s3api list-objects-v2 --region "$region" --bucket "$bucket" --prefix 'node-operator/bootstrap-state/terraform.tfstate' --output json)" || return 2
  if jq -e 'any(.Contents[]?; .Key == "node-operator/bootstrap-state/terraform.tfstate")' <<<"$objects" >/dev/null; then
    return 0
  else
    local object_status=$?
    [ "$object_status" -eq 1 ] && return 1
    return 2
  fi
}

bootstrap_has_local_state() {
  local module="$1"
  local local_state="$module/terraform.tfstate"
  [ -e "$local_state" ] || return 1
  [ -f "$local_state" ] && [ ! -L "$local_state" ] || return 2
  if ! jq -e 'type == "object" and (.resources | type == "array")' "$local_state" >/dev/null; then
    return 2
  fi
  jq -e '.resources | length > 0' "$local_state" >/dev/null || return 1
}

validate_bootstrap_plan() {
  local plan_file="$1" plan_json="$2"
  terraform -chdir="$bootstrap_module" show -json "$plan_file" > "$plan_json"
  chmod 600 "$plan_json"
  jq -e '
    (.configuration.root_module.resources | type == "array") and
    ([.configuration.root_module.resources[]?.address] | unique) as $allowed |
    all(.resource_changes[]?;
      (.address as $address | ($allowed | index($address)) != null) and
      all(.change.actions[]?; . != "delete")
    )
  ' "$plan_json" >/dev/null || fail "bootstrap plan contains a destructive action or a resource outside the bundled module"
}

copy_module() {
  local relative="$1" destination="$2"
  [ -d "$bundle_root/source/$relative" ] || fail "release bundle is missing $relative"
  [ ! -L "$destination" ] || fail "release module destination must not be a symlink"
  if [ -e "$destination" ]; then
    [ -d "$destination" ] || fail "release module destination must be a directory"
  else
    mkdir -p "$destination"; chmod 700 "$destination"
  fi
  guard_module_source_targets "$destination"
  # A checkpoint can be resumed with a newer verified bundle. Copy the module
  # contents, rather than the directory itself, so referenced non-Terraform
  # policy assets land at the module root and Terraform's local data remains.
  cp -R "$bundle_root/source/$relative/." "$destination"
}

guard_checkpoint_file() {
  local path="$1"
  [ ! -L "$path" ] || fail "checkpoint file must not be a symlink: $path"
}

guard_module_source_targets() {
  local destination="$1" unsafe_path
  # Terraform's provider cache is owned by Terraform. Every other entry is a
  # bundle source overwrite target and must not redirect a resumed copy.
  unsafe_path="$(find "$destination" -path "$destination/.terraform" -prune -o -type l -print -quit)"
  [ -z "$unsafe_path" ] || fail "release module source target must not contain symlinks: $unsafe_path"
}

validate_phase_plan() {
  local module="$1" plan_file="$2" plan_json="${2}.json"
  terraform -chdir="$module" show -json "$plan_file" > "$plan_json"
  chmod 600 "$plan_json"
  jq -e '
    def base: sub("\\[[^]]+\\]$"; "");
    ([.configuration.root_module.resources[]?.address | base] | unique) as $allowed |
    all(.resource_changes[]?;
      (.address | base) as $address | ($allowed | index($address)) != null and
      all(.change.actions[]?; . != "delete")
    )
  ' "$plan_json" >/dev/null || fail "ordinary resume plan contains a destructive action, replacement, or an unexpected resource"
}

apply_phase() {
  local module="$1" phase_config="$2" backend_config="$3" plan_file="$4"
  local apply_log apply_rc
  [ ! -L "$plan_file" ] || fail "checkpoint file must not be a symlink: $plan_file"
  [ ! -L "${plan_file}.json" ] || fail "checkpoint file must not be a symlink: ${plan_file}.json"
  terraform -chdir="$module" init -input=false -reconfigure -backend-config="$backend_config"
  terraform -chdir="$module" plan -input=false -var-file="$phase_config" -out="$plan_file"
  validate_phase_plan "$module" "$plan_file"
  # /private/tmp is a macOS-only spelling; use the portable temporary base
  # while retaining mktemp's private, collision-resistant apply log.
  apply_log="$(mktemp "${TMPDIR:-/tmp}/node-operator-terraform-apply.XXXXXX")"
  if terraform -chdir="$module" apply -input=false "$plan_file" 2>&1 | tee "$apply_log"; then
    unlink "$apply_log"
    return 0
  else
    apply_rc=${PIPESTATUS[0]}
  fi
  # EKS can briefly report ResourceNotFound for Pod Identity associations
  # immediately after the control plane becomes ACTIVE. Re-plan once after a
  # bounded delay so the release does not strand a partially created baseline.
  if grep -q 'No cluster found for name:' "$apply_log"; then
    printf '[terraform] EKS control plane propagation delay detected; waiting 30s and retrying %s apply.\n' "$module" >&2
    sleep 30
    terraform -chdir="$module" plan -input=false -var-file="$phase_config" -out="$plan_file"
    validate_phase_plan "$module" "$plan_file"
    terraform -chdir="$module" apply -input=false "$plan_file"
    unlink "$apply_log"
    return 0
  fi
  unlink "$apply_log"
  return "$apply_rc"
}

zero_prepare_artifacts_phase() {
  local bootstrap_output="$1" account="$2" region="$3" deployment_name="$4" fingerprint="$5"
  local artifacts_module="$work_dir/baseline-artifacts" artifacts_backend="$work_dir/baseline-artifacts.backend.hcl"
  local artifacts_plan="$work_dir/baseline-artifacts.tfplan" artifacts_plan_json="$work_dir/baseline-artifacts-plan.json" artifacts_state="$work_dir/baseline-artifacts-state.json"
  local artifacts_projection="$work_dir/artifact-prerequisites.json"
  local artifact_helper="$bundle_root/source/scripts/release/installer_artifact_prerequisites.py"
  local -a artifact_targets=(
    -target=aws_iam_role.kms_administrator
    -target=aws_ecr_repository.private_gitops
    -target=aws_ecr_lifecycle_policy.private_gitops
    -target=aws_ecr_repository.gitops_client
    -target=aws_ecr_repository.gitops_client_chart
    -target=aws_ecr_lifecycle_policy.gitops_client
    -target=aws_ecr_lifecycle_policy.gitops_client_chart
    -target=aws_kms_key.validator_runtime_ecr
    -target=aws_ecr_repository.validator_runtime
    -target=aws_kms_key.validator_client_ecr
    -target=aws_ecr_repository.validator_client
    -target=aws_ecr_repository.validator_signing_fence
    -target=aws_ecr_repository.validator_signer_identity_probe
    -target=aws_kms_key.validator_log_collector_ecr
    -target=aws_ecr_repository.validator_log_collector
    -target=aws_kms_key.vault_audit_relay_ecr
    -target=aws_ecr_repository.vault_audit_relay
  )
  local -a publisher_validation_args=(--account "$account" --region "$region" --name "$deployment_name")
  if [ "$include_publishers" = true ]; then
    local github_repository github_owner_id github_repository_id gitops_repository gitops_owner_id gitops_repository_id
    github_repository="$(jq -er '.github_repository | select(test("^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$"))' "$baseline_config")" || fail "baseline config lacks an exact operator GitHub repository"
    github_owner_id="$(jq -er '.github_owner_id | select(test("^[1-9][0-9]*$"))' "$baseline_config")" || fail "baseline config lacks an exact operator GitHub owner ID"
    github_repository_id="$(jq -er '.github_repository_id | select(test("^[1-9][0-9]*$"))' "$baseline_config")" || fail "baseline config lacks an exact operator GitHub repository ID"
    gitops_repository="$(jq -er '.gitops_client_github_repository | select(test("^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$"))' "$baseline_config")" || fail "baseline config lacks an exact GitOps repository"
    gitops_owner_id="$(jq -er '.gitops_client_github_owner_id | select(test("^[1-9][0-9]*$"))' "$baseline_config")" || fail "baseline config lacks an exact GitOps owner ID"
    gitops_repository_id="$(jq -er '.gitops_client_github_repository_id | select(test("^[1-9][0-9]*$"))' "$baseline_config")" || fail "baseline config lacks an exact GitOps repository ID"
    publisher_validation_args+=(--include-publishers)
    publisher_validation_args+=(--github-repository "$github_repository" --github-owner-id "$github_owner_id" --github-repository-id "$github_repository_id")
    publisher_validation_args+=(--gitops-client-github-repository "$gitops_repository" --gitops-client-github-owner-id "$gitops_owner_id" --gitops-client-github-repository-id "$gitops_repository_id")
    artifact_targets+=(
      -target=aws_iam_role.github_validator_client_mirror
      -target=aws_iam_role_policy.github_validator_client_mirror
      -target=aws_iam_role_policy.github_validator_signer_identity_probe_mirror
      -target=aws_iam_role.github_validator_log_collector_mirror
      -target=aws_iam_role_policy.github_validator_log_collector_mirror
      -target=aws_iam_role.github_vault_audit_relay_publisher
      -target=aws_iam_role_policy.github_vault_audit_relay_publisher
      -target=aws_iam_role.github_gitops_client_ecr_publisher
      -target=aws_iam_role_policy.github_gitops_client_ecr_publisher
    )
  fi

  [ -f "$artifact_helper" ] && [ ! -L "$artifact_helper" ] || fail "release bundle is missing a safe artifact prerequisite validator"
  for checkpoint_file in "$artifacts_backend" "$artifacts_plan" "$artifacts_plan_json" "$artifacts_state" "$artifacts_projection"; do
    guard_checkpoint_file "$checkpoint_file"
  done
  copy_module infra/terraform "$artifacts_module"
  for gitops_input in argocd-private-values.example.yaml cert-manager-values.example.yaml vault-tls-internal-ca.example.yaml; do
    [ -f "$bundle_root/source/docs/gitops/$gitops_input" ] || fail "release bundle is missing docs/gitops/$gitops_input"
    guard_checkpoint_file "$artifacts_module/$gitops_input"
    cp "$bundle_root/source/docs/gitops/$gitops_input" "$artifacts_module/$gitops_input"
    chmod 600 "$artifacts_module/$gitops_input"
  done
  write_backend_config "$bootstrap_output" "node-operator/baseline/terraform.tfstate" "$artifacts_backend"
  release_stage 'zero-resource artifact prerequisites' '3/4'
  terraform -chdir="$artifacts_module" init -input=false -reconfigure -backend-config="$artifacts_backend"
  terraform -chdir="$artifacts_module" plan -input=false -var-file="$baseline_config" "${artifact_targets[@]}" -out="$artifacts_plan"
  (
    trap 'rm -f "$artifacts_plan_json"' EXIT
    terraform -chdir="$artifacts_module" show -json "$artifacts_plan" > "$artifacts_plan_json"
    chmod 600 "$artifacts_plan_json"
    python3 "$artifact_helper" plan --plan "$artifacts_plan_json" "${publisher_validation_args[@]}"
  )
  terraform -chdir="$artifacts_module" apply -input=false "$artifacts_plan"
  (
    trap 'rm -f "$artifacts_state"' EXIT
    terraform -chdir="$artifacts_module" show -json > "$artifacts_state"
    chmod 600 "$artifacts_state"
    python3 "$artifact_helper" state --state "$artifacts_state" --fingerprint "$fingerprint" --output "$artifacts_projection" "${publisher_validation_args[@]}"
  )
  printf 'PASS zero-resource artifact prerequisites completed. Projection: %s\n' "$artifacts_projection"
}

zero_apply() {
  release_stage 'zero-resource bootstrap' '2/4'
  if [ -n "$inputs" ]; then
    [ -z "$bootstrap_config$foundation_config$baseline_config" ] || fail "--inputs cannot be combined with individual phase configs"
    case "$inputs" in /*) ;; *) fail "--inputs must be an absolute path" ;; esac
    [ -f "$inputs" ] && [ ! -L "$inputs" ] || fail "--inputs must name a regular file"
    local input_parent expected_bootstrap expected_foundation expected_baseline
    # Preserve the path spelling recorded by the zero-resource handoff. On
    # macOS /var is an alias of /private/var; canonicalizing here breaks the
    # contract's exact path bindings even when every file exists.
    input_parent="$(dirname "$inputs")"
    expected_bootstrap="$input_parent/bootstrap-state.tfvars.json"
    expected_foundation="$input_parent/foundation-network.tfvars.json"
    expected_baseline="$input_parent/baseline.tfvars.json"
    jq -e --arg bootstrap "$expected_bootstrap" --arg foundation "$expected_foundation" --arg baseline "$expected_baseline" '
      .schema_version == 1 and (.aws_account_id | test("^[0-9]{12}$")) and
      (.aws_region | test("^[a-z]{2}-[a-z0-9-]+-[0-9]+$")) and
      .bootstrap_config == $bootstrap and .foundation_config == $foundation and .baseline_config == $baseline
    ' "$inputs" >/dev/null || fail "--inputs is not a bounded zero-resource input contract"
    bootstrap_config="$expected_bootstrap"; foundation_config="$expected_foundation"; baseline_config="$expected_baseline"
  fi
  [ -n "$bootstrap_config" ] && [ -n "$foundation_config" ] && [ -n "$baseline_config" ] || fail "zero apply requires --inputs or all three phase configs"
  case "$work_dir" in /*) ;; *) fail "--work-dir must be an absolute directory" ;; esac
  [ ! -L "$work_dir" ] || fail "--work-dir must not be a symlink"
  if [ -e "$work_dir" ]; then
    [ -d "$work_dir" ] || fail "--work-dir must be a directory"
  else
    mkdir -p "$work_dir"; chmod 700 "$work_dir"
  fi
  require_command terraform
  require_command aws
  require_nonsecret_file "$bootstrap_config"; require_nonsecret_file "$foundation_config"; require_nonsecret_file "$baseline_config"
  reject_privileged_baseline_inputs "$baseline_config"
  configured_bootstrap_account="$(jq -er '.aws_account_id' "$bootstrap_config")"
  configured_deployment_name="$(jq -er '.name' "$bootstrap_config")"
  configured_region="$(jq -er '.aws_region' "$foundation_config")"
  jq -e --arg region "$configured_region" '.aws_region == $region' "$bootstrap_config" >/dev/null || fail "bootstrap configuration does not bind the foundation region"
  jq -e --arg account "$configured_bootstrap_account" --arg name "$configured_deployment_name" --arg region "$configured_region" '
    .aws_account_id == $account and .name == $name and .aws_region == $region
  ' "$baseline_config" >/dev/null || fail "baseline configuration does not bind the bootstrap account, deployment, and region"
  jq -e --arg name "$configured_deployment_name" --arg region "$configured_region" '
    .name == $name and .aws_region == $region
  ' "$foundation_config" >/dev/null || fail "foundation configuration does not bind the bootstrap deployment and region"
  checkpoint_binding="$work_dir/zero-inputs.sha256"
  # Hash only the ordered content digests. Bundle extraction paths are ephemeral
  # and must not invalidate a same-bundle resume in an existing work directory.
  checkpoint_fingerprint="$(shasum -a 256 "$bootstrap_config" "$foundation_config" "$baseline_config" "$bundle_root/bundle-manifest.json" | awk '{print $1}' | shasum -a 256 | awk '{print $1}')"
  if [ -e "$checkpoint_binding" ] || [ -L "$checkpoint_binding" ]; then
    [ -f "$checkpoint_binding" ] && [ ! -L "$checkpoint_binding" ] || fail "zero-resource checkpoint binding is unsafe"
    [ "$(<"$checkpoint_binding")" = "$checkpoint_fingerprint" ] || fail "zero-resource inputs differ from the existing checkpoint"
  else
    [ -z "$(find "$work_dir" -mindepth 1 -maxdepth 1 -print -quit)" ] || fail "nonempty work directory lacks a zero-resource checkpoint binding"
    printf '%s' "$checkpoint_fingerprint" > "$checkpoint_binding"
    chmod 600 "$checkpoint_binding"
  fi
  caller_bootstrap_account="$(aws sts get-caller-identity --output json | jq -er '.Account')" || fail "unable to determine the AWS caller account"
  [ "$caller_bootstrap_account" = "$configured_bootstrap_account" ] || fail "AWS caller account does not match bootstrap configuration"
  if grep -E -n '^[[:space:]]*(network_source|foundation_network|hoodi_nat_gateway_id)[[:space:]]*=' "$baseline_config" >/dev/null; then
    fail "zero apply derives foundation network inputs; remove network_source, foundation_network, and hoodi_nat_gateway_id from --baseline-config"
  fi

  local bootstrap_module="$work_dir/bootstrap-state" foundation_module="$work_dir/foundation-network" baseline_module="$work_dir/baseline"
  local bootstrap_backend="$work_dir/bootstrap.backend.hcl" foundation_backend="$work_dir/foundation.backend.hcl" baseline_backend="$work_dir/baseline.backend.hcl"
  local bootstrap_output="$work_dir/bootstrap-output.json" foundation_output="$work_dir/foundation-output.json" foundation_input="$work_dir/foundation-network.auto.tfvars.json" baseline_output="$work_dir/baseline-output.json" gitops_handoff="$work_dir/gitops-publisher-handoff.json" ops_handoff="$work_dir/ops-access-handoff.json"

  for checkpoint_file in "$bootstrap_backend" "$foundation_backend" "$baseline_backend" "$bootstrap_output" "$foundation_output" "$baseline_output" "$foundation_input" "$gitops_handoff" "$ops_handoff" "$work_dir/bootstrap-live-output.json" "$work_dir/bootstrap-state-values.json" "$work_dir/bootstrap-imports.tsv" "$work_dir/bootstrap.tfplan" "$work_dir/bootstrap-plan.json" "$work_dir/foundation.tfplan" "$work_dir/foundation.tfplan.json" "$work_dir/baseline.tfplan" "$work_dir/baseline.tfplan.json"; do
    guard_checkpoint_file "$checkpoint_file"
  done
  state_bucket_name="$(jq -r '.state_bucket_name // empty' "$bootstrap_config")"
  [ -n "$state_bucket_name" ] || state_bucket_name="$configured_deployment_name-tfstate-$configured_bootstrap_account-$(printf '%s' "$configured_region" | tr -d '-')"
  state_log_suffix="$(printf '%s' "$state_bucket_name" | shasum -a 256 | awk '{print substr($1,1,8)}')"
  state_logs_bucket="${state_bucket_name:0:48}-${state_log_suffix}-logs"
  bootstrap_table_name="${configured_deployment_name}-terraform-lock"
  write_bootstrap_backend_config "$state_bucket_name" "$bootstrap_table_name" "$configured_region" "$bootstrap_backend"
  bootstrap_state_migration_required=0
  if [ ! -f "$bootstrap_output" ]; then
    if [ -e "$bootstrap_module" ]; then
      [ -d "$bootstrap_module" ] && [ ! -L "$bootstrap_module" ] || fail "incomplete bootstrap checkpoint has an unsafe module path"
    else
      copy_module infra/bootstrap-state "$bootstrap_module"
      # The bootstrap module creates the S3 backend itself. Terraform cannot
      # plan its first local apply while the backend block is active.
      mv "$bootstrap_module/versions.tf" "$bootstrap_module/versions.tf.disabled"
    fi
    # state_bucket_name is intentionally null for the generated deterministic
    # name. Do not use jq -e here: an empty optional result is not an error.
    bootstrap_region="$configured_region"
    printf '[bootstrap] Initializing Terraform provider...\n' >&2
    bootstrap_remote_state=0
    if bootstrap_remote_state_exists "$state_bucket_name" "$bootstrap_region"; then
      # Prove tag ownership before Terraform can connect to a deterministic
      # backend name. The helper only reads AWS and rejects foreign lookalikes.
      python3 "$bundle_root/source/scripts/release/reconcile-bootstrap-state.py" --region "$bootstrap_region" --account-id "$configured_bootstrap_account" --deployment "$configured_deployment_name" --bucket "$state_bucket_name" --logs-bucket "$state_logs_bucket" --table "$bootstrap_table_name" >/dev/null
      if bootstrap_has_local_state "$bootstrap_module"; then
        fail "ambiguous bootstrap checkpoint has both local and remote state"
      else
        bootstrap_local_state_status=$?
        [ "$bootstrap_local_state_status" -eq 1 ] || fail "bootstrap checkpoint has invalid local Terraform state"
      fi
      # A prior completed migration is authoritative. Reconfigure directly
      # against it; this is deliberately not another local-state migration.
      terraform -chdir="$bootstrap_module" init -input=false -reconfigure -backend-config="$bootstrap_backend"
      bootstrap_remote_state=1
    else
      bootstrap_state_probe_status=$?
      [ "$bootstrap_state_probe_status" -eq 1 ] || fail "unable to determine whether bootstrap remote state exists"
      terraform -chdir="$bootstrap_module" init -input=false -reconfigure -backend=false
      bootstrap_state_migration_required=1
    fi
    # A retry after interruption can import only exact, owned resource names.
    # The helper makes AWS reads explicit and rejects uncertain/error states.
    bootstrap_state_json="$work_dir/bootstrap-state-values.json"
    if ! terraform -chdir="$bootstrap_module" show -json > "$bootstrap_state_json"; then
      # A first-run local bootstrap has no state before the initial apply. It
      # has no resources to reconcile, so represent that explicit empty state
      # rather than treating Terraform's expected "no state" exit as fatal.
      [ "$bootstrap_state_migration_required" -eq 1 ] || fail "unable to read bootstrap Terraform state"
      printf '%s\n' '{"format_version":"1.0","values":{"root_module":null}}' > "$bootstrap_state_json"
    fi
    chmod 600 "$bootstrap_state_json"
    jq -e 'type == "object" and (.format_version | type == "string")' "$bootstrap_state_json" >/dev/null || fail "bootstrap Terraform state JSON is invalid"
    bootstrap_state_entries="$(jq -r '
      def resources: .resources[]?, (.child_modules[]? | resources);
      if .values.root_module? == null then empty
      else .values.root_module | resources | [.address, .values.id] | @tsv end
    ' "$bootstrap_state_json")" || fail "bootstrap Terraform state JSON is invalid"
    reconcile_imports="$work_dir/bootstrap-imports.tsv"
    reconcile_args=(--region "$bootstrap_region" --account-id "$(jq -er '.aws_account_id' "$bootstrap_config")" --deployment "$(jq -er '.name' "$bootstrap_config")" --bucket "$state_bucket_name" --logs-bucket "$state_logs_bucket" --table "$bootstrap_table_name")
    while IFS=$'\t' read -r address state_identifier; do
      [ -n "$address" ] || continue
      case "$address" in
        aws_s3_bucket.state|aws_s3_bucket.state_access_logs|aws_dynamodb_table.lock|aws_kms_key.state|aws_kms_alias.state) ;;
        *) continue ;;
      esac
      [ -n "$state_identifier" ] || fail "unable to read Terraform state identity for $address"
      reconcile_args+=(--state-address "$address" --state-id "$address=$state_identifier")
    done <<<"$bootstrap_state_entries"
    python3 "$bundle_root/source/scripts/release/reconcile-bootstrap-state.py" "${reconcile_args[@]}" > "$reconcile_imports"
    while IFS=$'\t' read -r address identifier; do
      [ -n "$address" ] || continue
      terraform -chdir="$bootstrap_module" import -input=false -var-file="$bootstrap_config" "$address" "$identifier"
    done < "$reconcile_imports"
    printf '[bootstrap] Planning state resources...\n' >&2
    guard_checkpoint_file "$work_dir/bootstrap.tfplan"
    guard_checkpoint_file "$work_dir/bootstrap-plan.json"
    terraform -chdir="$bootstrap_module" plan -input=false -var-file="$bootstrap_config" -out="$work_dir/bootstrap.tfplan"
    validate_bootstrap_plan "$work_dir/bootstrap.tfplan" "$work_dir/bootstrap-plan.json"
    printf '[bootstrap] Applying state resources...\n' >&2
    terraform -chdir="$bootstrap_module" apply -input=false "$work_dir/bootstrap.tfplan"
    terraform -chdir="$bootstrap_module" output -json backend > "$bootstrap_output"
  else
    [ -d "$bootstrap_module" ] && [ ! -L "$bootstrap_module" ] || fail "bootstrap checkpoint output has no safe module"
    copy_module infra/bootstrap-state "$bootstrap_module"
    if bootstrap_remote_state_exists "$state_bucket_name" "$configured_region"; then
      python3 "$bundle_root/source/scripts/release/reconcile-bootstrap-state.py" --region "$configured_region" --account-id "$configured_bootstrap_account" --deployment "$configured_deployment_name" --bucket "$state_bucket_name" --logs-bucket "$state_logs_bucket" --table "$bootstrap_table_name" >/dev/null
      terraform -chdir="$bootstrap_module" init -input=false -reconfigure -backend-config="$bootstrap_backend"
    else
      bootstrap_state_probe_status=$?
      [ "$bootstrap_state_probe_status" -eq 1 ] || fail "unable to determine whether bootstrap remote state exists"
      bootstrap_has_local_state "$bootstrap_module"
      bootstrap_local_state_status=$?
      [ "$bootstrap_local_state_status" -eq 0 ] || fail "bootstrap cached output has no usable local or remote state"
      terraform -chdir="$bootstrap_module" init -input=false -reconfigure -backend=false
      bootstrap_state_migration_required=1
    fi
    terraform -chdir="$bootstrap_module" output -json backend > "$work_dir/bootstrap-live-output.json" || fail "unable to read live bootstrap Terraform output"
    mv "$work_dir/bootstrap-live-output.json" "$bootstrap_output"
  fi
  jq -e --arg bucket "$state_bucket_name" --arg table "$bootstrap_table_name" --arg region "$configured_region" --arg account "$configured_bootstrap_account" '
    .bucket == $bucket and .dynamodb_table == $table and .region == $region and
    (.kms_key_id | type == "string" and test("^arn:aws:kms:" + $region + ":" + $account + ":key/[A-Za-z0-9-]+$"))
  ' "$bootstrap_output" >/dev/null || fail "live bootstrap output does not bind the configured backend identity"
  write_backend_config "$bootstrap_output" "node-operator/bootstrap-state/terraform.tfstate" "$bootstrap_backend"
  if [ "$bootstrap_state_migration_required" -eq 1 ]; then
    # Restore the backend block only after its bucket and lock table exist.
    [ -f "$bootstrap_module/versions.tf.disabled" ] && mv "$bootstrap_module/versions.tf.disabled" "$bootstrap_module/versions.tf"
    # Bootstrap begins in local state because the remote backend is being made.
    # Migration is explicit and never uses force-copy.
    terraform -chdir="$bootstrap_module" init -input=false -migrate-state -backend-config="$bootstrap_backend"
  fi

  if [ "$operation" = prepare-artifacts ]; then
    zero_prepare_artifacts_phase "$bootstrap_output" "$configured_bootstrap_account" "$configured_region" "$configured_deployment_name" "$checkpoint_fingerprint"
    return
  fi

  write_backend_config "$bootstrap_output" "node-operator/foundation-network/terraform.tfstate" "$foundation_backend"
  if [ -e "$foundation_module" ]; then
    [ -d "$foundation_module" ] && [ ! -L "$foundation_module" ] || fail "incomplete foundation checkpoint has an unsafe module path"
  fi
  copy_module infra/foundation-network "$foundation_module"
  apply_phase "$foundation_module" "$foundation_config" "$foundation_backend" "$work_dir/foundation.tfplan"
  terraform -chdir="$foundation_module" output -json network > "$foundation_output"
  jq -e 'type == "object" and (.vpc_id | test("^vpc-[0-9a-f]+$")) and (.vpc_cidr | type == "string") and (.system_subnet_ids | type == "array" and length >= 2) and (.hoodi_subnet_ids | type == "array" and length >= 1) and (.system_route_table_id | test("^rtb-[0-9a-f]+$")) and (.hoodi_route_table_id | test("^rtb-[0-9a-f]+$")) and (.hoodi_nat_gateway_id | test("^nat-[0-9a-f]+$")) and (.hoodi_nat_public_ip | test("^([0-9]{1,3}\\.){3}[0-9]{1,3}$"))' "$foundation_output" >/dev/null || fail "foundation output is not a usable zero-resource network contract"
  jq '{network_source:"foundation", foundation_network:{vpc_id:.vpc_id, vpc_cidr:.vpc_cidr, system_subnet_ids:.system_subnet_ids, hoodi_subnet_ids:.hoodi_subnet_ids, system_route_table_id:.system_route_table_id, hoodi_route_table_id:.hoodi_route_table_id, hoodi_nat_gateway_id:.hoodi_nat_gateway_id, hoodi_nat_public_ip:.hoodi_nat_public_ip}}' "$foundation_output" > "$foundation_input"
  chmod 600 "$foundation_input"

  copy_module infra/terraform "$baseline_module"
  # The Argo bootstrap buildspec may need reviewed non-secret values that are
  # not Terraform resources. Copy them beside the module so Terraform's
  # file() calls remain valid after the release bundle is staged in a clean
  # temporary work directory.
  for gitops_input in argocd-private-values.example.yaml cert-manager-values.example.yaml vault-tls-internal-ca.example.yaml; do
    [ -f "$bundle_root/source/docs/gitops/$gitops_input" ] || fail "release bundle is missing docs/gitops/$gitops_input"
    guard_checkpoint_file "$baseline_module/$gitops_input"
    cp "$bundle_root/source/docs/gitops/$gitops_input" "$baseline_module/$gitops_input"
    chmod 600 "$baseline_module/$gitops_input"
  done
  guard_checkpoint_file "$baseline_module/foundation-network.auto.tfvars.json"
  cp "$foundation_input" "$baseline_module/foundation-network.auto.tfvars.json"
  write_backend_config "$bootstrap_output" "node-operator/baseline/terraform.tfstate" "$baseline_backend"
  apply_phase "$baseline_module" "$baseline_config" "$baseline_backend" "$work_dir/baseline.tfplan"
  terraform -chdir="$baseline_module" output -json > "$baseline_output"
  deployment_region="$(jq -er '.aws_region' "$foundation_config")" || fail "foundation configuration lacks aws_region"
  jq -e --arg region "$deployment_region" '
    (.deployment_account_id.value | test("^[0-9]{12}$")) and
    (.cluster_name.value | test("^[a-z][a-z0-9-]{1,38}[a-z0-9]$")) and
    (.gitops_client_ecr_repository_url.value | test("^[0-9]{12}\\.dkr\\.ecr\\." + $region + "\\.amazonaws\\.com/[a-z0-9][a-z0-9._/-]*$")) and
    (.github_gitops_client_ecr_publisher_role_arn.value | test("^arn:aws:iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_-]+$"))
  ' "$baseline_output" >/dev/null || fail "baseline did not emit the required GitOps publisher handoff"
  jq --arg gitops_repository "$(jq -er '.gitops_client_github_repository | select(test("^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$"))' "$baseline_config")" '{schema_version:"v1",gitops_repository:$gitops_repository,publisher_environment:"gitops-client-ecr-publish",aws_account_id:.deployment_account_id.value,chart_repository:.gitops_client_ecr_repository_url.value,publisher_role_arn:.github_gitops_client_ecr_publisher_role_arn.value}' "$baseline_output" > "$gitops_handoff"
  jq --arg region "$deployment_region" --slurpfile foundation "$foundation_output" --slurpfile bootstrap "$bootstrap_output" '
    {schema_version:"v1",aws_region:$region,aws_account_id:.deployment_account_id.value,
     cluster_name:.cluster_name.value,
     vpc_id:$foundation[0].vpc_id,subnet_id:$foundation[0].system_subnet_ids[0],
     backend:{bucket:$bootstrap[0].bucket,dynamodb_table:$bootstrap[0].dynamodb_table,kms_key_id:$bootstrap[0].kms_key_id,region:$bootstrap[0].region,
       key:"node-operator/ops-access/terraform.tfstate"}}
  ' "$baseline_output" > "$ops_handoff"
  chmod 600 "$gitops_handoff" "$ops_handoff"
  printf 'PASS zero-resource infrastructure bootstrap completed. Configure the GitOps publisher from %s and prepare isolated SSM access from %s before Argo, Vault, and validator phases.\n' "$gitops_handoff" "$ops_handoff"
}

zero_verify_recorder() {
  [ -n "$inputs" ] && [ -n "$work_dir" ] || fail "zero verify-recorder requires --inputs and --work-dir"
  [ -f "$inputs" ] && [ ! -L "$inputs" ] || fail "recorder verification inputs are unsafe"
  [ -d "$work_dir" ] && [ ! -L "$work_dir" ] || fail "recorder verification work directory is unsafe"
  local parent bootstrap foundation baseline account region name bucket table logs suffix verify_dir bootstrap_module baseline_module bootstrap_backend baseline_backend backend state
  parent="$(dirname "$inputs")"; bootstrap="$parent/bootstrap-state.tfvars.json"; foundation="$parent/foundation-network.tfvars.json"; baseline="$parent/baseline.tfvars.json"
  require_nonsecret_file "$bootstrap"; require_nonsecret_file "$foundation"; require_nonsecret_file "$baseline"
  account="$(jq -er '.aws_account_id' "$bootstrap")"; name="$(jq -er '.name' "$bootstrap")"; region="$(jq -er '.aws_region' "$foundation")"
  jq -e --arg region "$region" '.aws_region == $region' "$bootstrap" >/dev/null || fail "recorder verification bootstrap region differs from foundation"
  jq -e --arg account "$account" --arg name "$name" --arg region "$region" '.aws_account_id == $account and .name == $name and .aws_region == $region and .manage_config_recorder == true' "$baseline" >/dev/null || fail "recorder verification inputs are not a managed deployment context"
  [ "$(aws sts get-caller-identity --output json | jq -er '.Account')" = "$account" ] || fail "recorder verification caller account differs"
  bucket="$(jq -r '.state_bucket_name // empty' "$bootstrap")"; [ -n "$bucket" ] || bucket="$name-tfstate-$account-$(printf '%s' "$region" | tr -d '-')"
  table="$name-terraform-lock"; suffix="$(printf '%s' "$bucket" | shasum -a 256 | awk '{print substr($1,1,8)}')"; logs="${bucket:0:48}-${suffix}-logs"
  bootstrap_remote_state_exists "$bucket" "$region" || fail "owned recorder verification requires an existing remote bootstrap state"
  python3 "$bundle_root/source/scripts/release/reconcile-bootstrap-state.py" --region "$region" --account-id "$account" --deployment "$name" --bucket "$bucket" --logs-bucket "$logs" --table "$table" >/dev/null
  verify_dir="$(mktemp -d "$work_dir/.recorder-state-verify.XXXXXX")"; chmod 700 "$verify_dir"
  bootstrap_module="$verify_dir/bootstrap"; baseline_module="$verify_dir/baseline"; bootstrap_backend="$verify_dir/bootstrap.hcl"; baseline_backend="$verify_dir/baseline.hcl"
  (
  trap 'rm -rf "$verify_dir"' EXIT
  copy_module infra/bootstrap-state "$bootstrap_module"; write_bootstrap_backend_config "$bucket" "$table" "$region" "$bootstrap_backend"
  terraform -chdir="$bootstrap_module" init -input=false -reconfigure -backend-config="$bootstrap_backend"
  terraform -chdir="$bootstrap_module" output -json backend > "$verify_dir/bootstrap-output.json"
  jq -e --arg bucket "$bucket" --arg table "$table" --arg region "$region" --arg account "$account" '.bucket == $bucket and .dynamodb_table == $table and .region == $region and (.kms_key_id | type == "string" and test("^arn:aws:kms:" + $region + ":" + $account + ":key/[A-Za-z0-9-]+$"))' "$verify_dir/bootstrap-output.json" >/dev/null || fail "remote bootstrap output does not bind recorder verification"
  copy_module infra/terraform "$baseline_module"; write_backend_config "$verify_dir/bootstrap-output.json" "node-operator/baseline/terraform.tfstate" "$baseline_backend"
  terraform -chdir="$baseline_module" init -input=false -reconfigure -backend-config="$baseline_backend"
  terraform -chdir="$baseline_module" show -json > "$verify_dir/baseline-state.json"
  jq -e --arg name "$name" --arg account "$account" --arg region "$region" '
    def r($a): [.values.root_module.resources[]? | select(.address == $a)];
    (r("aws_config_configuration_recorder.baseline[0]") | length == 1) and
    (r("aws_config_delivery_channel.baseline[0]") | length <= 1) and
    (r("aws_config_configuration_recorder_status.baseline[0]") | length <= 1) and
    (r("aws_iam_role.config") | length == 1) and (r("aws_s3_bucket.audit") | length == 1) and (r("aws_kms_key.audit") | length == 1) and
    (r("aws_iam_role.config")[0].values.arn | test("^arn:aws:iam::" + $account + ":role/")) and
    (r("aws_kms_key.audit")[0].values.arn | test("^arn:aws:kms:" + $region + ":" + $account + ":key/[A-Za-z0-9-]+$")) and
    (r("aws_s3_bucket.audit")[0].values.tags.Project == "node-operator") and
    (r("aws_s3_bucket.audit")[0].values.tags.Deployment == $name) and
    (r("aws_s3_bucket.audit")[0].values.tags.DeploymentRegion == $region) and
    (r("aws_s3_bucket.audit")[0].values.tags.ManagedBy == "terraform") and
    (r("aws_config_configuration_recorder.baseline[0]")[0].values.name == ($name + "-baseline-config")) and
    (r("aws_config_configuration_recorder.baseline[0]")[0].values.role_arn == r("aws_iam_role.config")[0].values.arn) and
    ((r("aws_config_delivery_channel.baseline[0]") | length == 0) or
      (r("aws_config_delivery_channel.baseline[0]")[0].values.name == r("aws_config_configuration_recorder.baseline[0]")[0].values.name and
       r("aws_config_delivery_channel.baseline[0]")[0].values.s3_bucket_name == r("aws_s3_bucket.audit")[0].values.id)) and
    ((r("aws_config_configuration_recorder_status.baseline[0]") | length == 0) or
      r("aws_config_configuration_recorder_status.baseline[0]")[0].values.name == r("aws_config_configuration_recorder.baseline[0]")[0].values.name)
  ' "$verify_dir/baseline-state.json" >/dev/null || fail "remote baseline state does not prove ownership of the Config recorder"
  local recorder_name recorder_role channel_bucket
  recorder_name="$(jq -er '.values.root_module.resources[] | select(.address == "aws_config_configuration_recorder.baseline[0]") | .values.name' "$verify_dir/baseline-state.json")"
  recorder_role="$(jq -er '.values.root_module.resources[] | select(.address == "aws_config_configuration_recorder.baseline[0]") | .values.role_arn' "$verify_dir/baseline-state.json")"
  channel_bucket="$(jq -r '[.values.root_module.resources[] | select(.address == "aws_config_delivery_channel.baseline[0]") | .values.s3_bucket_name] | if length == 0 then empty else .[0] end' "$verify_dir/baseline-state.json")"
  aws configservice describe-configuration-recorders --region "$region" --output json > "$verify_dir/live-recorders.json" || fail "unable to read live Config recorder"
  aws configservice describe-delivery-channels --region "$region" --output json > "$verify_dir/live-channels.json" || fail "unable to read live Config delivery channel"
  aws configservice describe-configuration-recorder-status --region "$region" --output json > "$verify_dir/live-status.json" || fail "unable to read live Config recorder status"
  jq -e --arg name "$recorder_name" --arg role "$recorder_role" '.ConfigurationRecorders | type == "array" and length == 1 and .[0].name == $name and .[0].roleARN == $role' "$verify_dir/live-recorders.json" >/dev/null || fail "live Config recorder differs from owned remote state"
  if [ -n "$channel_bucket" ]; then
    jq -e --arg name "$recorder_name" --arg bucket "$channel_bucket" '.DeliveryChannels | type == "array" and length == 1 and .[0].name == $name and .[0].s3BucketName == $bucket' "$verify_dir/live-channels.json" >/dev/null || fail "live Config delivery channel differs from owned remote state"
  else
    jq -e '.DeliveryChannels | type == "array" and length == 0' "$verify_dir/live-channels.json" >/dev/null || fail "untracked live Config delivery channel blocks recorder repair"
  fi
  jq -e --arg name "$recorder_name" '.ConfigurationRecordersStatus | type == "array" and length == 1 and .[0].name == $name' "$verify_dir/live-status.json" >/dev/null || fail "live Config recorder status differs from owned remote state"
  )
  printf '%s\n' 'PASS remote baseline state proves managed Config recorder ownership.'
}

case "$command_name" in
  verify)
    [ -z "$operation$config$bootstrap_config$foundation_config$baseline_config$inputs$work_dir" ] || fail "verify accepts only --bundle-root"
    verify_bundle ;;
  bootstrap)
    [ "$operation" = plan ] || [ "$operation" = apply ] || fail "bootstrap requires plan or apply"
    [ -n "$config" ] && [ -f "$config" ] || fail "--config must name a readable non-secret tfvars file"
    verify_bundle; reject_privileged_baseline_inputs "$config"; require_command terraform
    terraform -chdir="$bundle_root/source/infra/terraform" init -input=false
    terraform -chdir="$bundle_root/source/infra/terraform" "$operation" -input=false -var-file="$config" ;;
  zero)
    [ "$operation" = apply ] || [ "$operation" = verify-recorder ] || [ "$operation" = prepare-artifacts ] || fail "zero requires apply, prepare-artifacts, or verify-recorder"
    verify_bundle
    if [ "$operation" = verify-recorder ]; then zero_verify_recorder; else zero_apply; fi ;;
  *) usage; fail "unsupported command: $command_name" ;;
esac
