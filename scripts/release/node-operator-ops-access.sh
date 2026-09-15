#!/usr/bin/env bash
set -euo pipefail
umask 077

usage() { printf '%s\n' 'usage: node-operator-ops-access.sh verify|plan|apply|destroy --root BUNDLE_ROOT (--inputs OPS_INPUTS_JSON | --config TFVARS --backend-config BACKEND_HCL) --plan-file PRIVATE_SAVED_PLAN [--session-handoff NEW_ABSOLUTE_JSON] [--backend-profile PROFILE --expected-backend-principal-arn IAM_PRINCIPAL_ARN --provider-profile PROFILE --expected-provider-principal-arn IAM_PRINCIPAL_ARN] [--expected-sha SHA256] [--allow-create]'; }
operation="${1:-}"
[ "$operation" = verify ] || [ "$operation" = plan ] || [ "$operation" = apply ] || [ "$operation" = destroy ] || { usage; exit 64; }
shift
root=""; config=""; backend_config=""; inputs=""; session_handoff=""; plan_file=""; expected_sha=""; allow_create=false
backend_profile=""; provider_profile=""; expected_backend_principal_arn=""; expected_provider_principal_arn=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --root) root="${2:-}"; shift 2 ;; --config) config="${2:-}"; shift 2 ;;
    --backend-config) backend_config="${2:-}"; shift 2 ;; --plan-file) plan_file="${2:-}"; shift 2 ;;
    --inputs) inputs="${2:-}"; shift 2 ;;
    --session-handoff) session_handoff="${2:-}"; shift 2 ;;
    --backend-profile) backend_profile="${2:-}"; shift 2 ;;
    --provider-profile) provider_profile="${2:-}"; shift 2 ;;
    --expected-backend-principal-arn) expected_backend_principal_arn="${2:-}"; shift 2 ;;
    --expected-provider-principal-arn) expected_provider_principal_arn="${2:-}"; shift 2 ;;
    --expected-sha) expected_sha="${2:-}"; shift 2 ;; --allow-create) allow_create=true; shift ;;
    *) usage; exit 64 ;;
  esac
done

credential_boundary=false
if [ -n "$backend_profile$provider_profile$expected_backend_principal_arn$expected_provider_principal_arn" ]; then
  [ -n "$backend_profile" ] && [ -n "$provider_profile" ] &&
    [ -n "$expected_backend_principal_arn" ] && [ -n "$expected_provider_principal_arn" ] || {
      printf 'credential separation requires both profiles and both expected principal ARNs\n' >&2
      exit 64
    }
  credential_boundary=true
  [ "$backend_profile" != "$provider_profile" ] &&
    [ "$expected_backend_principal_arn" != "$expected_provider_principal_arn" ] || {
      printf 'backend and provider credentials must resolve through distinct profiles and principals\n' >&2
      exit 64
    }
fi

for variable in AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AWS_SECURITY_TOKEN; do
  [ -z "${!variable:-}" ] || {
    printf 'static or exported AWS credentials are not accepted; use short-lived named profiles\n' >&2
    exit 1
  }
done

validate_profile() {
  case "$1" in
    ''|*[!A-Za-z0-9._-]*) printf 'AWS profile name is invalid\n' >&2; return 1 ;;
  esac
}

validate_principal_arn() {
  case "$1" in
    arn:aws:iam::*:role/*|arn:aws:iam::*:user/*) ;;
    *) printf 'expected identity must be an IAM role or user ARN\n' >&2; return 1 ;;
  esac
  case "$1" in *[!A-Za-z0-9_+=,.@:/-]*) printf 'expected role ARN is invalid\n' >&2; return 1 ;; esac
}

profile_principal_arn() {
  local profile="$1" identity account arn role_path
  identity="$(env -u AWS_ACCESS_KEY_ID -u AWS_SECRET_ACCESS_KEY -u AWS_SESSION_TOKEN -u AWS_SECURITY_TOKEN \
    -u AWS_DEFAULT_PROFILE -u AWS_WEB_IDENTITY_TOKEN_FILE -u AWS_ROLE_ARN -u AWS_ROLE_SESSION_NAME \
    -u AWS_CONTAINER_CREDENTIALS_FULL_URI -u AWS_CONTAINER_CREDENTIALS_RELATIVE_URI \
    AWS_PROFILE="$profile" aws sts get-caller-identity --output json)"
  account="$(printf '%s' "$identity" | jq -er '.Account')"
  arn="$(printf '%s' "$identity" | jq -er '.Arn')"
  case "$arn" in
    arn:aws:sts::*:assumed-role/*/*)
      role_path="${arn#*:assumed-role/}"; role_path="${role_path%/*}"
      printf 'arn:aws:iam::%s:role/%s\n' "$account" "$role_path"
      ;;
    arn:aws:iam::*:role/*|arn:aws:iam::*:user/*) printf '%s\n' "$arn" ;;
    *) printf 'profile did not resolve to an allowed IAM principal\n' >&2; return 1 ;;
  esac
}

terraform_scoped() {
  if [ "$credential_boundary" = true ]; then
    env -u AWS_ACCESS_KEY_ID -u AWS_SECRET_ACCESS_KEY -u AWS_SESSION_TOKEN -u AWS_SECURITY_TOKEN \
      -u AWS_DEFAULT_PROFILE -u AWS_WEB_IDENTITY_TOKEN_FILE -u AWS_ROLE_ARN -u AWS_ROLE_SESSION_NAME \
      -u AWS_CONTAINER_CREDENTIALS_FULL_URI -u AWS_CONTAINER_CREDENTIALS_RELATIVE_URI \
      AWS_PROFILE="$provider_profile" terraform "$@"
  else
    terraform "$@"
  fi
}

private_path() {
  local candidate="$1" parent mode
  case "$candidate" in /*) ;; *) printf 'plan path must be absolute\n' >&2; return 1 ;; esac
  [ ! -L "$candidate" ] || { printf 'plan path must not be a symlink\n' >&2; return 1; }
  parent="$(dirname "$candidate")"
  [ -d "$parent" ] || { printf 'plan directory is missing\n' >&2; return 1; }
  while [ "$parent" != / ]; do
    # macOS exposes /tmp and /var through the /private volume.  Those fixed
    # system aliases are resolved by the OS; every caller-controlled component
    # still has to be a real directory.
    case "$parent" in
      /private|/var|/tmp) ;;
      *) [ ! -L "$parent" ] || { printf 'plan directory must not traverse a symlink\n' >&2; return 1; } ;;
    esac
    parent="$(dirname "$parent")"
  done
  if ! mode="$(stat -c '%a' "$(dirname "$candidate")" 2>/dev/null)"; then
    mode="$(stat -f '%OLp' "$(dirname "$candidate")")"
  fi
  [ $((8#$mode & 077)) -eq 0 ] || { printf 'plan directory must not be accessible by group or others\n' >&2; return 1; }
}

[ -d "$root/infra/ops-access" ] || { printf 'ops-access root is missing\n' >&2; exit 1; }
if [ -n "$inputs" ]; then
  [ -z "$config$backend_config" ] || { printf '%s\n' '--inputs cannot be combined with --config or --backend-config' >&2; exit 64; }
  case "$inputs" in /*) ;; *) printf '%s\n' '--inputs must be an absolute path' >&2; exit 64 ;; esac
  [ -f "$inputs" ] && [ ! -L "$inputs" ] || { printf '%s\n' '--inputs must name a regular file' >&2; exit 1; }
  input_parent="$(cd "$(dirname "$inputs")" && pwd -P)"
  expected_config="$input_parent/ops-access.tfvars.json"
  expected_backend="$input_parent/ops-access.backend.hcl"
  jq -e --arg config "$expected_config" --arg backend "$expected_backend" '
    .schema_version == 1 and (.cluster_name | test("^[a-z][a-z0-9-]{1,38}[a-z0-9]$")) and
    .config == $config and .backend_config == $backend
  ' "$inputs" >/dev/null || { printf '%s\n' '--inputs is not a bounded ops-access input contract' >&2; exit 1; }
  config="$expected_config"; backend_config="$expected_backend"
fi
[ -z "$session_handoff" ] || case "$session_handoff" in /*) ;; *) printf '%s\n' '--session-handoff must be an absolute path' >&2; exit 64 ;; esac
[ -f "$config" ] && [ ! -L "$config" ] || { printf 'non-secret tfvars file is required\n' >&2; exit 1; }
[ -f "$backend_config" ] && [ ! -L "$backend_config" ] || { printf 'an isolated non-secret backend config is required\n' >&2; exit 1; }
[ -z "$session_handoff" ] || { [ "$operation" = apply ] && [ -n "$inputs" ]; } || { printf '%s\n' '--session-handoff is supported only for apply with --inputs' >&2; exit 64; }
[ -n "$plan_file" ] || { printf 'a private saved plan path is required\n' >&2; exit 64; }
private_path "$plan_file" || exit 1
command -v terraform >/dev/null 2>&1 || { printf 'terraform is required\n' >&2; exit 127; }
command -v jq >/dev/null 2>&1 || { printf 'jq is required\n' >&2; exit 127; }
command -v shasum >/dev/null 2>&1 || { printf 'shasum is required\n' >&2; exit 127; }
if [ "$credential_boundary" = true ]; then
  command -v aws >/dev/null 2>&1 || { printf 'aws is required for credential identity verification\n' >&2; exit 127; }
  validate_profile "$backend_profile"; validate_profile "$provider_profile"
  validate_principal_arn "$expected_backend_principal_arn"; validate_principal_arn "$expected_provider_principal_arn"
  [ "$(profile_principal_arn "$backend_profile")" = "$expected_backend_principal_arn" ] || {
    printf 'backend profile principal does not match the allowlist\n' >&2; exit 1;
  }
  [ "$(profile_principal_arn "$provider_profile")" = "$expected_provider_principal_arn" ] || {
    printf 'provider profile principal does not match the allowlist\n' >&2; exit 1;
  }
fi
module="$root/infra/ops-access"; guard="$root/scripts/ci/check-ops-access-ssm-retention-plan.sh"
# The historical retention checker is checkout-only and is not shipped.

fresh_plan() {
  jq -e '
    def managed: [.. | objects | .resources?[]? | select(.mode == "managed")];
    # Creation legitimately leaves provider-computed IDs/addresses unknown.  Do
    # not let that relax any host hardening field; an unknown SG/profile is
    # allowed only when this same plan creates the owned reference.
    def known_security_configuration:
      (.ebs_optimized != true) and (.monitoring != true) and
      (.associate_public_ip_address != true) and (.subnet_id != true) and
      (.metadata_options[0].http_tokens != true) and
      (.metadata_options[0].http_endpoint != true) and
      (.metadata_options[0].http_put_response_hop_limit != true) and
      (.root_block_device[0].encrypted != true) and (.root_block_device[0].volume_type != true);
    . as $plan |
    def resource_map: reduce .[] as $resource ({}; .[$resource.address] = $resource);
    def expected_resources($create_endpoints; $manage_endpoint_ingress; $manage_cluster_ingress):
      {
        "aws_iam_instance_profile.host":"aws_iam_instance_profile",
        "aws_iam_role.host":"aws_iam_role",
        "aws_iam_role_policy_attachment.ssm":"aws_iam_role_policy_attachment",
        "aws_instance.host":"aws_instance",
        "aws_security_group.host":"aws_security_group",
        "aws_vpc_security_group_egress_rule.to_cluster":"aws_vpc_security_group_egress_rule",
        "aws_vpc_security_group_egress_rule.to_endpoints":"aws_vpc_security_group_egress_rule"
      } +
      (if $manage_cluster_ingress then {"aws_vpc_security_group_ingress_rule.cluster[0]":"aws_vpc_security_group_ingress_rule"} else {} end) +
      (if $create_endpoints then {
        "aws_security_group.endpoints[0]":"aws_security_group",
        "aws_vpc_security_group_ingress_rule.endpoints[0]":"aws_vpc_security_group_ingress_rule",
        "aws_vpc_endpoint.ssm[\"ec2messages\"]":"aws_vpc_endpoint",
        "aws_vpc_endpoint.ssm[\"ssm\"]":"aws_vpc_endpoint",
        "aws_vpc_endpoint.ssm[\"ssmmessages\"]":"aws_vpc_endpoint"
      } elif $manage_endpoint_ingress then {"aws_vpc_security_group_ingress_rule.endpoints[0]":"aws_vpc_security_group_ingress_rule"} else {} end);
    ($plan.variables.existing_ssm_endpoint_security_group_id.value?) as $endpoint_security_group_id |
    ($plan.variables.manage_existing_endpoint_ingress_rule.value?) as $manage_endpoint_ingress |
    ($plan.variables.manage_cluster_ingress_rule.value?) as $manage_cluster_ingress |
    ($endpoint_security_group_id == null) as $create_endpoints |
    (expected_resources($create_endpoints; $manage_endpoint_ingress; $manage_cluster_ingress)) as $expected |
    ($expected | keys | sort) as $addresses |
    ($plan.planned_values.root_module | managed) as $planned |
    [$plan.resource_changes[]? | select(.mode == "managed")] as $changes |
    ($planned | resource_map) as $planned_map |
    ($changes | resource_map) as $change_map |
    ($plan.planned_values.root_module | managed | map(select(.address == "aws_instance.host" and .type == "aws_instance"))) as $planned_hosts |
    ($plan.planned_values.root_module | managed | map(select(.type == "aws_instance"))) as $planned_instances |
    [$plan.resource_changes[]? | select(.mode == "managed" and .address == "aws_instance.host" and .type == "aws_instance")] as $host_changes |
    [$plan.resource_changes[]? | select(.mode == "managed" and .type == "aws_instance")] as $instance_changes |
    [$plan.resource_changes[]? | select(.mode == "managed" and .address == "aws_security_group.host" and .type == "aws_security_group" and (.change.actions | index("create")))] as $owned_sg_changes |
    [$plan.resource_changes[]? | select(.mode == "managed" and .address == "aws_iam_instance_profile.host" and .type == "aws_iam_instance_profile" and (.change.actions | index("create")))] as $owned_profile_changes |
    [ $plan.configuration.root_module.resources[]? | select(.address == "aws_instance.host" and .mode == "managed" and .type == "aws_instance") ] as $configured_hosts |
    ($plan.prior_state.values.root_module | managed | map(select(.address == "aws_instance.host"))) as $prior_hosts |
    ($plan.variables | has("retained_host_instance_id")) and
    ($plan.variables.retained_host_instance_id | has("value")) and
    ($plan.variables.retained_host_instance_id.value == null) and
    ($plan.variables | has("existing_ssm_endpoint_security_group_id") and has("manage_existing_endpoint_ingress_rule") and has("manage_cluster_ingress_rule")) and
    (all(["existing_ssm_endpoint_security_group_id", "manage_existing_endpoint_ingress_rule", "manage_cluster_ingress_rule"][]; $plan.variables[.] | has("value"))) and
    (($endpoint_security_group_id == null) or ($endpoint_security_group_id | type == "string" and length > 0)) and
    ($manage_endpoint_ingress | type == "boolean") and ($manage_cluster_ingress | type == "boolean") and
    ($plan.prior_state.values.root_module | managed | length == 0) and
    ($planned | length == ($addresses | length)) and ($changes | length == ($addresses | length)) and
    ($planned_map | keys | sort) == $addresses and ($change_map | keys | sort) == $addresses and
    (all($addresses[]; $planned_map[.].type == $expected[.] and $change_map[.].type == $expected[.] and
      $change_map[.].change.actions == ["create"] and $change_map[.].change.before == null and
      $change_map[.].change.after == $planned_map[.].values)) and
    ($prior_hosts | length == 0) and ($planned_hosts | length == 1) and ($planned_instances | length == 1) and
    ($host_changes | length == 1) and ($instance_changes | length == 1) and
    ($owned_sg_changes | length == 1) and ($owned_profile_changes | length == 1) and
    ($host_changes[0].change.actions == ["create"]) and ($host_changes[0].change.after == $planned_hosts[0].values) and
    ($configured_hosts | length > 0) and
    # Terraform may emit both the attribute reference and its owning resource
    # reference.  Require the owned attribute in that set instead of pinning
    # the provider-version-specific complete list.
    (all($configured_hosts[]; (.expressions.iam_instance_profile.references | index("aws_iam_instance_profile.host.name")) != null and (.expressions.vpc_security_group_ids.references | index("aws_security_group.host.id")) != null)) and
    ($host_changes[0].change.after_unknown | known_security_configuration) and
    ($planned_hosts[0].values.ebs_optimized == true) and ($planned_hosts[0].values.monitoring == false) and
    ($planned_hosts[0].values.associate_public_ip_address == false) and
    ($planned_hosts[0].values.subnet_id | type == "string" and length > 0) and
    (($host_changes[0].change.after_unknown.iam_instance_profile == true) or
      ($planned_hosts[0].values.iam_instance_profile == $owned_profile_changes[0].change.after.name)) and
    # Terraform JSON plans represent an entirely unknown set as either a
    # boolean or a single unknown element, depending on provider version.
    (($host_changes[0].change.after_unknown.vpc_security_group_ids == true) or
      ($host_changes[0].change.after_unknown.vpc_security_group_ids == [true])) and
    ($planned_hosts[0].values.metadata_options | type == "array" and length == 1) and
    ($planned_hosts[0].values.metadata_options[0].http_tokens == "required") and
    ($planned_hosts[0].values.metadata_options[0].http_endpoint == "enabled") and
    ($planned_hosts[0].values.metadata_options[0].http_put_response_hop_limit == 1) and
    ($planned_hosts[0].values.root_block_device | type == "array" and length == 1) and
    ($planned_hosts[0].values.root_block_device[0].encrypted == true) and ($planned_hosts[0].values.root_block_device[0].volume_type == "gp3")
  ' "$1" >/dev/null
}

render_json() {
  local output="$1" existing="${2:-false}"
  if [ "$existing" = true ]; then
    [ -f "$output" ] && [ ! -L "$output" ] || { printf 'temporary plan JSON is unsafe\n' >&2; return 1; }
  else
    [ ! -e "$output" ] && [ ! -L "$output" ] || { printf 'refusing to overwrite plan JSON\n' >&2; return 1; }
  fi
  terraform_scoped -chdir="$module" show -json "$plan_file" > "$output"
  jq -e . "$output" >/dev/null
}
classify_plan() {
  local json="$1"
  if [ -x "$guard" ] && bash "$guard" "$json" >/dev/null; then
    [ "$allow_create" = false ] || { printf 'retained-host plan must not use --allow-create\n' >&2; return 1; }
    printf 'retention\n'
  elif jq -e '
    # A resumed zero-resource release can legitimately produce a no-op plan
    # for its own already-created host. Accept only an entirely no-op plan
    # whose host still satisfies the fresh-host security invariants.
    ([.resource_changes[]?.change.actions] | all(. == ["no-op"])) and
    ([.resource_changes[]? | select(.address == "aws_instance.host") | .change.after] | length == 1) and
    ([.resource_changes[]? | select(.address == "aws_instance.host") | .change.after] | .[0].ebs_optimized == true and
      .[0].monitoring == false and .[0].associate_public_ip_address == false and
      .[0].instance_type == "t3.micro" and .[0].metadata_options[0].http_tokens == "required" and
      .[0].metadata_options[0].http_put_response_hop_limit == 1 and
      .[0].root_block_device[0].encrypted == true and .[0].root_block_device[0].volume_type == "gp3")
  ' "$json" >/dev/null; then
    printf 'retention\n'
  else
    [ "$allow_create" = true ] || { printf 'fresh creation requires --allow-create\n' >&2; return 1; }
    fresh_plan "$json" || { printf 'plan is neither the reviewed retained host nor a secure fresh create\n' >&2; return 1; }
    printf 'fresh\n'
  fi
}

backend_args=(-backend-config="$backend_config")
[ "$credential_boundary" = false ] || backend_args+=(-backend-config="profile=$backend_profile")
verification_data_dir=""
if [ "$operation" = verify ]; then
  verification_data_dir="${plan_file}.terraform-data"
  [ ! -e "$verification_data_dir" ] && [ ! -L "$verification_data_dir" ] || {
    printf 'refusing to reuse verification Terraform data directory\n' >&2; exit 1;
  }
  mkdir "$verification_data_dir"; chmod 700 "$verification_data_dir"
  export TF_DATA_DIR="$verification_data_dir"
  trap 'rm -rf "$plan_file" "${plan_file}.json" "$verification_data_dir"' EXIT
fi
terraform_scoped -chdir="$module" init -input=false -lockfile=readonly "${backend_args[@]}"
case "$operation" in
  verify)
    [ "$allow_create" = false ] || { printf 'read-only verification cannot allow creation\n' >&2; exit 1; }
    [ ! -e "$plan_file" ] && [ ! -L "$plan_file" ] || { printf 'refusing to overwrite verification plan\n' >&2; exit 1; }
    plan_json="${plan_file}.json"; private_path "$plan_json" || exit 1
    [ ! -e "$plan_json" ] && [ ! -L "$plan_json" ] || { printf 'refusing to overwrite verification JSON\n' >&2; exit 1; }
    verify_exit=0
    terraform_scoped -chdir="$module" plan -input=false -lock=false -detailed-exitcode -var-file="$config" -out="$plan_file" || verify_exit=$?
    [ "$verify_exit" -eq 0 ] || [ "$verify_exit" -eq 2 ] || exit "$verify_exit"
    render_json "$plan_json"
    mode="$(classify_plan "$plan_json")"
    [ "$mode" = retention ] || { printf 'verification is not a retained-host plan\n' >&2; exit 1; }
    no_op_count="$(jq -er '[.resource_changes[]? | select(.mode == "managed" and .change.actions == ["no-op"])] | length' "$plan_json")"
    managed_count="$(jq -er '[.resource_changes[]? | select(.mode == "managed")] | length' "$plan_json")"
    [ "$no_op_count" -eq "$managed_count" ] && [ "$verify_exit" -eq 0 ] || {
      printf 'verification found Terraform drift; inspect privately and do not apply\n' >&2; exit 2;
    }
    plan_sha="$(shasum -a 256 "$plan_file" | awk '{print $1}')"
    printf 'verification_mode=%s managed_no_op=%s saved_plan_sha256=%s retained=false\n' "$mode" "$no_op_count" "$plan_sha"
    ;;
  plan)
    [ ! -e "$plan_file" ] && [ ! -L "$plan_file" ] || { printf 'refusing to overwrite saved plan\n' >&2; exit 1; }
    plan_json="${plan_file}.json"; private_path "$plan_json" || exit 1
    [ ! -e "$plan_json" ] && [ ! -L "$plan_json" ] || { printf 'refusing to overwrite saved plan JSON\n' >&2; exit 1; }
    terraform_scoped -chdir="$module" plan -input=false -var-file="$config" -out="$plan_file"
    render_json "$plan_json"; mode="$(classify_plan "$plan_json")"
    plan_sha="$(shasum -a 256 "$plan_file" | awk '{print $1}')"
    printf 'saved_plan_mode=%s saved_plan_sha256=%s\n' "$mode" "$plan_sha"
    ;;
  apply)
    [ -n "$expected_sha" ] || { printf 'apply requires --expected-sha for the reviewed saved plan\n' >&2; exit 64; }
    [ -f "$plan_file" ] && [ ! -L "$plan_file" ] || { printf 'saved plan is missing or unsafe\n' >&2; exit 1; }
    actual_sha="$(shasum -a 256 "$plan_file" | awk '{print $1}')"; [ "$actual_sha" = "$expected_sha" ] || { printf 'saved plan hash mismatch\n' >&2; exit 1; }
    plan_json="$(mktemp "$(dirname "$plan_file")/.node-operator-ops-access-plan.XXXXXX")"; trap 'rm -f "$plan_json"' EXIT
    render_json "$plan_json" true; mode="$(classify_plan "$plan_json")"
    actual_sha="$(shasum -a 256 "$plan_file" | awk '{print $1}')"; [ "$actual_sha" = "$expected_sha" ] || { printf 'saved plan changed during validation\n' >&2; exit 1; }
    terraform_scoped -chdir="$module" apply -input=false "$plan_file"
    if [ -n "$session_handoff" ]; then
      [ ! -e "$session_handoff" ] && [ ! -L "$session_handoff" ] || { printf '%s\n' 'refusing to overwrite session handoff' >&2; exit 1; }
      instance_id="$(terraform_scoped -chdir="$module" output -raw instance_id)"
      [[ "$instance_id" =~ ^i-[0-9a-f]+$ ]] || { printf '%s\n' 'ops-access apply did not return a valid SSM instance ID' >&2; exit 70; }
      cluster_name="$(jq -er '.cluster_name' "$inputs")"
      aws_region="$(jq -er '.aws_region | select(test("^[a-z]{2}-[a-z0-9-]+-[0-9]+$"))' "$config")"
      jq -n --arg cluster "$cluster_name" --arg region "$aws_region" --arg instance "$instance_id" \
        '{schema_version:1,aws_region:$region,cluster_name:$cluster,ssm_ops_instance_id:$instance}' > "$session_handoff"
      chmod 600 "$session_handoff"
      printf 'PASS private EKS session handoff written to %s.\n' "$session_handoff"
    fi
    ;;
  destroy)
    printf 'destroy requires a separately reviewed explicit destroy-plan interface; direct destroy is disabled\n' >&2
    exit 1 ;;
esac
