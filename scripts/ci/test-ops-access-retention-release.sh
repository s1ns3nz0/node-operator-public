#!/usr/bin/env bash
# Check objective: Verify the saved-plan release wrapper preserves approved SSM retention changes only.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
entrypoint="$root/scripts/release/node-operator-ops-access.sh"
scratch="$(mktemp -d "${TMPDIR:-/tmp}/ops-access-release.XXXXXX")"
trap 'rm -rf "$scratch"' EXIT
bundle="$scratch/bundle"; mkdir -p "$bundle/infra" "$bundle/scripts/ci" "$scratch/bin" "$scratch/private"
chmod 700 "$scratch/private"
mkdir -p "$bundle/infra/ops-access"
cp "$root/infra/ops-access/"*.tf "$bundle/infra/ops-access/"
cp "$root/scripts/ci/check-ops-access-ssm-retention-plan.sh" "$bundle/scripts/ci/"
chmod +x "$bundle/scripts/ci/check-ops-access-ssm-retention-plan.sh"
: > "$scratch/config.tfvars"; : > "$scratch/backend.hcl"
cat > "$scratch/bin/terraform" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
case "$*" in
  *' init '*) exit 0 ;;
  *' show -json '*) [ -z "${MUTATE_PLAN:-}" ] || printf 'changed-after-review\n' > "$MUTATE_PLAN"; cat "$MOCK_PLAN_JSON" ;;
  *' plan '*) for argument in "$@"; do case "$argument" in -out=*) printf 'verification-plan\n' > "${argument#-out=}" ;; esac; done; exit "${MOCK_PLAN_EXIT:-0}" ;;
  *' apply '*) printf 'apply\n' >> "$MOCK_TRACE" ;;
  *) exit 64 ;;
esac
EOF
chmod +x "$scratch/bin/terraform"

jq -n '
  def rs: [
    {address:"aws_iam_instance_profile.host",mode:"managed",type:"aws_iam_instance_profile",values:{id:"profile-id"}},
    {address:"aws_iam_role.host",mode:"managed",type:"aws_iam_role",values:{id:"role-id"}},
    {address:"aws_iam_role_policy_attachment.ssm",mode:"managed",type:"aws_iam_role_policy_attachment",values:{id:"attachment-id"}},
    {address:"aws_instance.host",mode:"managed",type:"aws_instance",values:{id:"i-0123456789abcdef0",instance_type:"t3.micro",ebs_optimized:false,monitoring:false}},
    {address:"aws_security_group.host",mode:"managed",type:"aws_security_group",values:{id:"sg-host"}},
    {address:"aws_vpc_security_group_egress_rule.to_cluster",mode:"managed",type:"aws_vpc_security_group_egress_rule",values:{id:"egress-cluster"}},
    {address:"aws_vpc_security_group_egress_rule.to_endpoints",mode:"managed",type:"aws_vpc_security_group_egress_rule",values:{id:"egress-endpoints"}},
    {address:"aws_vpc_security_group_ingress_rule.cluster",mode:"managed",type:"aws_vpc_security_group_ingress_rule",values:{id:"ingress-cluster"}},
    {address:"aws_vpc_security_group_ingress_rule.endpoints",mode:"managed",type:"aws_vpc_security_group_ingress_rule",values:{id:"ingress-endpoints"}}
  ];
  {variables:{retained_host_instance_id:{value:"i-0123456789abcdef0"}},prior_state:{values:{root_module:{resources:rs}}},planned_values:{root_module:{resources:(rs | map(if .address == "aws_vpc_security_group_ingress_rule.cluster" then .address += "[0]" elif .address == "aws_vpc_security_group_ingress_rule.endpoints" then .address += "[0]" else . end))}},resource_changes:(rs | map({address,mode,type,change:{actions:["no-op"],before:.values,after:.values,after_unknown:{}}}))}
' > "$scratch/retention.json"
jq -n '
  def host: {ebs_optimized:true,monitoring:false,associate_public_ip_address:false,subnet_id:"subnet-private",iam_instance_profile:null,vpc_security_group_ids:[null],metadata_options:[{http_tokens:"required",http_endpoint:"enabled",http_put_response_hop_limit:1}],root_block_device:[{encrypted:true,volume_type:"gp3"}]};
  def owned: [
    {address:"aws_security_group.host",mode:"managed",type:"aws_security_group",values:{id:null,name:"owned-host-sg"}},
    {address:"aws_vpc_security_group_egress_rule.to_cluster",mode:"managed",type:"aws_vpc_security_group_egress_rule",values:{id:null}},
    {address:"aws_vpc_security_group_egress_rule.to_endpoints",mode:"managed",type:"aws_vpc_security_group_egress_rule",values:{id:null}},
    {address:"aws_vpc_security_group_ingress_rule.cluster[0]",mode:"managed",type:"aws_vpc_security_group_ingress_rule",values:{id:null}},
    {address:"aws_iam_instance_profile.host",mode:"managed",type:"aws_iam_instance_profile",values:{id:null,name:"owned-host-profile"}},
    {address:"aws_iam_role.host",mode:"managed",type:"aws_iam_role",values:{id:null}},
    {address:"aws_iam_role_policy_attachment.ssm",mode:"managed",type:"aws_iam_role_policy_attachment",values:{id:null}}
  ];
  {variables:{retained_host_instance_id:{value:null},existing_ssm_endpoint_security_group_id:{value:"sg-shared"},manage_existing_endpoint_ingress_rule:{value:false},manage_cluster_ingress_rule:{value:true}},configuration:{root_module:{resources:[{address:"aws_instance.host",mode:"managed",type:"aws_instance",expressions:{iam_instance_profile:{references:["aws_iam_instance_profile.host.name"]},vpc_security_group_ids:{references:["aws_security_group.host.id"]}}}]}},prior_state:{values:{root_module:{resources:[]}}},planned_values:{root_module:{resources:([{address:"aws_instance.host",mode:"managed",type:"aws_instance",values:host}] + owned)}},resource_changes:[
    {address:"aws_instance.host",mode:"managed",type:"aws_instance",change:{actions:["create"],before:null,after:host,after_unknown:{id:true,arn:true,private_ip:true,iam_instance_profile:true,vpc_security_group_ids:[true],ebs_optimized:false,monitoring:false,associate_public_ip_address:false,subnet_id:false,metadata_options:[{http_tokens:false,http_endpoint:false,http_put_response_hop_limit:false}],root_block_device:[{encrypted:false,volume_type:false}]}}},
    (owned[] | {address,mode,type,change:{actions:["create"],before:null,after:.values,after_unknown:{id:true}}})
  ]}
' > "$scratch/fresh.json"

verify_plan="$scratch/private/verify-plan"
verify_output="$(PATH="$scratch/bin:$PATH" MOCK_PLAN_JSON="$scratch/retention.json" MOCK_TRACE="$scratch/trace" bash "$entrypoint" verify --root "$bundle" --config "$scratch/config.tfvars" --backend-config "$scratch/backend.hcl" --plan-file "$verify_plan")"
printf '%s' "$verify_output" | grep -Eq '^verification_mode=retention managed_no_op=9 saved_plan_sha256=[0-9a-f]{64} retained=false$'
if [ -e "$verify_plan" ] || [ -e "${verify_plan}.json" ]; then
  printf 'verification artifacts were retained\n' >&2
  exit 1
fi
if PATH="$scratch/bin:$PATH" MOCK_PLAN_JSON="$scratch/retention.json" MOCK_TRACE="$scratch/trace" bash "$entrypoint" verify --root "$bundle" --config "$scratch/config.tfvars" --backend-config "$scratch/backend.hcl" --plan-file "$verify_plan" --allow-create >/dev/null 2>&1; then
  printf 'read-only verification accepted allow-create\n' >&2
  exit 1
fi

run_apply() {
  local json="$1" allow="${2:-false}" plan="$scratch/private/plan-$RANDOM"
  printf 'reviewed-plan\n' > "$plan"
  local sha; sha="$(shasum -a 256 "$plan" | awk '{print $1}')"
  local args=(apply --root "$bundle" --config "$scratch/config.tfvars" --backend-config "$scratch/backend.hcl" --plan-file "$plan" --expected-sha "$sha")
  [ "$allow" = true ] && args+=(--allow-create)
  PATH="$scratch/bin:$PATH" MOCK_PLAN_JSON="$json" MOCK_TRACE="$scratch/trace" bash "$entrypoint" "${args[@]}" >/dev/null
}

run_apply "$scratch/retention.json"
run_apply "$scratch/fresh.json" true
jq '
  def endpoint: [
    {address:"aws_security_group.endpoints[0]",mode:"managed",type:"aws_security_group",values:{id:null}},
    {address:"aws_vpc_security_group_ingress_rule.endpoints[0]",mode:"managed",type:"aws_vpc_security_group_ingress_rule",values:{id:null}},
    {address:"aws_vpc_endpoint.ssm[\"ec2messages\"]",mode:"managed",type:"aws_vpc_endpoint",values:{id:null}},
    {address:"aws_vpc_endpoint.ssm[\"ssm\"]",mode:"managed",type:"aws_vpc_endpoint",values:{id:null}},
    {address:"aws_vpc_endpoint.ssm[\"ssmmessages\"]",mode:"managed",type:"aws_vpc_endpoint",values:{id:null}}
  ];
  .variables.existing_ssm_endpoint_security_group_id.value = null |
  .planned_values.root_module.resources += endpoint |
  .resource_changes += [endpoint[] | {address,mode,type,change:{actions:["create"],before:null,after:.values,after_unknown:{id:true}}}]
' "$scratch/fresh.json" > "$scratch/fresh-isolated-endpoints.json"
run_apply "$scratch/fresh-isolated-endpoints.json" true
for scope_variable in existing_ssm_endpoint_security_group_id manage_existing_endpoint_ingress_rule manage_cluster_ingress_rule; do
  jq --arg variable "$scope_variable" 'del(.variables[$variable].value)' "$scratch/fresh-isolated-endpoints.json" > "$scratch/fresh-missing-scope-value.json"
  if run_apply "$scratch/fresh-missing-scope-value.json" true >/dev/null 2>&1; then printf 'fresh plan with missing scope value applied\n' >&2; exit 1; fi
done
test "$(wc -l < "$scratch/trace" | tr -d ' ')" = 3

# Published bundles omit the obsolete maintainer-specific checker. Fresh
# deployment remains functional, while historical retention cannot be used.
mv "$bundle/scripts/ci/check-ops-access-ssm-retention-plan.sh" "$scratch/historical-checker"
run_apply "$scratch/fresh.json" true
if run_apply "$scratch/retention.json" >/dev/null 2>&1; then
  printf 'release without legacy checker accepted maintainer host retention\n' >&2
  exit 1
fi
mv "$scratch/historical-checker" "$bundle/scripts/ci/check-ops-access-ssm-retention-plan.sh"

# --allow-create cannot transform a retained or malformed plan into fresh mode.
if run_apply "$scratch/retention.json" true >/dev/null 2>&1; then printf 'allow-create bypassed retention guard\n' >&2; exit 1; fi
jq 'del(.variables.retained_host_instance_id)' "$scratch/retention.json" > "$scratch/invalid.json"
if run_apply "$scratch/invalid.json" true >/dev/null 2>&1; then printf 'known retained host bypassed fresh validation\n' >&2; exit 1; fi
jq 'del(.variables.retained_host_instance_id)' "$scratch/fresh.json" > "$scratch/fresh-missing-optin.json"
if run_apply "$scratch/fresh-missing-optin.json" true >/dev/null 2>&1; then printf 'fresh plan without explicit null opt-in applied\n' >&2; exit 1; fi
jq '.resource_changes[0].change.after_unknown.monitoring=true' "$scratch/fresh.json" > "$scratch/fresh-monitoring-unknown.json"
if run_apply "$scratch/fresh-monitoring-unknown.json" true >/dev/null 2>&1; then printf 'fresh plan with unknown monitoring applied\n' >&2; exit 1; fi
jq '.configuration.root_module.resources[0].expressions.vpc_security_group_ids.references=["aws_security_group.foreign.id"]' "$scratch/fresh.json" > "$scratch/fresh-foreign-sg.json"
if run_apply "$scratch/fresh-foreign-sg.json" true >/dev/null 2>&1; then printf 'fresh plan with foreign security group reference applied\n' >&2; exit 1; fi
jq '.configuration.root_module.resources[0].expressions.iam_instance_profile.references=["aws_iam_instance_profile.foreign.name"]' "$scratch/fresh.json" > "$scratch/fresh-foreign-profile.json"
if run_apply "$scratch/fresh-foreign-profile.json" true >/dev/null 2>&1; then printf 'fresh plan with foreign profile reference applied\n' >&2; exit 1; fi
jq '.planned_values.root_module.resources[0].values.iam_instance_profile="foreign-profile" | .resource_changes[0].change.after.iam_instance_profile="foreign-profile" | .resource_changes[0].change.after_unknown.iam_instance_profile=false' "$scratch/fresh.json" > "$scratch/fresh-arbitrary-profile.json"
if run_apply "$scratch/fresh-arbitrary-profile.json" true >/dev/null 2>&1; then printf 'fresh plan with arbitrary profile value applied\n' >&2; exit 1; fi
jq '.planned_values.root_module.resources[0].values.vpc_security_group_ids=["sg-foreign"] | .resource_changes[0].change.after.vpc_security_group_ids=["sg-foreign"] | .resource_changes[0].change.after_unknown.vpc_security_group_ids=[false]' "$scratch/fresh.json" > "$scratch/fresh-arbitrary-sg.json"
if run_apply "$scratch/fresh-arbitrary-sg.json" true >/dev/null 2>&1; then printf 'fresh plan with arbitrary security group value applied\n' >&2; exit 1; fi
jq '.planned_values.root_module.resources += [{address:"aws_instance.other",mode:"managed",type:"aws_instance",values:{}}]' "$scratch/fresh.json" > "$scratch/fresh-other-instance.json"
if run_apply "$scratch/fresh-other-instance.json" true >/dev/null 2>&1; then printf 'fresh plan with a second instance applied\n' >&2; exit 1; fi
jq '.planned_values.root_module.resources += [{address:"aws_iam_policy.extra",mode:"managed",type:"aws_iam_policy",values:{id:null}}] | .resource_changes += [{address:"aws_iam_policy.extra",mode:"managed",type:"aws_iam_policy",change:{actions:["create"],before:null,after:{id:null},after_unknown:{id:true}}}]' "$scratch/fresh.json" > "$scratch/fresh-extra-iam.json"
if run_apply "$scratch/fresh-extra-iam.json" true >/dev/null 2>&1; then printf 'fresh plan with extra IAM resource applied\n' >&2; exit 1; fi
jq '(.resource_changes[] | select(.address == "aws_iam_role.host")).change.actions=["update"]' "$scratch/fresh.json" > "$scratch/fresh-update.json"
if run_apply "$scratch/fresh-update.json" true >/dev/null 2>&1; then printf 'fresh plan with an update action applied\n' >&2; exit 1; fi
jq '(.resource_changes[] | select(.address == "aws_iam_role.host")).change.actions=["delete"]' "$scratch/fresh.json" > "$scratch/fresh-delete.json"
if run_apply "$scratch/fresh-delete.json" true >/dev/null 2>&1; then printf 'fresh plan with a delete action applied\n' >&2; exit 1; fi
jq '(.resource_changes[] | select(.address == "aws_iam_role.host")).change.actions=["delete","create"]' "$scratch/fresh.json" > "$scratch/fresh-replacement.json"
if run_apply "$scratch/fresh-replacement.json" true >/dev/null 2>&1; then printf 'fresh plan with a replacement action applied\n' >&2; exit 1; fi
jq '.planned_values.root_module.resources |= map(select(.address != "aws_iam_instance_profile.host")) | .resource_changes |= map(select(.address != "aws_iam_instance_profile.host"))' "$scratch/fresh.json" > "$scratch/fresh-missing-profile.json"
if run_apply "$scratch/fresh-missing-profile.json" true >/dev/null 2>&1; then printf 'fresh plan missing the owned profile applied\n' >&2; exit 1; fi
jq 'del(.variables.manage_cluster_ingress_rule.value)' "$scratch/fresh.json" > "$scratch/fresh-missing-ingress-value.json"
if run_apply "$scratch/fresh-missing-ingress-value.json" true >/dev/null 2>&1; then printf 'fresh plan with missing ingress value applied\n' >&2; exit 1; fi

# An expected digest mismatch stops before show/apply, and no unsafe path is accepted.
plan="$scratch/private/hash-plan"; printf 'changed\n' > "$plan"
if PATH="$scratch/bin:$PATH" MOCK_PLAN_JSON="$scratch/retention.json" MOCK_TRACE="$scratch/trace" bash "$entrypoint" apply --root "$bundle" --config "$scratch/config.tfvars" --backend-config "$scratch/backend.hcl" --plan-file "$plan" --expected-sha 0000000000000000000000000000000000000000000000000000000000000000 >/dev/null 2>&1; then printf 'changed saved plan unexpectedly applied\n' >&2; exit 1; fi
plan="$scratch/private/mutated-after-show"; printf 'reviewed-plan\n' > "$plan"; sha="$(shasum -a 256 "$plan" | awk '{print $1}')"
if PATH="$scratch/bin:$PATH" MOCK_PLAN_JSON="$scratch/retention.json" MOCK_TRACE="$scratch/trace" MUTATE_PLAN="$plan" bash "$entrypoint" apply --root "$bundle" --config "$scratch/config.tfvars" --backend-config "$scratch/backend.hcl" --plan-file "$plan" --expected-sha "$sha" >/dev/null 2>&1; then printf 'plan changed during validation unexpectedly applied\n' >&2; exit 1; fi
if PATH="$scratch/bin:$PATH" bash "$entrypoint" apply --root "$bundle" --config "$scratch/config.tfvars" --backend-config "$scratch/backend.hcl" --plan-file relative-plan --expected-sha x >/dev/null 2>&1; then printf 'relative plan path accepted\n' >&2; exit 1; fi
ln -s "$plan" "$scratch/private/plan-link"
if PATH="$scratch/bin:$PATH" bash "$entrypoint" apply --root "$bundle" --config "$scratch/config.tfvars" --backend-config "$scratch/backend.hcl" --plan-file "$scratch/private/plan-link" --expected-sha x >/dev/null 2>&1; then printf 'symlink plan path accepted\n' >&2; exit 1; fi

printf 'PASS ops-access wrapper permits only reviewed retained or secure fresh saved plans.\n'
