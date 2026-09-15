#!/usr/bin/env bash
# Check objective: Reject Terraform plans that weaken reviewed SSM access-log retention.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
guard="$root/scripts/ci/check-ops-access-ssm-retention-plan.sh"
scratch="$(mktemp -d "${TMPDIR:-/tmp}/ops-access-retention.XXXXXX")"
trap 'rm -rf "$scratch"' EXIT

jq -n '
  # Synthetic plan identities only; no live state or saved-plan content is embedded.
  def resources: [
    {address:"aws_iam_instance_profile.host",mode:"managed",type:"aws_iam_instance_profile",values:{id:"profile-id"}},
    {address:"aws_iam_role.host",mode:"managed",type:"aws_iam_role",values:{id:"role-id"}},
    {address:"aws_iam_role_policy_attachment.ssm",mode:"managed",type:"aws_iam_role_policy_attachment",values:{id:"attachment-id"}},
    {address:"aws_instance.host",mode:"managed",type:"aws_instance",values:{id:"i-0123456789abcdef0",instance_type:"t3.micro",ebs_optimized:false}},
    {address:"aws_security_group.host",mode:"managed",type:"aws_security_group",values:{id:"sg-host"}},
    {address:"aws_vpc_security_group_egress_rule.to_cluster",mode:"managed",type:"aws_vpc_security_group_egress_rule",values:{id:"egress-cluster"}},
    {address:"aws_vpc_security_group_egress_rule.to_endpoints",mode:"managed",type:"aws_vpc_security_group_egress_rule",values:{id:"egress-endpoints"}},
    {address:"aws_vpc_security_group_ingress_rule.cluster",mode:"managed",type:"aws_vpc_security_group_ingress_rule",values:{id:"ingress-cluster"}},
    {address:"aws_vpc_security_group_ingress_rule.endpoints",mode:"managed",type:"aws_vpc_security_group_ingress_rule",values:{id:"ingress-endpoints"}}
  ];
  {variables:{retained_host_instance_id:{value:"i-0123456789abcdef0"}},prior_state:{values:{root_module:{resources:resources}}},planned_values:{root_module:{resources:(resources | map(if .address == "aws_vpc_security_group_ingress_rule.cluster" then .address = "aws_vpc_security_group_ingress_rule.cluster[0]" elif .address == "aws_vpc_security_group_ingress_rule.endpoints" then .address = "aws_vpc_security_group_ingress_rule.endpoints[0]" else . end))}},resource_changes:(resources | map({address:.address,mode,type,change:{actions:["no-op"],before:.values,after:.values,after_unknown:{ebs_optimized:false,id:false,instance_type:false,monitoring:false,ami:false}}}))}
' > "$scratch/valid.json"
bash "$guard" "$scratch/valid.json" >/dev/null

for mutation in \
  'del(.prior_state.values.root_module.resources)' \
  '.resource_changes[0].change.actions=["create"]' \
  '.resource_changes[0].change.actions=["delete"]' \
  '.resource_changes[0].change.actions=["delete","create"]' \
  'del(.variables.retained_host_instance_id)' \
  '.prior_state.values.root_module.resources[3].values.id="i-0123456789abcdef0"' \
  '.prior_state.values.root_module.resources[3].values.instance_type="t3.small"' \
  '.resource_changes[3].change.after.monitoring=true | .planned_values.root_module.resources[3].values.monitoring=true' \
  '.resource_changes[3].change.after.ami="ami-changed" | .planned_values.root_module.resources[3].values.ami="ami-changed"' \
  '.resource_changes[0].change.after_unknown.ebs_optimized=true' \
  '.resource_changes[0].change.after_unknown.iam_instance_profile=true' \
  '.resource_changes[4].change.after.vpc_id="vpc-changed" | .planned_values.root_module.resources[4].values.vpc_id="vpc-changed"' \
  '.planned_values.root_module.resources += [{address:"aws_instance.other",mode:"managed",type:"aws_instance",values:{id:"i-0123456789abcdef0",instance_type:"t3.micro",ebs_optimized:false}}]' \
  '.resource_changes += [{address:"aws_instance.other",mode:"managed",type:"aws_instance",change:{actions:["update"],before:{id:"i-0123456789abcdef0",instance_type:"t3.micro",ebs_optimized:true},after:{id:"i-0123456789abcdef0",instance_type:"t3.micro",ebs_optimized:false},after_unknown:{ebs_optimized:false}}}]'; do
  jq "$mutation" "$scratch/valid.json" > "$scratch/invalid.json"
  if bash "$guard" "$scratch/invalid.json" >/dev/null 2>&1; then
    printf 'unsafe retained-host plan accepted\n' >&2
    exit 1
  fi
done

printf 'PASS offline ops-access retained-host saved-plan guard.\n'
