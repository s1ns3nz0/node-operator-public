#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 1 ]; then
  printf 'usage: %s PLAN_JSON\n' "$0" >&2
  exit 64
fi

plan="$1"
test -f "$plan" || { printf 'missing plan JSON: %s\n' "$plan" >&2; exit 1; }

# This intentionally accepts only the reviewed nine-resource representation.
# It is a release guard, not a general Terraform plan validator.
jq -e '
  . as $plan |
  def expected:
    {
      "aws_iam_instance_profile.host":"aws_iam_instance_profile",
      "aws_iam_role.host":"aws_iam_role",
      "aws_iam_role_policy_attachment.ssm":"aws_iam_role_policy_attachment",
      "aws_instance.host":"aws_instance",
      "aws_security_group.host":"aws_security_group",
      "aws_vpc_security_group_egress_rule.to_cluster":"aws_vpc_security_group_egress_rule",
      "aws_vpc_security_group_egress_rule.to_endpoints":"aws_vpc_security_group_egress_rule",
      "aws_vpc_security_group_ingress_rule.cluster[0]":"aws_vpc_security_group_ingress_rule",
      "aws_vpc_security_group_ingress_rule.endpoints[0]":"aws_vpc_security_group_ingress_rule"
    };
  def normalized_address:
    if . == "aws_vpc_security_group_ingress_rule.cluster" then "aws_vpc_security_group_ingress_rule.cluster[0]"
    elif . == "aws_vpc_security_group_ingress_rule.endpoints" then "aws_vpc_security_group_ingress_rule.endpoints[0]"
    else . end;
  def managed_resources: [.. | objects | .resources?[]? | select(.mode == "managed")];
  def resource_map: reduce .[] as $r ({}; .[$r.address | normalized_address] = $r);
  def without_permitted_metadata: del(.description?, .tags?, .tags_all?);
  def no_guarded_unknown:
    [paths(scalars) as $path | select(getpath($path) == true and
      (["description", "tags", "tags_all"] | index($path[0]) | not))] | length == 0;
  def change_map: reduce .[] as $r ({}; .[$r.address | normalized_address] = $r);

  expected as $expected |
  ($expected | keys | sort) as $addresses |
  "aws_instance.host" as $host |
  "i-0123456789abcdef0" as $host_id |
  ($plan.prior_state.values.root_module | managed_resources) as $before |
  ($plan.planned_values.root_module | managed_resources) as $planned |
  [$plan.resource_changes[]? | select(.mode == "managed")] as $changes |
  ($before | resource_map) as $before_map |
  ($planned | resource_map) as $planned_map |
  ($changes | change_map) as $change_map |
  ($plan.variables.retained_host_instance_id.value? == $host_id) and
  ($before_map | keys | sort) == $addresses and
  ($planned_map | keys | sort) == $addresses and
  ($change_map | keys | sort) == $addresses and
  ($before | length) == 9 and ($planned | length) == 9 and ($changes | length) == 9 and
  (all($addresses[]; $before_map[.].type == $expected[.] and $planned_map[.].type == $expected[.] and $change_map[.].type == $expected[.])) and
  (all($addresses[];
    ($before_map[.].values.id | type == "string" and length > 0) and
    $before_map[.].values.id == $planned_map[.].values.id and
    $before_map[.].values.id == $change_map[.].change.before.id and
    $planned_map[.].values.id == $change_map[.].change.after.id)) and
  (all($addresses[]; $change_map[.].change.before == $before_map[.].values and $change_map[.].change.after == $planned_map[.].values)) and
  (all($addresses[]; $change_map[.].change.after_unknown | no_guarded_unknown)) and
  ($before_map[$host].values.id == $host_id) and
  ($before_map[$host].values.instance_type == "t3.micro") and
  ($before_map[$host].values.ebs_optimized == false) and
  ($planned_map[$host].values == $before_map[$host].values) and
  ($change_map[$host].change.actions == ["no-op"]) and
  ($change_map[$host].change.before == $change_map[$host].change.after) and
  (all($addresses[] | select(. != $host);
    ($change_map[.].change.actions == ["no-op"] or $change_map[.].change.actions == ["update"]) and
    ($change_map[.].change.before | without_permitted_metadata) ==
      ($change_map[.].change.after | without_permitted_metadata)))
' "$plan" >/dev/null

printf 'PASS ops-access retained-host plan is identity-bound and non-destructive.\n'
