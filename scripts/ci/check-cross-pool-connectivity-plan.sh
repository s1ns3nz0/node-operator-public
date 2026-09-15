#!/usr/bin/env bash
set -euo pipefail
if [ "$#" -ne 3 ]; then printf 'usage: %s PLAN_JSON SYSTEM_SG HOODI_SG\n' "$0" >&2; exit 64; fi
[[ "$2" =~ ^sg-[0-9a-f]+$ && "$3" =~ ^sg-[0-9a-f]+$ && "$2" != "$3" ]]
jq -e --arg system "$2" --arg hoodi "$3" '
  [
    {name:"hoodi_prysm_health_from_system",destination:$hoodi,source:$system,port:3500},
    {name:"hoodi_p2p_probe_from_system",destination:$hoodi,source:$system,port:30303},
    {name:"hoodi_vault_ha_from_system",destination:$hoodi,source:$system,port:8201},
    {name:"system_vault_ha_from_hoodi",destination:$system,source:$hoodi,port:8201}
  ] as $expected |
  [.resource_changes[] | select(.mode == "managed" and .change.actions != ["no-op"])] as $changes |
  ($changes | length) == 4 and
  all($expected[]; . as $rule |
    [$changes[] | select(.address == ("aws_vpc_security_group_ingress_rule." + $rule.name))] as $matches |
    ($matches | length) == 1 and ($matches[0] |
      .type == "aws_vpc_security_group_ingress_rule" and .change.actions == ["create"] and
      .change.after.security_group_id == $rule.destination and
      .change.after.referenced_security_group_id == $rule.source and
      .change.after.ip_protocol == "tcp" and
      .change.after.from_port == $rule.port and .change.after.to_port == $rule.port and
      .change.after.cidr_ipv4 == null and .change.after.cidr_ipv6 == null and
      .change.after.prefix_list_id == null and
      .change.after_unknown.cidr_ipv4 != true and .change.after_unknown.cidr_ipv6 != true and
      .change.after_unknown.prefix_list_id != true))
' "$1" >/dev/null
printf 'PASS exact four SG-reference TCP creates; no other managed changes.\n'
