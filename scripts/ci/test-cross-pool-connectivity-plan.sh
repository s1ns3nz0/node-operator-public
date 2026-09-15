#!/usr/bin/env bash
# Check objective: Reject Terraform plans that widen or misdirect cross-pool connectivity.
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
checker="$root/scripts/ci/check-cross-pool-connectivity-plan.sh"
scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT
jq -n '
  {resource_changes:([
    ["hoodi_prysm_health_from_system","sg-002","sg-001",3500],
    ["hoodi_p2p_probe_from_system","sg-002","sg-001",30303],
    ["hoodi_vault_ha_from_system","sg-002","sg-001",8201],
    ["system_vault_ha_from_hoodi","sg-001","sg-002",8201]
  ] | map({address:("aws_vpc_security_group_ingress_rule."+.[0]),mode:"managed",type:"aws_vpc_security_group_ingress_rule",
    change:{actions:["create"],after:{security_group_id:.[1],referenced_security_group_id:.[2],from_port:.[3],to_port:.[3],ip_protocol:"tcp"}}}))}
' > "$scratch/valid.json"
bash "$checker" "$scratch/valid.json" sg-001 sg-002 >/dev/null
for mutation in \
  '.resource_changes[0].change.after.cidr_ipv4="0.0.0.0/0"' \
  '.resource_changes[0].change.after.cidr_ipv6="::/0"' \
  '.resource_changes[0].change.after.prefix_list_id="pl-123"' \
  '.resource_changes[0].change.after_unknown={cidr_ipv4:true}' \
  '.resource_changes[0].change.after.ip_protocol="udp"' \
  '.resource_changes[0].change.after.to_port=3501' \
  '.resource_changes[0].change.after.referenced_security_group_id="sg-003"' \
  '.resource_changes[0].change.actions=["delete","create"]' \
  '.resource_changes[0].change.actions=["update"]' \
  '.resource_changes[0].change.after.security_group_id=null' \
  '.resource_changes += [{address:"aws_security_group.nodes",mode:"managed",change:{actions:["update"]}}]' \
  '.resource_changes[1]=.resource_changes[0]'; do
  jq "$mutation" "$scratch/valid.json" > "$scratch/invalid.json"
  if bash "$checker" "$scratch/invalid.json" sg-001 sg-002 >/dev/null 2>&1; then
    printf 'FAIL unsafe cross-pool plan accepted\n' >&2; exit 1
  fi
done
printf 'PASS cross-pool plan rejects broad ingress, wrong directions, duplicates and dependency changes.\n'
