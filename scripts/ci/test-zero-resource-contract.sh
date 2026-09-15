#!/usr/bin/env bash
# Check objective: Enforce the baseline infrastructure contract without external replacement resources.
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
contract="$root/infra/baseline/variables.tf"
network="$root/infra/foundation-network/main.tf"
test -f "$contract"
grep -F 'variable "foundation_network"' "$contract" >/dev/null
grep -F 'system_subnet_ids' "$contract" >/dev/null
grep -F 'hoodi_subnet_ids' "$contract" >/dev/null
grep -F 'aws_nat_gateway' "$network" >/dev/null
if grep -n 'variable "hoodi_nat_gateway_id"' "$root"/infra/baseline/*.tf; then
  printf 'replacement baseline must not accept an external NAT gateway\n' >&2
  exit 1
fi
printf 'PASS zero-resource foundation and replacement-baseline boundary.\n'
