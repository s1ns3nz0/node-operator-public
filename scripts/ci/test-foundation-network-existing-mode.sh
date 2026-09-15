#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
if [ "$#" -gt 1 ]; then
  printf 'usage: %s [MODULE_DIRECTORY]\n' "$0" >&2
  exit 64
fi
module="${1:-$root/infra/foundation-network}"
test -d "$module" || { printf 'missing module directory: %s\n' "$module" >&2; exit 1; }

terraform -chdir="$module" fmt -check -recursive
terraform -chdir="$module" validate >/dev/null

# The exact existing-mode resource boundary is deliberately source-rendered:
# data sources cannot be read in an offline contract test.
for address in aws_subnet.nat aws_eip.hoodi_nat aws_internet_gateway.nat aws_route_table.public aws_route_table_association.public aws_nat_gateway.hoodi; do
  grep -F "\"$address\"" "$module/outputs.tf" >/dev/null
done
test "$(grep -c '^resource "aws_' "$module/main.tf")" -eq 13
grep -E 'count[[:space:]]*=[[:space:]]*local\.existing_mode \? 0 : 1' "$module/main.tf" >/dev/null
test "$(grep -c 'count.*local.existing_mode.*0' "$module/security.tf")" -eq 6
test "$(grep -c 'prevent_destroy = true' "$module/main.tf")" -eq 7
grep -F 'availability_zone == var.existing_network.nat_public_subnet_az' "$module/main.tf" >/dev/null
grep -F 'length(distinct([for configured in var.existing_network.private_subnets : configured.id]))' "$module/main.tf" >/dev/null
grep -F 'network_mode=existing requires existing_network' "$module/main.tf" >/dev/null
grep -F 'Baseline-owned objects are data only in existing mode.' "$module/main.tf" >/dev/null
moved_compact="$(tr '\n' ' ' < "$module/moved.tf")"
for move in 'from = aws_vpc.this[[:space:]]+to   = aws_vpc.this\[0\]' 'from = aws_subnet.hoodi[[:space:]]+to   = aws_subnet.hoodi\[0\]' 'from = aws_flow_log.foundation[[:space:]]+to   = aws_flow_log.foundation\[0\]'; do
  printf '%s\n' "$moved_compact" | grep -E "$move" >/dev/null
done
for invalid in 'network_mode must be either fresh or existing' 'existing_network requires VPC/CIDR'; do
  grep -F "$invalid" "$module/variables.tf" >/dev/null
done
printf 'PASS foundation existing mode preserves fresh moves and the six-resource public-edge boundary.\n'
