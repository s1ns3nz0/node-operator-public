#!/usr/bin/env bash
set -euo pipefail
[ "$#" -eq 1 ] || { echo "usage: $0 PLAN_JSON" >&2; exit 64; }
jq -e '
  ([.resource_changes[]? | select(.change.actions | index("create")) | .type] | any(. == "aws_nat_gateway" or . == "aws_internet_gateway") | not) as $no_public_gateway
  | ([.resource_changes[]? | select(.change.actions | index("create")) | select(.change.after.public_access == true)] | length == 0) as $no_public_access
  | $no_public_gateway and $no_public_access
' "$1" >/dev/null || { echo "plan crosses private infrastructure boundary" >&2; exit 1; }
