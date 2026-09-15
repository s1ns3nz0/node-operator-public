#!/usr/bin/env bash
# Check objective: Run Terraform security-policy fixtures through the reviewed OPA policy suite.
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$script_dir/lib/common.sh"
root="$(repo_root)"
require_command opa

# The policy permits an operationally stopped dedicated pool, but Terraform's
# initial intent must still provision the paired Hoodi nodes and Vault HA pool.
grep -A8 'variable "system_node_desired_size"' "$root/infra/terraform/variables.tf" | grep -Eq 'default[[:space:]]*=[[:space:]]*3'
for pool in consensus execution; do
  grep -A8 "variable \"${pool}_node_desired_size\"" "$root/infra/terraform/variables.tf" | grep -Eq 'default[[:space:]]*=[[:space:]]*1'
  grep -A8 "variable \"${pool}_node_min_size\"" "$root/infra/terraform/variables.tf" | grep -Eq 'default[[:space:]]*=[[:space:]]*0'
done

opa test --fail-on-empty --ignore fixtures "$root/policy"
opa eval --format=json --data "$root/policy/terraform" --input "$root/policy/tests/fixtures/terraform-baseline-secure.json" 'data.nodeoperator.terraform.deny' | jq -e '.result[0].expressions[0].value == []' >/dev/null
for fixture in "$root"/policy/tests/fixtures/terraform-baseline-{broad-iam,invalid-node-group,public-endpoint,unencrypted}.json; do
  opa eval --format=json --data "$root/policy/terraform" --input "$fixture" 'data.nodeoperator.terraform.deny' | jq -e '.result[0].expressions[0].value | length > 0' >/dev/null
done
