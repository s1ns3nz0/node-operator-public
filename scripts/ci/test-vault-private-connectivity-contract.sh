#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$script_dir/lib/common.sh"
root="$(repo_root)"
fail() { printf 'FAIL Vault private connectivity contract: %s\n' "$*" >&2; exit 1; }

contract="$root/docs/gitops/vault-private-connectivity-contract.md"
values="$root/docs/gitops/vault-values.example.yaml"
runner_contract="$root/docs/gitops/private-release-runner-contract.md"
for file in "$contract" "$values" "$runner_contract"; do
  test -f "$file" || fail "missing required contract: $file"
done

for required in \
  "\`vault.node-operator.internal\`" \
  '**HTTPS/TCP 8200** only' \
  'internal gateway or private endpoint' \
  "existing Kubernetes \`ClusterIP\` service" \
  'public Internet DNS' \
  'private hosted zone is split-horizon' \
  'public DNS has no record' \
  'No endpoint address' \
  'load-balancer address' \
  'route target belongs in this repository' \
  "\`vault-tls\`" \
  'approved private CA' \
  'certificate subject/SAN includes exactly' \
  'SNI' \
  'rotation procedure' \
  'expiration probe' \
  'self-hosted release runner and CodeBuild are separate sources' \
  'distinct route, security-group rule' \
  "\`0.0.0.0/0\`" \
  'NAT/public fallback' \
  'Vault then authenticates and authorizes each request' \
  'source-network access alone never' \
  'grants a token or signing permission' \
  'Raft is separate from the release API route' \
  'TCP 8201 is permitted only' \
  'Vault server pods' \
  '**DNS probe:**' \
  '**TLS probe:**' \
  '**Route probe:**' \
  '**Audit correlation probe:**' \
  'fail-closed' \
  'authorized rollout work'; do
  grep -Fq "$required" "$contract" || fail "omits required control: $required"
done

grep -Fqx '    type: ClusterIP' "$values" || fail 'Vault values must retain ClusterIP service exposure'
grep -Fqx '    enabled: false' "$values" || fail 'Vault values must retain disabled ingress'
grep -Fq "\`vault.node-operator.internal\`" "$runner_contract" || fail 'runner contract must use the same private Vault hostname'

if grep -Eq '(https?://|[[:space:]](LoadBalancer|NodePort)[[:space:]]|[[:space:]]-[[:space:]]*k([[:space:]]|`)|AWS_(ACCESS|SECRET)_ACCESS_KEY|vault[[:space:]_-]*token[[:space:]]*=)' "$contract"; then
  fail 'contains a URL, public service type, TLS bypass, or static credential pattern'
fi

# The contract deliberately bans the all-address CIDR but records no other
# concrete endpoint address; an address would be environment-owned state.
addresses="$(grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' "$contract" || true)"
if test -n "$addresses" && test "$(printf '%s\n' "$addresses" | grep -Fvx '0.0.0.0' || true)" != ""; then
  fail 'must not record a concrete endpoint address'
fi

printf 'PASS Vault private connectivity contract is constrained and fail-closed.\n'
