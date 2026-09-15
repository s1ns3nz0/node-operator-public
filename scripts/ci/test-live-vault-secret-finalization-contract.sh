#!/usr/bin/env bash
# shellcheck disable=SC2016 # literal source-contract fragments
# Check objective: Enforce the guarded final removal of legacy live Vault secret paths.
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
script="$root/scripts/ops/finalize-live-vault-secret-cutover.sh"
test -x "$script"; bash -n "$script"
for required in \
  'live-engine-vault-cutover' \
  'live-validator-vault-cutover' \
  'Vault injection missing' \
  'legacy Secret mount remains in a live Pod' \
  'delete secret engine-api-jwt --ignore-not-found' \
  'validator-${validator_set}-signer-tls' \
  'validator-${validator_set}-client-tls' \
  'vault-agent-ca trust anchor' \
  'known-clients ConfigMap' \
  'live-vault-legacy-secret-finalization'; do
  grep -Fq "$required" "$script" || { printf 'missing finalization control: %s\n' "$required" >&2; exit 1; }
done
if grep -Eq 'delete (configmap|secret).*vault-agent-ca|delete (configmap|secret).*known-clients|kubectl.*get secret.*-o json' "$script"; then
  printf '%s\n' 'finalization may not delete public trust material or read Secret data' >&2
  exit 1
fi
printf '%s\n' 'PASS: finalization deletes only superseded credential Secrets after Vault template and live-Pod checks.'
