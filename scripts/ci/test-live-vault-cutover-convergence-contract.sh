#!/usr/bin/env bash
# shellcheck disable=SC2016 # literal source-contract fragments
# Check objective: Require post-cutover Vault runtime convergence before finalization.
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
script="$root/scripts/ops/verify-live-vault-cutover-convergence.sh"
test -x "$script"; bash -n "$script"
for required in \
  'live-engine-vault-cutover' \
  'live-validator-vault-cutover' \
  'live-vault-legacy-secret-finalization' \
  '--phase finalized' \
  'legacy_credential_secrets_absent == true' \
  'secret_values_emitted == false' \
  'live-vault-cutover-convergence'; do
  grep -Fq -- "$required" "$script" || { printf 'missing convergence control: %s\n' "$required" >&2; exit 1; }
done
if grep -Eq 'vault kv|get secret.*-o json|kubectl.*logs' "$script"; then
  printf '%s\n' 'convergence must be evidence and metadata only' >&2
  exit 1
fi
printf '%s\n' 'PASS: final convergence is read-only, evidence-bound, and verifies finalized metadata without credential reads.'
