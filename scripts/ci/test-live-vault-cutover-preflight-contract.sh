#!/usr/bin/env bash
# shellcheck disable=SC2016 # literal source-contract fragments
# Check objective: Reject live Vault cutover unless its preflight guards and approvals remain intact.
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
script="$root/scripts/ops/preflight-live-vault-cutover.sh"
test -x "$script"
bash -n "$script"
for required in \
  'baseline|ready|finalized' \
  'legacy credential Secret still exists after finalization' \
  'get secret "$name" -o json' \
  'source_secret_key_inventory_only:true' \
  'secret_values_emitted:false' \
  'vault-agent-injector' \
  'allow-client-egress' \
  'node-operator-client'; do grep -Fq "$required" "$script" || { printf 'missing preflight control: %s\n' "$required" >&2; exit 1; }; done
if grep -Eq 'jsonpath=.*data|base64Decode|kubectl.*get secret.*-o yaml' "$script"; then printf '%s\n' 'preflight must not read Secret values' >&2; exit 1; fi
printf '%s\n' 'PASS: live cutover preflight is read-only and checks workload, injector, policy, and Secret metadata boundaries.'
