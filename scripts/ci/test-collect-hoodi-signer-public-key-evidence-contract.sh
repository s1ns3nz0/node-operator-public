#!/usr/bin/env bash
# Check objective: Ensure signer identity evidence is a disposable Vault-injected mTLS GET-only probe.
# shellcheck disable=SC2016 # literal source-contract fragments
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
script="$root/scripts/ops/collect-hoodi-signer-public-key-evidence.sh"
test -x "$script"; bash -n "$script"
for required in \
  'GET of the public signer key' \
  'serviceAccountName:"validator-client"' \
  'app.kubernetes.io/component":"validator-signing-fence"' \
  'node-operator.io/vault-client":"true"' \
  'agent-inject-secret-tls.crt' \
  'client-tls' \
  'vault-agent-init' \
  'public_key_match == true' \
  'sanitized Pod status follows' \
  'waiting_reason' \
  'terminated_reason' \
  'exit_code' \
  'preconditions:{uid:$uid}' \
  'no signature, keystore, client key, or Vault response retained'; do
  grep -Fq "$required" "$script" || { printf 'missing signer-public-key evidence boundary: %s\n' "$required" >&2; exit 1; }
done
if grep -Eq 'get secret.*client-tls|create secret generic|vault kv get|--validators/.*/sign' "$script"; then
  printf '%s\n' 'signer evidence probe must use Vault injection and never request signing or Secret data' >&2
  exit 1
fi
printf '%s\n' 'PASS: signer identity evidence uses one disposable Vault-injected mTLS GET-only probe.'
