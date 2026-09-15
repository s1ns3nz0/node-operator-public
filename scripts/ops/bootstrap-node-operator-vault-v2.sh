#!/usr/bin/env bash
set -euo pipefail
umask 077

# Bootstrap only the two isolated mounts used by fresh workloads. It never
# modifies legacy kv/, writes custody payloads, or exposes issuer material.
[ "$#" -eq 0 ] || { printf 'Usage: %s\n' "${0##*/}" >&2; exit 64; }
for command in vault jq; do command -v "$command" >/dev/null 2>&1 || { printf 'missing command: %s\n' "$command" >&2; exit 69; }; done
: "${VAULT_TOKEN:?Supply a short-lived Vault administrator token through the secure environment}"
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
"$root/scripts/ops/ensure-node-operator-runtime-kv-v2.sh" >/dev/null
mounts="$(vault secrets list -format=json)"
if jq -e '."node-operator-pki/"' <<<"$mounts" >/dev/null; then
  jq -e '."node-operator-pki/" | select(.type == "pki")' <<<"$mounts" >/dev/null || { printf '%s\n' 'node-operator-pki/ exists with the wrong engine type' >&2; exit 65; }
else
  vault secrets enable -path=node-operator-pki pki >/dev/null
fi
vault secrets tune -max-lease-ttl=8760h node-operator-pki/ >/dev/null
if ! vault read -format=json node-operator-pki/cert/ca >/dev/null 2>&1; then
  vault write -field=certificate node-operator-pki/root/generate/internal \
    common_name='node-operator Hoodi mTLS root' ttl=8760h >/dev/null
fi
vault write node-operator-pki/roles/validator-mtls \
  allowed_domains='validator-operations.svc,validator-operations.svc.cluster.local' \
  allow_subdomains=true allow_bare_domains=true allow_localhost=false \
  server_flag=true client_flag=true max_ttl=720h >/dev/null
printf '%s\n' 'PASS: isolated KV v2 runtime and PKI mounts are ready; legacy kv/ was not modified.'
