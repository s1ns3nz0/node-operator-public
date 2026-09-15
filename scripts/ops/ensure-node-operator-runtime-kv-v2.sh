#!/usr/bin/env bash
set -euo pipefail
umask 077

# Creates or verifies the isolated runtime mount. It intentionally never
# changes the historical `kv/` mount, which may serve unrelated consumers.
[ "$#" -eq 0 ] || { printf 'Usage: %s\n' "${0##*/}" >&2; exit 64; }
for command in vault jq; do command -v "$command" >/dev/null 2>&1 || { printf 'missing command: %s\n' "$command" >&2; exit 69; }; done
: "${VAULT_TOKEN:?Supply a short-lived Vault administrator token through the secure environment}"
mount='node-operator-runtime'
mounts="$(vault secrets list -format=json)"
if jq -e --arg mount "${mount}/" 'has($mount)' <<<"$mounts" >/dev/null; then
  jq -e --arg mount "${mount}/" '.[$mount] | select(.type == "kv") | (.options.version // "1") | tostring | select(. == "2")' <<<"$mounts" >/dev/null || {
    printf '%s\n' 'node-operator-runtime/ exists but is not a KV v2 mount' >&2
    exit 65
  }
else
  vault secrets enable -path="$mount" -version=2 kv >/dev/null
fi
# A newly enabled KV v2 engine reports zero to select Vault's default retention.
vault read -format=json "${mount}/config" | jq -e '.data.max_versions | tonumber? | select(. >= 0)' >/dev/null
printf '%s\n' 'PASS: isolated node-operator-runtime/ KV v2 mount is ready; legacy kv/ was not modified.'
