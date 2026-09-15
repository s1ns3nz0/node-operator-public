#!/usr/bin/env bash
set +x
set -euo pipefail
umask 077

# Creates one Hoodi Engine API JWT inside Vault and grants it only to the
# paired Nethermind and Prysm Beacon service accounts.  The secret is never
# printed, written to Kubernetes, or accepted from command-line arguments.
usage() { printf 'Usage: %s [--prepare-only]\n' "${0##*/}" >&2; exit 64; }
prepare_only=false
if [ "$#" -eq 1 ] && [ "$1" = --prepare-only ]; then prepare_only=true
elif [ "$#" -ne 0 ]; then usage; fi
for command in vault openssl jq mktemp rm; do command -v "$command" >/dev/null 2>&1 || { printf 'missing command: %s\n' "$command" >&2; exit 69; }; done
: "${VAULT_ADDR:?VAULT_ADDR must name the private Vault endpoint}"
: "${VAULT_TOKEN:?Supply a short-lived Vault administrator token through the secure environment}"

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
policy="$root/deploy/vault/policies/hoodi-engine-api.hcl"
nethermind_role="$root/deploy/vault/auth/hoodi-engine-nethermind-kubernetes-role.json"
prysm_role="$root/deploy/vault/auth/hoodi-engine-prysm-kubernetes-role.json"
payload="$(mktemp "${TMPDIR:-/tmp}/node-operator-engine-jwt.XXXXXX")"
cleanup() { rm -f "$payload"; unset VAULT_TOKEN; }
trap cleanup EXIT INT TERM

"$root/scripts/ops/ensure-node-operator-runtime-kv-v2.sh" >/dev/null
if [ "$prepare_only" = false ]; then
vault read -format=json auth/kubernetes/config >/dev/null
vault policy write hoodi-engine-api "$policy" >/dev/null
vault write auth/kubernetes/role/hoodi-engine-nethermind @"$nethermind_role" >/dev/null
vault write auth/kubernetes/role/hoodi-engine-prysm @"$prysm_role" >/dev/null
fi

if engine_record="$(vault read -format=json node-operator-runtime/data/nodes/hoodi/engine-api-jwt 2>/dev/null)"; then
  jwt="$(jq -er '.data.data.jwt | select(test("^[0-9a-f]{64}$"))' <<<"$engine_record")"
else
  jwt="$(openssl rand -hex 32)"
  jq -n --arg jwt "$jwt" '{options:{cas:0},data:{jwt:$jwt}}' > "$payload"
  vault write node-operator-runtime/data/nodes/hoodi/engine-api-jwt @"$payload" >/dev/null
fi
vault read -format=json node-operator-runtime/data/nodes/hoodi/engine-api-jwt > "$payload"
[ "$(jq -er '.data.data.jwt' "$payload")" = "$jwt" ] || exit 65
unset jwt engine_record
if [ "$prepare_only" = true ]; then
  printf '%s\n' 'PASS: staged Engine JWT verified; live roles and workloads unchanged. Coordinated Engine cutover is required.'
  exit 0
fi
printf '%s\n' 'PASS: Vault Engine API JWT and the isolated Nethermind/Prysm Kubernetes roles are configured. The JWT was not emitted.'
