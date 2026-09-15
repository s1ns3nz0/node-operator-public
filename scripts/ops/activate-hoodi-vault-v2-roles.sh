#!/usr/bin/env bash
# Administrator-only authorization cutover. Invoke inside the private EKS/Vault
# session after preparation and a signing-proxy fence ceremony. No scale-up.
set +x
set -euo pipefail
umask 077
dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
usage() { printf 'Usage: %s --validator-set <hoodi-id> --preparation-evidence <absolute-json>\n' "${0##*/}" >&2; exit 64; }
validator_set=''; preparation=''
while [ "$#" -gt 0 ]; do case "$1" in
  --validator-set) validator_set="${2:-}"; shift 2 ;;
  --preparation-evidence) preparation="${2:-}"; shift 2 ;;
  *) usage ;;
esac; done
[[ "$validator_set" =~ ^hoodi-[a-z0-9][a-z0-9-]{0,35}$ ]] || usage
[[ "$preparation" = /* ]] && [ -f "$preparation" ] && [ ! -L "$preparation" ] || usage
: "${VAULT_TOKEN:?A short-lived administrator token is required}"
jq -e --arg set "$validator_set" '
  .schema_version == 1 and .operation == "prepare-existing-hoodi-vault-v2" and
  .validator_set == $set and .runtime_mount == "node-operator-runtime" and
  .custody_preserved == true and .transport_verified == true and
  .engine_jwt_verified == true and .generated_root_revoked == true and
  .live_policies_changed == false and .live_workloads_changed == false and
  .secret_values_emitted == false' "$preparation" >/dev/null
"$dir/assert-hoodi-validator-quiesced.sh" --validator-set "$validator_set" >/dev/null
# Revalidate the preserved custody records against legacy before editing policy.
"$dir/copy-hoodi-custody-to-runtime-v2.sh" --validator-set "$validator_set" >/dev/null
# Reverify the current certificate chains, expiry, hostnames and key pairs.
# This mode cannot issue certificates or write Vault records.
scratch="$(mktemp -d "${TMPDIR:-/tmp}/node-operator-v2-role-check.XXXXXX")"
cleanup() {
  local rc=$?
  trap - EXIT
  find "$scratch" -type f -exec unlink {} \;
  [ ! -d "$scratch/public" ] || rmdir "$scratch/public"
  rmdir "$scratch"
  exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
"$dir/prepare-hoodi-vault-v2-transport.sh" --validator-set "$validator_set" --output-dir "$scratch/public" --verify-only >/dev/null
vault read -format=json node-operator-runtime/data/nodes/hoodi/engine-api-jwt |
  jq -e '.data.data.jwt | type == "string" and test("^[0-9a-f]{64}$")' >/dev/null
"$dir/assert-hoodi-validator-quiesced.sh" --validator-set "$validator_set" >/dev/null
"$dir/bootstrap-hoodi-engine-api-vault.sh" >/dev/null
"$dir/bootstrap-hoodi-validator-runtime-vault.sh" --validator-set "$validator_set" >/dev/null
kubectl -n validator-operations create configmap "validator-$validator_set-known-clients" \
  --from-file="known-clients=$scratch/public/known-clients.txt" --dry-run=client -o json |
  jq '{data:{"known-clients":.data["known-clients"]}}' |
  kubectl -n validator-operations patch configmap "validator-$validator_set-known-clients" --type merge --patch-file /dev/stdin >/dev/null
printf '%s\n' 'PASS: Vault v2 workload roles installed while validator client/fence were quiesced. Workload cutover and duty verification remain required.'
