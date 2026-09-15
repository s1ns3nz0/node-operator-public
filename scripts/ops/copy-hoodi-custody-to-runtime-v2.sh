#!/usr/bin/env bash
# Preserve the existing signing identity and database credential. No workload
# or policy is changed here; the caller owns fencing and its admin ceremony.
set +x
set -euo pipefail
umask 077
dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
[ "$#" = 2 ] && [ "$1" = --validator-set ] || { printf 'Usage: %s --validator-set <hoodi-id>\n' "${0##*/}" >&2; exit 64; }
validator_set="$2"
[[ "$validator_set" =~ ^hoodi-[a-z0-9][a-z0-9-]{0,35}$ ]] || exit 64
: "${VAULT_TOKEN:?A short-lived administrator token is required}"
for command in vault jq mktemp; do command -v "$command" >/dev/null || exit 69; done
scratch="$(mktemp -d "${TMPDIR:-/tmp}/node-operator-custody-copy.XXXXXX")"
cleanup() {
  local rc=$?
  trap - EXIT
  find "$scratch" -type f -exec unlink {} \;
  rmdir "$scratch"
  exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP
mounts="$(vault secrets list -format=json)"
legacy_version="$(jq -er '."kv/" | select(.type == "kv") | (.options.version // "1") | tostring | select(. == "1" or . == "2")' <<<"$mounts")"
base="validators/hoodi/$validator_set/runtime"

# Read and validate every source before enabling or writing the destination.
for record in keystore password slashing-db-password; do
  source_path="kv/$base/$record"
  [ "$legacy_version" = 1 ] || source_path="kv/data/$base/$record"
  vault read -format=json "$source_path" > "$scratch/source"
  if [ "$legacy_version" = 1 ]; then
    jq -e '.data' "$scratch/source" > "$scratch/$record"
  else
    jq -e '.data.data' "$scratch/source" > "$scratch/$record"
  fi
  field=password; [ "$record" != keystore ] || field=keystore
  jq -e --arg field "$field" 'type == "object" and (.[$field] | type == "string" and length > 0)' "$scratch/$record" >/dev/null
done
"$dir/ensure-node-operator-runtime-kv-v2.sh" >/dev/null

# CAS=0 makes retry safe: an existing value must match; it is never overwritten.
for record in keystore password slashing-db-password; do
  destination="node-operator-runtime/data/$base/$record"
  if vault read -format=json "$destination" > "$scratch/existing" 2>/dev/null; then
    jq -e --slurpfile expected "$scratch/$record" '.data.data == $expected[0]' "$scratch/existing" >/dev/null || {
      printf 'Destination differs; refusing to replace %s.\n' "$record" >&2; exit 65;
    }
  else
    jq '{options:{cas:0},data:.}' "$scratch/$record" > "$scratch/payload"
    vault write "$destination" @"$scratch/payload" >/dev/null
  fi
  vault read -format=json "$destination" > "$scratch/verified"
  jq -e --slurpfile expected "$scratch/$record" '.data.data == $expected[0]' "$scratch/verified" >/dev/null
done
printf '%s\n' 'PASS: existing keystore, keystore password, and slashing DB credential copied and verified unchanged. Legacy records retained.'
