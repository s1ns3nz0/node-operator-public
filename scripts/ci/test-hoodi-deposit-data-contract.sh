#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
validator="$root/scripts/ops/validate-hoodi-deposit-data.sh"
tmp="$(mktemp -d /private/tmp/node-operator-deposit-data.XXXXXX)"
trap 'rm -rf "$tmp"' EXIT

pubkey="$(printf 'a%.0s' {1..96})"
withdrawal='403ff64383b8ddf994d5563550c8040d89f025ac'
credentials="010000000000000000000000${withdrawal}"
jq -n --arg pubkey "$pubkey" --arg credentials "$credentials" \
  '[{network_name:"hoodi",amount:32000000000,pubkey:$pubkey,withdrawal_credentials:$credentials}]' > "$tmp/standard.json"
"$validator" --deposit-data "$tmp/standard.json" --withdrawal-address "0x${withdrawal}" --output-dir "$tmp/evidence" >/dev/null
jq -e --arg key "0x${pubkey}" --arg credentials "0x${credentials}" \
  '.validator_public_key == $key and .withdrawal_credentials == $credentials' "$tmp/evidence/uc-1-deposit-attestation.json" >/dev/null
jq '.[] .pubkey = "not-a-public-key"' "$tmp/standard.json" > "$tmp/invalid.json"
if "$validator" --deposit-data "$tmp/invalid.json" --withdrawal-address "0x${withdrawal}" --output-dir "$tmp/invalid-evidence" >/dev/null 2>&1; then
  printf '%s\n' 'invalid deposit public key was accepted' >&2
  exit 1
fi
printf '%s\n' 'PASS: Hoodi deposit validation accepts standard byte strings, normalizes public evidence, and rejects malformed public keys.'
