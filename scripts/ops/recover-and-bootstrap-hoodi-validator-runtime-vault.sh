#!/usr/bin/env bash
set -euo pipefail
# Recovery-key ceremony for one Hoodi set. It never prints or persists keys/tokens.
dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
usage() { printf 'Usage: %s --validator-set <hoodi-id>\n' "${0##*/}" >&2; exit 64; }
set_id=''
while [ "$#" -gt 0 ]; do case "$1" in --validator-set) set_id="${2:-}"; shift 2;; *) usage;; esac; done
case "$set_id" in hoodi-[a-z0-9][a-z0-9-]*) ;; *) usage;; esac
if [ "${PRIVATE_VAULT_SESSION:-}" != 1 ]; then exec "$dir/with-private-vault.sh" -- env PRIVATE_VAULT_SESSION=1 "$0" --validator-set "$set_id"; fi
for x in vault jq; do command -v "$x" >/dev/null || { printf 'missing command: %s\n' "$x" >&2; exit 69; }; done
started=false; complete=false; root_token=''
cleanup() { set +e; [ -z "$root_token" ] || VAULT_TOKEN="$root_token" vault token revoke -self >/dev/null 2>&1; [ "$started" = true ] && [ "$complete" != true ] && vault operator generate-root -cancel >/dev/null 2>&1; unset VAULT_TOKEN root_token; }
trap cleanup EXIT INT TERM
# shellcheck source=scripts/ops/lib/vault-recovery-auth.sh
source "$dir/lib/vault-recovery-auth.sh"
vault_recovery_auth_preflight
status="$(vault operator generate-root -status -format=json)"
[ "$(jq -r '.started' <<<"$status")" = false ] || { printf 'root-token ceremony already in progress\n' >&2; exit 75; }
init="$(vault operator generate-root -init -format=json)"; started=true
nonce="$(jq -er .nonce <<<"$init")"; otp="$(jq -er .otp <<<"$init")"; required="$(jq -er .required <<<"$init")"
for n in $(seq 1 "$required"); do
  printf 'Recovery key share %s of %s: ' "$n" "$required" >&2; IFS= read -r -s share; printf '\n' >&2
  submitted="$(printf %s "$share" | vault operator generate-root -nonce="$nonce" -format=json -)"; unset share
  if [ "$(jq -r .complete <<<"$submitted")" = true ]; then complete=true; encoded="$(jq -er .encoded_token <<<"$submitted")"; break; fi
done
[ "$complete" = true ] || { printf 'recovery quorum was not reached\n' >&2; exit 77; }
root_token="$(vault_recovery_decode_generated_root "$encoded" "$otp")"; unset encoded otp nonce init submitted status
VAULT_TOKEN="$root_token" PRIVATE_VAULT_SESSION=1 "$dir/bootstrap-hoodi-validator-runtime-vault.sh" --validator-set "$set_id"
printf 'PASS: Hoodi runtime Vault bootstrap completed; generated root token will now be revoked.\n'
