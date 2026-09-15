#!/usr/bin/env bash
set -euo pipefail

# Interactive recovery-key ceremony for the Engine API JWT boundary. Recovery
# shares are read directly from the terminal and the short-lived generated root
# token is revoked on every exit path.
dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
usage() { printf 'Usage: %s\n' "${0##*/}" >&2; exit 64; }
[ "$#" -eq 0 ] || usage
if [ "${PRIVATE_VAULT_SESSION:-}" != 1 ]; then exec "$dir/with-private-vault.sh" -- env PRIVATE_VAULT_SESSION=1 "$0"; fi
for command in vault jq; do command -v "$command" >/dev/null 2>&1 || { printf 'missing command: %s\n' "$command" >&2; exit 69; }; done
started=false; complete=false; root_token=''
cleanup() {
  set +e
  [ -z "$root_token" ] || VAULT_TOKEN="$root_token" vault token revoke -self >/dev/null 2>&1
  [ "$started" = true ] && [ "$complete" != true ] && vault operator generate-root -cancel >/dev/null 2>&1
  unset VAULT_TOKEN root_token
}
trap cleanup EXIT INT TERM
# shellcheck source=scripts/ops/lib/vault-recovery-auth.sh
source "$dir/lib/vault-recovery-auth.sh"
vault_recovery_auth_preflight
status="$(vault operator generate-root -status -format=json)"
[ "$(jq -r '.started' <<<"$status")" = false ] || { printf 'root-token ceremony already in progress\n' >&2; exit 75; }
init="$(vault operator generate-root -init -format=json)"; started=true
nonce="$(jq -er .nonce <<<"$init")"; otp="$(jq -er .otp <<<"$init")"; required="$(jq -er .required <<<"$init")"
for n in $(seq 1 "$required"); do
  printf 'Recovery key share %s of %s: ' "$n" "$required" >&2
  IFS= read -r -s share; printf '\n' >&2
  submitted="$(printf %s "$share" | vault operator generate-root -nonce="$nonce" -format=json -)"; unset share
  if [ "$(jq -r .complete <<<"$submitted")" = true ]; then complete=true; encoded="$(jq -er .encoded_token <<<"$submitted")"; break; fi
done
[ "$complete" = true ] || { printf 'recovery quorum was not reached\n' >&2; exit 77; }
root_token="$(vault_recovery_decode_generated_root "$encoded" "$otp")"
unset encoded otp nonce init submitted status
VAULT_TOKEN="$root_token" PRIVATE_VAULT_SESSION=1 "$dir/bootstrap-hoodi-engine-api-vault.sh"
printf '%s\n' 'PASS: Engine API Vault bootstrap completed; generated root token will now be revoked.'
