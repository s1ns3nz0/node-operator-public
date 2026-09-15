#!/usr/bin/env bash
set -euo pipefail

# Emergency recovery-key ceremony for one snapshot. It never prints or writes
# the generated root token and revokes it after the snapshot command returns.
dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
if [ "${PRIVATE_VAULT_SESSION:-}" != 1 ]; then
  exec "$dir/with-private-vault.sh" -- env PRIVATE_VAULT_SESSION=1 "$0" "$@"
fi

bucket_args=("$@")
for command in vault jq; do command -v "$command" >/dev/null 2>&1 || { printf 'missing command: %s\n' "$command" >&2; exit 69; }; done
started=false
complete=false
root_token=''
revoke_root_token() {
  local revoke_status=0

  # Deliberately do not include the token in diagnostics or command arguments.
  if VAULT_TOKEN="$root_token" vault token revoke -self >/dev/null 2>&1; then
    :
  else
    revoke_status=$?
    printf 'failed to revoke the generated root token\n' >&2
    return "$revoke_status"
  fi
  root_token=''
  unset VAULT_TOKEN
  return 0
}
cleanup() {
  local original_status=$?
  local revoke_status=0
  local cancel_status=0

  # Signal handlers exit first, then this EXIT handler preserves their status.
  trap - EXIT INT TERM
  set +e
  if [ -n "$root_token" ]; then
    if revoke_root_token; then
      :
    else
      revoke_status=$?
    fi
  fi
  if [ "$started" = true ] && [ "$complete" != true ]; then
    if vault operator generate-root -cancel >/dev/null 2>&1; then
      :
    else
      cancel_status=$?
      printf 'failed to cancel the incomplete root-token generation ceremony\n' >&2
    fi
  fi
  unset VAULT_TOKEN root_token

  # Do not mask the reason the ceremony or snapshot failed.  On an otherwise
  # successful path, cleanup failures are fatal so success cannot be reported.
  if [ "$original_status" -ne 0 ]; then
    exit "$original_status"
  fi
  if [ "$revoke_status" -ne 0 ]; then
    exit "$revoke_status"
  fi
  if [ "$cancel_status" -ne 0 ]; then
    exit "$cancel_status"
  fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# shellcheck source=lib/vault-recovery-auth.sh
source "$dir/lib/vault-recovery-auth.sh"
vault_recovery_auth_preflight
status="$(vault operator generate-root -status -format=json)"
[ "$(jq -r '.started' <<<"$status")" = false ] || { printf 'a root-token generation ceremony is already in progress; finish or cancel it first\n' >&2; exit 75; }
init="$(vault operator generate-root -init -format=json)"
started=true
nonce="$(jq -er '.nonce' <<<"$init")"
otp="$(jq -er '.otp' <<<"$init")"
required="$(jq -er '.required' <<<"$init")"
for number in $(seq 1 "$required"); do
  printf 'Recovery key share %s of %s: ' "$number" "$required" >&2
  IFS= read -r -s share; printf '\n' >&2
  submitted="$(printf '%s' "$share" | vault operator generate-root -nonce="$nonce" -format=json -)"
  unset share
  if [ "$(jq -r '.complete' <<<"$submitted")" = true ]; then
    complete=true
    encoded="$(jq -er '.encoded_token' <<<"$submitted")"
    break
  fi
done
[ "$complete" = true ] || { printf 'recovery quorum was not reached\n' >&2; exit 77; }
root_token="$(vault_recovery_decode_generated_root "$encoded" "$otp")"
[ -n "$root_token" ] || { printf 'root-token decode returned an empty value\n' >&2; exit 78; }
unset encoded otp nonce init submitted status
VAULT_TOKEN="$root_token" "$dir/save-private-vault-raft-snapshot.sh" "${bucket_args[@]}"
revoke_root_token
printf 'PASS: generated root token was revoked after the snapshot ceremony.\n'
