#!/usr/bin/env bash
# USER-RUN ONLY. Recovery shares are read from /dev/tty, never arguments or logs.
set +x
set -euo pipefail
umask 077
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
inside=false
if [ "${1:-}" = --inside ]; then inside=true; shift; fi
if [ "$#" -ne 2 ] || [ "$1" != --evidence-dir ] || [[ "$2" != /* ]]; then
  printf 'Usage: recover-and-run-hoodi-uc5.sh --evidence-dir <new-absolute-directory>\n' >&2
  exit 64
fi
evidence_dir="$2"
if [ "$inside" = false ]; then
  [ ! -e "$evidence_dir" ] && [ ! -L "$evidence_dir" ] || { printf 'Use a new evidence directory.\n' >&2; exit 64; }
  mkdir -m 700 "$evidence_dir"
  exec "$script_dir/with-private-vault-operator.sh" -- bash "$0" --inside --evidence-dir "$evidence_dir"
fi
[ "${PRIVATE_VAULT_SESSION:-}" = 1 ] || exit 64
for command in vault jq python3; do
  command -v "$command" >/dev/null 2>&1 || { printf 'missing command: %s\n' "$command" >&2; exit 69; }
done
python3 "$script_dir/run-hoodi-uc5-ceremony.py" preflight --evidence-dir "$evidence_dir"
{ exec 9<>/dev/tty; } 2>/dev/null || { printf 'An interactive terminal is required.\n' >&2; exit 69; }
printf 'UC-5 will pause this validator, revoke only its signer runtime role, and restore it. Client/Fence remain stopped pending activation checks. Type UC5 to continue: ' >&9
IFS= read -r confirmation <&9
[ "$confirmation" = UC5 ] || exit 64
unset confirmation
source "$script_dir/lib/vault-recovery-auth.sh"
started=false
complete=false
root_token=''
cleanup() {
  local original_status=$?
  local cleanup_status=0
  trap - EXIT INT TERM HUP
  set +e
  unset share
  if [ -n "$root_token" ]; then
    UC5_USER_RECOVERY=1 VAULT_TOKEN="$root_token" python3 "$script_dir/run-hoodi-uc5-ceremony.py" cleanup-root >/dev/null 2>&1 || cleanup_status=1
  fi
  if [ "$started" = true ] && [ "$complete" != true ]; then
    vault operator generate-root -cancel >/dev/null 2>&1 || cleanup_status=1
  fi
  unset root_token encoded otp nonce init submitted status
  exec 9>&-
  if [ "$cleanup_status" -ne 0 ]; then
    printf 'CRITICAL: recovery credential cleanup unconfirmed; do not activate.\n' >&2
    exit 1
  fi
  if [ "$original_status" -eq 0 ]; then
    printf 'PASS: UC-5 role probe and credential cleanup; client/Fence remain stopped. Activation and new canonical duty evidence are still required.\n'
  fi
  exit "$original_status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP
vault_recovery_auth_preflight
status="$(vault operator generate-root -status -format=json 2>/dev/null)" || exit 1
jq -e '.started == false' <<<"$status" >/dev/null || { printf 'Another recovery ceremony is active.\n' >&2; exit 75; }
init="$(vault operator generate-root -init -format=json 2>/dev/null)" || exit 1
started=true
nonce="$(jq -er '.nonce | select(type == "string" and length > 0)' <<<"$init")"
otp="$(jq -er '.otp | select(type == "string" and length > 0)' <<<"$init")"
required="$(jq -er '.required | select(type == "number" and floor == . and . >= 1 and . <= 10)' <<<"$init")"
for ((number=1; number<=required; number++)); do
  printf 'Recovery key share %s of %s: ' "$number" "$required" >&9
  IFS= read -r -s share <&9 || exit 1
  printf '\n' >&9
  submitted="$(printf '%s' "$share" | vault operator generate-root -nonce="$nonce" -format=json - 2>/dev/null)" || { unset share; exit 1; }
  unset share
  if jq -e '.complete == true' <<<"$submitted" >/dev/null; then
    complete=true
    encoded="$(jq -er '.encoded_token | select(type == "string" and length > 0)' <<<"$submitted")"
    break
  fi
done
[ "$complete" = true ] || { printf 'Recovery quorum not reached.\n' >&2; exit 77; }
root_token="$(vault_recovery_decode_generated_root "$encoded" "$otp")"
[[ "$root_token" =~ ^(hvs\.|s\.)[A-Za-z0-9._-]+$ ]] || { printf 'Generated root format invalid.\n' >&2; exit 78; }
unset encoded otp nonce init submitted status
UC5_USER_RECOVERY=1 VAULT_TOKEN="$root_token" \
  python3 "$script_dir/run-hoodi-uc5-ceremony.py" execute --evidence-dir "$evidence_dir"
