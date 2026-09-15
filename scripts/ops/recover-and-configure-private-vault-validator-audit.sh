#!/usr/bin/env bash
set -euo pipefail

# Configures the two non-raw Vault validator-audit devices through a recovery
# quorum. The generated root token is process-local and revoked on every exit.
dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
if [ "${PRIVATE_VAULT_SESSION:-}" != 1 ]; then
  exec "$dir/with-private-vault.sh" -- env PRIVATE_VAULT_SESSION=1 "$0"
fi
for command in vault jq kubectl openssl python3; do command -v "$command" >/dev/null 2>&1 || { printf 'missing command: %s\n' "$command" >&2; exit 69; }; done
audit_receipt_mode=false
if [ -n "${AUDIT_RECEIPT:-}${AUDIT_ACCOUNT:-}${AUDIT_REGION:-}${AUDIT_DEPLOYMENT:-}${AUDIT_RELEASE_REVISION:-}${AUDIT_OPERATION_ID:-}" ]; then
  : "${AUDIT_RECEIPT:?private audit receipt path is required}"; : "${AUDIT_ACCOUNT:?audit account is required}"; : "${AUDIT_REGION:?audit region is required}"; : "${AUDIT_DEPLOYMENT:?audit deployment is required}"; : "${AUDIT_RELEASE_REVISION:?audit release revision is required}"; : "${AUDIT_OPERATION_ID:?audit operation id is required}"
  [[ "$AUDIT_ACCOUNT" =~ ^[0-9]{12}$ ]] || { printf '%s\n' 'audit account is invalid' >&2; exit 65; }
  [[ "$AUDIT_REGION" =~ ^[a-z]{2}-[a-z]+-[0-9]+$ ]] || { printf '%s\n' 'audit region is invalid' >&2; exit 65; }
  [[ "$AUDIT_DEPLOYMENT" =~ ^[a-z][a-z0-9-]{0,62}$ ]] || { printf '%s\n' 'audit deployment is invalid' >&2; exit 65; }
  [[ "$AUDIT_RELEASE_REVISION" =~ ^[0-9a-f]{40}$ ]] || { printf '%s\n' 'audit release revision is invalid' >&2; exit 65; }
  [[ "$AUDIT_OPERATION_ID" =~ ^[0-9a-f]{32}$ ]] || { printf '%s\n' 'audit operation id is invalid' >&2; exit 65; }
  case "$AUDIT_RECEIPT" in /*) ;; *) printf '%s\n' 'audit receipt path is unsafe' >&2; exit 65;; esac
  receipt_name="${AUDIT_RECEIPT##*/}"; case "$receipt_name" in ''|.|..) printf '%s\n' 'audit receipt path is unsafe' >&2; exit 65;; esac
  receipt_dir="$(cd "$(dirname "$AUDIT_RECEIPT")" && pwd -P)" || { printf '%s\n' 'audit receipt path is unsafe' >&2; exit 65; }
  receipt_ancestor="$receipt_dir"
  while :; do [ ! -L "$receipt_ancestor" ] || { printf '%s\n' 'audit receipt path is unsafe' >&2; exit 65; }; [ "$receipt_ancestor" = / ] && break; receipt_ancestor="$(dirname "$receipt_ancestor")"; done
  AUDIT_RECEIPT="$receipt_dir/$receipt_name"
  python3 - "$receipt_dir" <<'PY' || { printf '%s\n' 'audit receipt path is unsafe' >&2; exit 65; }
import os, stat, sys
info = os.lstat(sys.argv[1])
raise SystemExit(not (stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700 and info.st_uid == os.geteuid()))
PY
  [ ! -e "$AUDIT_RECEIPT" ] && [ ! -L "$AUDIT_RECEIPT" ] || { printf '%s\n' 'audit receipt path is unsafe' >&2; exit 65; }; audit_receipt_mode=true
fi

started=false; complete=false; root_token=''; receipt_tmp=''
cleanup() {
  set +e
  [ -z "$receipt_tmp" ] || rm -f "$receipt_tmp"
  [ -n "$root_token" ] && VAULT_TOKEN="$root_token" vault token revoke -self >/dev/null 2>&1 || true
  [ "$started" = true ] && [ "$complete" != true ] && vault operator generate-root -cancel >/dev/null 2>&1 || true
  unset VAULT_TOKEN root_token
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

statefulset="$(kubectl -n vault get statefulset vault -o json)"
jq -e 'all(.spec.template.spec.containers[]; select(.name == "vault-validator-audit-relay") | .securityContext.readOnlyRootFilesystem == true) and any(.spec.template.spec.containers[]; .name == "vault-validator-audit-relay")' <<<"$statefulset" >/dev/null || {
  printf '%s\n' 'Vault audit relay is absent or unsafe; refusing audit-device ceremony.' >&2; exit 65;
}
for pod in vault-0 vault-1 vault-2; do
  kubectl -n vault get pod "$pod" -o json | jq -e '[.status.containerStatuses[] | select(.name == "vault-validator-audit-relay") | .ready] == [true]' >/dev/null || {
    printf 'Vault audit relay is not ready: %s\n' "$pod" >&2; exit 65;
  }
  # The relay is intentionally a scratch image and has no shell/coreutils.
  # Check the shared audit PVC from the Vault container instead.
  kubectl -n vault exec "$pod" -c vault -- sh -ec 'test -S /vault/audit/validator-audit.sock' || {
    printf 'Vault audit socket is not bound: %s\n' "$pod" >&2; exit 65;
  }
done

# shellcheck source=scripts/ops/lib/vault-recovery-auth.sh
source "$dir/lib/vault-recovery-auth.sh"
vault_recovery_auth_preflight
printf '%s\n' 'Preflight passed: Vault audit relay and recovery authentication were verified; no audit-device or root-token mutation has started.' >&2
status="$(vault operator generate-root -status -format=json)"
[ "$(jq -r '.started' <<<"$status")" = false ] || { printf '%s\n' 'a root-token generation ceremony is already in progress' >&2; exit 75; }
init="$(vault operator generate-root -init -format=json)"; started=true
nonce="$(jq -er '.nonce' <<<"$init")"; otp="$(jq -er '.otp' <<<"$init")"; required="$(jq -er '.required' <<<"$init")"
for number in $(seq 1 "$required"); do
  printf 'Recovery key share %s of %s: ' "$number" "$required" >&2
  IFS= read -r -s share; printf '\n' >&2
  submitted="$(printf '%s' "$share" | vault operator generate-root -nonce="$nonce" -format=json -)"; unset share
  if [ "$(jq -r '.complete' <<<"$submitted")" = true ]; then complete=true; encoded="$(jq -er '.encoded_token' <<<"$submitted")"; break; fi
done
[ "$complete" = true ] || { printf '%s\n' 'recovery quorum was not reached' >&2; exit 77; }
root_token="$(vault_recovery_decode_generated_root "$encoded" "$otp")"
unset encoded otp nonce init submitted status

devices="$(VAULT_TOKEN="$root_token" vault audit list -format=json)"
if ! jq -e 'has("validator-file/")' <<<"$devices" >/dev/null; then
  VAULT_TOKEN="$root_token" vault audit enable -path=validator-file file file_path=/vault/audit/validator-audit.json log_raw=false hmac_accessor=false elide_list_responses=true
fi
if ! jq -e 'has("validator-socket/")' <<<"$devices" >/dev/null; then
  VAULT_TOKEN="$root_token" vault audit enable -path=validator-socket socket address=/vault/audit/validator-audit.sock socket_type=unix log_raw=false hmac_accessor=false elide_list_responses=true
fi
VAULT_TOKEN="$root_token" "$dir/verify-vault-validator-audit.sh"
if [ "$audit_receipt_mode" = true ]; then marker="$(openssl rand -hex 32)"; after_ms="$(python3 -c 'import time; print(time.time_ns()//1_000_000)')"
challenge="$(VAULT_TOKEN="$root_token" vault write -format=json sys/audit-hash/validator-socket input="$marker")"; unset marker
marker_hmac="$(jq -er '.data.hash | select(test("^hmac-sha256:[0-9a-f]{64}$"))' <<<"$challenge")"; request_id="$(jq -er '.request_id | select(test("^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$"))' <<<"$challenge")"; unset challenge; fi
VAULT_TOKEN="$root_token" vault token revoke -self >/dev/null 2>&1 || { printf '%s\n' 'generated root token revocation was not confirmed' >&2; exit 75; }
# Without a token argument, lookup uses auth/token/lookup-self. Unlike revoke,
# lookup does not support -self; that flag fails locally before contacting Vault.
if lookup_output="$(VAULT_TOKEN="$root_token" vault token lookup -format=json 2>&1)"; then
  printf '%s\n' 'generated root token revocation rejection was not confirmed' >&2; exit 75
fi
# A transport or server failure is not evidence of revocation. Vault CLI exposes
# the API status in its error report; accept only the invalid-token 403 response.
if [[ "$lookup_output" != *"Code: 403"* || "$lookup_output" != *"invalid token"* ]]; then
  printf '%s\n' 'generated root token revocation rejection was not explicitly confirmed as HTTP 403 invalid token' >&2; exit 75
fi
unset lookup_output
root_token=''
if [ "$audit_receipt_mode" = true ]; then receipt_tmp="$(mktemp "$receipt_dir/.audit-challenge.XXXXXX")"; chmod 600 "$receipt_tmp"; jq -n --arg account "$AUDIT_ACCOUNT" --arg region "$AUDIT_REGION" --arg deployment "$AUDIT_DEPLOYMENT" --arg revision "$AUDIT_RELEASE_REVISION" --arg operation "$AUDIT_OPERATION_ID" --arg hmac "$marker_hmac" --arg request "$request_id" --argjson after "$after_ms" '{schema_version:1,result:"socket-audit-challenge-emitted-and-root-revoked",aws_account_id:$account,aws_region:$region,deployment_name:$deployment,release_revision:$revision,operation_id:$operation,marker_hmac:$hmac,request_id:$request,after_ms:$after}' > "$receipt_tmp"; ln "$receipt_tmp" "$AUDIT_RECEIPT" || { printf '%s\n' 'audit receipt already exists' >&2; exit 65; }; rm -f "$receipt_tmp"; receipt_tmp=''; fi
printf '%s\n' 'PASS: Vault validator file/socket audit devices were configured and generated root-token revocation was verified.'
