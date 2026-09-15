#!/usr/bin/env bash
set +x
set -euo pipefail

dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
if [ "$#" -ne 2 ] || [ "$1" != --principal-arn ] ||
   [[ ! "$2" =~ ^arn:aws:iam::123456789012:user/[A-Za-z0-9+=,.@_-]+$ ]]; then
  printf 'Usage: %s --principal-arn EXACT_IAM_USER_ARN\n' "${0##*/}" >&2
  exit 64
fi
if [ "${PRIVATE_VAULT_SESSION:-}" != 1 ]; then
  exec "$dir/with-private-vault.sh" -- env PRIVATE_VAULT_SESSION=1 "$0" "$@"
fi
for command in vault jq aws; do command -v "$command" >/dev/null || exit 69; done
caller="$(aws sts get-caller-identity --query Arn --output text)"
[ "$caller" = "$2" ] || { printf 'Current AWS identity does not match the requested operator.\n' >&2; exit 65; }
decision="$(aws iam simulate-principal-policy \
  --policy-source-arn arn:aws:iam::123456789012:role/node-operator-baseline-vault \
  --action-names iam:GetUser --resource-arns "$2" \
  --query 'EvaluationResults[0].EvalDecision' --output text)"
[ "$decision" = allowed ] || {
  printf 'Vault requires reviewed iam:GetUser permission for this exact user before the recovery ceremony.\n' >&2
  exit 65
}

started=false
complete=false
root_token=''
operator_token=''
cleanup() {
  local rc=$?
  trap - EXIT
  set +e
  if [ -n "$operator_token" ] && ! VAULT_TOKEN="$operator_token" vault token revoke -self >/dev/null 2>&1; then
    printf 'CRITICAL: operator token revocation could not be confirmed.\n' >&2; rc=1
  fi
  if [ -n "$root_token" ] && ! VAULT_TOKEN="$root_token" vault token revoke -self >/dev/null 2>&1; then
    printf 'CRITICAL: generated root revocation could not be confirmed.\n' >&2; rc=1
  fi
  if [ "$started" = true ] && [ "$complete" != true ] && ! vault operator generate-root -cancel >/dev/null 2>&1; then
    printf 'CRITICAL: incomplete root ceremony cancellation could not be confirmed.\n' >&2; rc=1
  fi
  unset VAULT_TOKEN root_token operator_token share otp encoded
  if [ "$rc" -eq 0 ]; then printf 'PASS: operator authentication configured and tested; generated tokens revoked.\n'; fi
  exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
# shellcheck source=scripts/ops/lib/vault-recovery-auth.sh
source "$dir/lib/vault-recovery-auth.sh"
vault_recovery_auth_preflight
status="$(vault operator generate-root -status -format=json)"
[ "$(jq -r '.started' <<<"$status")" = false ] || { printf 'A root ceremony is already active.\n' >&2; exit 75; }
initial="$(vault operator generate-root -init -format=json)"; started=true
nonce="$(jq -er '.nonce' <<<"$initial")"
otp="$(jq -er '.otp' <<<"$initial")"
required="$(jq -er '.required|select(type=="number" and .>=1 and .<=255 and .==floor)' <<<"$initial")"
for number in $(seq 1 "$required"); do
  printf 'Recovery key share %s of %s: ' "$number" "$required" >&2
  IFS= read -r -s share; printf '\n' >&2
  reply="$(printf '%s' "$share" | vault operator generate-root -nonce="$nonce" -format=json -)"
  unset share
  if [ "$(jq -r '.complete' <<<"$reply")" = true ]; then
    complete=true; encoded="$(jq -er '.encoded_token' <<<"$reply")"; break
  fi
done
[ "$complete" = true ] || { printf 'Recovery quorum not reached.\n' >&2; exit 77; }
root_token="$(vault_recovery_decode_generated_root "$encoded" "$otp")"
unset initial reply status nonce otp encoded
VAULT_TOKEN="$root_token" bash "$dir/configure-private-vault-operator-auth.sh" "$@"

# Login is captured, never persisted by the CLI token helper or printed.
login="$(VAULT_TOKEN='' vault login -method=aws -path=operator-aws -no-store -format=json \
  role=operator-recovery region=ap-northeast-2 \
  header_value=node-operator-vault-operator-123456789012-apne2 2>/dev/null)" || {
  printf 'AWS operator login failed; configuration may be partial. Do not upgrade Vault.\n' >&2; exit 1;
}
operator_token="$(jq -er '.auth.client_token|select(type=="string" and length>0)' <<<"$login")"
jq -e '.auth.policies==["operator-recovery"] and .auth.lease_duration>0 and .auth.lease_duration<=600' <<<"$login" >/dev/null
unset login
VAULT_TOKEN="$operator_token" vault operator generate-root -status -format=json >/dev/null
# Inspect capabilities with the temporary administrator token; do not perform
# a negative token-create probe that could mint a credential on policy drift.
capabilities="$(OPERATOR_TOKEN="$operator_token" jq -n \
  '{token:env.OPERATOR_TOKEN,paths:["auth/token/create","sys/policies/acl/operator-recovery"]}' | \
  VAULT_TOKEN="$root_token" vault write -format=json sys/capabilities -)"
jq -e '.data["auth/token/create"]==["deny"] and .data["sys/policies/acl/operator-recovery"]==["deny"]' <<<"$capabilities" >/dev/null
unset capabilities
VAULT_TOKEN="$operator_token" vault operator generate-root -status -format=json >/dev/null
