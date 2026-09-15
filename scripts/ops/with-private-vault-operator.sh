#!/usr/bin/env bash
# Run one trusted command with a short-lived, self-revoking Vault operator token.
set +x
set -euo pipefail

usage() {
  printf 'Usage: %s -- <trusted command> [arguments...]\n' "${0##*/}" >&2
  exit 64
}

[ "${1:-}" = -- ] || usage
shift
[ "$#" -gt 0 ] || usage

dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
if [ "${PRIVATE_VAULT_SESSION:-}" != 1 ]; then
  exec "$dir/with-private-vault.sh" -- env PRIVATE_VAULT_SESSION=1 bash "$0" -- "$@"
fi

fail() {
  printf '%s\n' "$1" >&2
  exit 1
}

for command in aws vault jq; do
  command -v "$command" >/dev/null 2>&1 || { printf 'missing command: %s\n' "$command" >&2; exit 69; }
done

caller="$(aws sts get-caller-identity --query Arn --output text 2>/dev/null)" || fail 'cannot determine AWS caller identity'
[ "$caller" = 'arn:aws:iam::123456789012:user/jsyang' ] || fail 'current AWS identity is not the reviewed Vault operator'

operator_token=''
cleanup() {
  local rc=$?
  trap - EXIT
  set +e
  if [ -n "$operator_token" ] && ! VAULT_TOKEN="$operator_token" vault token revoke -self >/dev/null 2>&1; then
    printf '%s\n' 'CRITICAL: operator token revocation could not be confirmed.' >&2
    rc=1
  fi
  unset VAULT_TOKEN operator_token login caller
  exit "$rc"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

# Capture the response rather than using a token helper or allowing CLI output.
login="$(VAULT_TOKEN='' vault login -method=aws -path=operator-aws -no-store -format=json \
  role=operator-recovery region=ap-northeast-2 \
  header_value=node-operator-vault-operator-123456789012-apne2 2>/dev/null)" || fail 'Vault AWS operator login failed'

# Extract first so a token returned with an invalid contract is still revoked.
operator_token="$(jq -er '.auth.client_token | select(type == "string" and length > 0)' <<<"$login" 2>/dev/null)" || fail 'Vault AWS operator login returned no usable token'
jq -e '
  .auth.policies == ["operator-recovery"] and
  (.auth.lease_duration | type == "number" and floor == . and . > 0 and . <= 600)
' <<<"$login" >/dev/null 2>&1 || fail 'Vault AWS operator login contract is not the reviewed policy and TTL'
unset login

# This is the only Vault command before the trusted child, and is read-only.
VAULT_TOKEN="$operator_token" vault operator generate-root -status -format=json >/dev/null 2>&1 || fail 'operator token cannot read root-ceremony status'

VAULT_TOKEN="$operator_token" "$@"
