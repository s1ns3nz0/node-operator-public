#!/usr/bin/env bash
# Check objective: Verify the Vault operator recovery wrapper preserves its bounded authentication protocol.
# Mock-only lifecycle contract for the recovery wrapper; it does not prove AWS login.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
wrapper="$root/scripts/ops/recover-and-configure-private-vault-operator-auth.sh"
policy="$root/deploy/vault/operator-recovery-policy.hcl"
scratch="$(mktemp -d)"
trap 'rm -rf -- "$scratch"' EXIT
tools="$scratch/tools"
mkdir -p "$tools"

cat > "$tools/aws" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
case "$*" in
  'sts get-caller-identity --query Arn --output text') printf '%s\n' 'arn:aws:iam::123456789012:user/operator.recovery' ;;
  'iam simulate-principal-policy '*'--action-names iam:GetUser '*'--query EvaluationResults[0].EvalDecision --output text') printf '%s\n' allowed ;;
  *) exit 64 ;;
esac
EOF

cat > "$tools/vault" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "$TRACE"
case "$*" in
  'status -format=json') printf '%s\n' '{"initialized":true,"sealed":false,"version":"1.20.4"}' ;;
  'operator generate-root -status -format=json') printf '%s\n' '{"started":false}' ;;
  # Vault encodes only the XOR result with raw standard base64. The OTP is a
  # literal base62 string, so AA XOR a yields the mock root token "a".
  'operator generate-root -init -format=json') printf '%s\n' '{"nonce":"mock-nonce","otp":"a","required":1}' ;;
  'operator generate-root -nonce=mock-nonce -format=json -') cat >/dev/null; printf '%s\n' '{"complete":true,"encoded_token":"AA"}' ;;
  'auth list -format=json') printf '%s\n' '{}' ;;
  'policy list -format=json') printf '%s\n' '[]' ;;
  'auth enable -path=operator-aws aws'|'policy write operator-recovery '*|'write auth/operator-aws/config/client '*|'write auth/operator-aws/role/operator-recovery '*) : ;;
  'read -format=json auth/operator-aws/config/client') printf '%s\n' '{"data":{"sts_region":"ap-northeast-2","sts_endpoint":"https://sts.ap-northeast-2.amazonaws.com","use_sts_region_from_client":false,"iam_server_id_header_value":"node-operator-vault-operator-123456789012-apne2"}}' ;;
  'read -format=json auth/operator-aws/role/operator-recovery') printf '%s\n' '{"data":{"auth_type":"iam","bound_iam_principal_arn":["arn:aws:iam::123456789012:user/operator.recovery"],"bound_iam_principal_id":["AIDAEXACT"],"resolve_aws_unique_ids":true,"token_policies":["operator-recovery"],"token_ttl":300,"token_max_ttl":600,"token_explicit_max_ttl":600,"token_no_default_policy":true}}' ;;
  'policy read operator-recovery') cat "$POLICY" ;;
  'login -method=aws -path=operator-aws -no-store -format=json role=operator-recovery region=ap-northeast-2 header_value=node-operator-vault-operator-123456789012-apne2')
    [ "${MODE:-ok}" = login-fail ] && exit 1
    printf '%s\n' '{"auth":{"client_token":"operator-token","policies":["operator-recovery"],"lease_duration":300}}'
    ;;
  'write -format=json sys/capabilities -') cat >/dev/null; printf '%s\n' '{"data":{"auth/token/create":["deny"],"sys/policies/acl/operator-recovery":["deny"]}}' ;;
  'token revoke -self')
    case "${VAULT_TOKEN:-}" in
      operator-token) printf '%s\n' revoke-operator >> "$TRACE" ;;
      a)
        printf '%s\n' revoke-root >> "$TRACE"
        if [ "${MODE:-ok}" = root-cleanup-fail ]; then exit 1; fi
        ;;
      *) exit 64 ;;
    esac
    ;;
  'operator generate-root -cancel') printf '%s\n' cancel-root >> "$TRACE" ;;
  *) exit 64 ;;
esac
EOF
chmod 0755 "$tools/aws" "$tools/vault"

run() {
  local name="$1" expected="$2" mode="$3" rc
  set +e
  last_out="$(printf 'mock-share\n' | PATH="$tools:$PATH" TRACE="$scratch/$name.trace" POLICY="$policy" MODE="$mode" PRIVATE_VAULT_SESSION=1 "$wrapper" --principal-arn arn:aws:iam::123456789012:user/operator.recovery 2>&1)"
  rc=$?
  set -e
  if [ "$expected" = success ]; then
    [ "$rc" -eq 0 ] || { printf 'unexpected %s failure: %s\n' "$name" "$last_out" >&2; exit 1; }
  else
    [ "$rc" -ne 0 ] || { printf 'unexpected %s success\n' "$name" >&2; exit 1; }
  fi
  if grep -Eq '(^|[^[:alnum:]])a([^[:alnum:]]|$)|operator-token|mock-share|AA' <<<"$last_out"; then
    printf '%s\n' 'credential material leaked to wrapper output' >&2
    exit 1
  fi
}

run success success ok
grep -Fx 'revoke-operator' "$scratch/success.trace" >/dev/null
grep -Fx 'revoke-root' "$scratch/success.trace" >/dev/null
grep -Fq 'login -method=aws -path=operator-aws -no-store -format=json' "$scratch/success.trace"

run login-failure failure login-fail
grep -Fq 'AWS operator login failed' <<<"$last_out"
grep -Fx 'revoke-root' "$scratch/login-failure.trace" >/dev/null
if grep -Fxq 'revoke-operator' "$scratch/login-failure.trace"; then
  printf '%s\n' 'operator token was revoked despite failed login' >&2
  exit 1
fi

run root-cleanup-failure failure root-cleanup-fail
grep -Fx 'revoke-operator' "$scratch/root-cleanup-failure.trace" >/dev/null
grep -Fx 'revoke-root' "$scratch/root-cleanup-failure.trace" >/dev/null
printf '%s\n' 'PASS operator auth recovery wrapper mock lifecycle (not Vault or AWS authentication proof).'
