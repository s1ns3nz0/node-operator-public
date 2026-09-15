#!/usr/bin/env bash
# Check objective: Verify private Vault operator authentication configuration with mocked commands only.
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
script="$root/scripts/ops/configure-private-vault-operator-auth.sh"
policy="$root/deploy/vault/operator-recovery-policy.hcl"
scratch="$(mktemp -d)"; trap 'rm -rf -- "$scratch"' EXIT
tools="$scratch/tools"; mkdir -p "$tools"
cat > "$tools/vault" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "$TRACE"
case "$*" in
  'auth list -format=json')
    case "${MODE:-ok}" in
      mount) printf '{"operator-aws/":{}}\n' ;;
      mount-malformed) printf '[]\n' ;;
      *) printf '{}\n' ;;
    esac
    ;;
  'policy list -format=json')
    case "${MODE:-ok}" in
      policy) printf '["operator-recovery"]\n' ;;
      policy-malformed) printf '{}\n' ;;
      *) printf '[]\n' ;;
    esac
    ;;
  'auth enable -path=operator-aws aws'|'policy write operator-recovery '*|'write auth/operator-aws/config/client '*|'write auth/operator-aws/role/operator-recovery '*) if [ "${MODE:-ok}" = writefail ]; then exit 1; fi ;;
  'read -format=json auth/operator-aws/config/client')
    if [ "${MODE:-ok}" = config-readback-bad ]; then
      printf '%s\n' '{"data":{"sts_region":"ap-northeast-2","sts_endpoint":"https://sts.amazonaws.com","use_sts_region_from_client":false,"iam_server_id_header_value":"node-operator-vault-operator-123456789012-apne2"}}'
    else
      printf '%s\n' '{"data":{"sts_region":"ap-northeast-2","sts_endpoint":"https://sts.ap-northeast-2.amazonaws.com","use_sts_region_from_client":false,"iam_server_id_header_value":"node-operator-vault-operator-123456789012-apne2"}}'
    fi
    ;;
  'read -format=json auth/operator-aws/role/operator-recovery')
    if [ "${MODE:-ok}" = role-readback-bad ]; then
      printf '%s\n' "{\"data\":{\"auth_type\":\"iam\",\"bound_iam_principal_arn\":[\"$PRINCIPAL\"],\"resolve_aws_unique_ids\":true,\"bound_iam_principal_id\":[],\"token_policies\":[\"operator-recovery\"],\"token_ttl\":300,\"token_max_ttl\":600,\"token_explicit_max_ttl\":600,\"token_no_default_policy\":true}}"
    else
      # Vault AWS auth role readback uses singular field names, each holding an array.
      printf '%s\n' "{\"data\":{\"auth_type\":\"iam\",\"bound_iam_principal_arn\":[\"$PRINCIPAL\"],\"resolve_aws_unique_ids\":true,\"bound_iam_principal_id\":[\"AIDAEXACT\"],\"token_policies\":[\"operator-recovery\"],\"token_ttl\":300,\"token_max_ttl\":600,\"token_explicit_max_ttl\":600,\"token_no_default_policy\":true}}"
    fi
    ;;
  'policy read operator-recovery') cat "$POLICY" ;;
  *) exit 64 ;;
esac
EOF
chmod 0755 "$tools/vault"
principal='arn:aws:iam::123456789012:user/operator.recovery'
run() { local name="$1" expect="$2"; shift 2; local out rc; set +e; out="$(PATH="$tools:$PATH" TRACE="$scratch/$name.trace" POLICY="$policy" PRINCIPAL="$principal" VAULT_TOKEN=synthetic-admin "$@" 2>&1)"; rc=$?; set -e; if [ "$expect" = ok ]; then [ "$rc" -eq 0 ] || { printf 'unexpected %s: %s\n' "$name" "$out" >&2; exit 1; }; else [ "$rc" -ne 0 ] || { printf 'unexpected %s: %s\n' "$name" "$out" >&2; exit 1; }; fi; ! grep -Fq synthetic-admin <<<"$out" || { printf 'token leak\n' >&2; exit 1; }; }
run ok ok "$script" --principal-arn "$principal"
grep -Fx 'auth enable -path=operator-aws aws' "$scratch/ok.trace" >/dev/null
grep -Fq 'resolve_aws_unique_ids=true' "$scratch/ok.trace"
grep -Fq 'token_no_default_policy=true' "$scratch/ok.trace"
grep -Fq 'sts_endpoint=https://sts.ap-northeast-2.amazonaws.com' "$scratch/ok.trace"
grep -Fq 'use_sts_region_from_client=false' "$scratch/ok.trace"
for mode in mount mount-malformed policy policy-malformed writefail config-readback-bad role-readback-bad; do run "$mode" fail env MODE="$mode" "$script" --principal-arn "$principal"; done
if grep -Eq '^(auth enable|policy write|write auth/)' "$scratch/mount.trace" || grep -Eq '^(auth enable|policy write|write auth/)' "$scratch/mount-malformed.trace" || grep -Eq '^(auth enable|policy write|write auth/)' "$scratch/policy.trace" || grep -Eq '^(auth enable|policy write|write auth/)' "$scratch/policy-malformed.trace"; then
  printf '%s\n' 'pre-existing mount or policy check performed a write' >&2; exit 1
fi
index=0
for bad in 'arn:aws:iam::123456789012:role/operator' 'arn:aws:iam::123456789012:user/path/name' 'arn:aws:iam::999999999999:user/operator' 'arn:aws:iam::123456789012:user/*'; do
  index=$((index + 1)); run "invalid-$index" fail "$script" --principal-arn "$bad"
  if test -e "$scratch/invalid-$index.trace"; then printf '%s\n' 'invalid principal reached Vault API' >&2; exit 1; fi
done
run duplicate-principal fail "$script" --principal-arn "$principal" --principal-arn "$principal"
if test -e "$scratch/duplicate-principal.trace"; then printf '%s\n' 'duplicate principal reached Vault API' >&2; exit 1; fi
grep -Fq 'path "sys/generate-root/attempt"' "$policy"
grep -Fq 'path "sys/generate-root/update"' "$policy"
grep -Fq 'path "auth/token/revoke-self"' "$policy"
if grep -Eq 'kv/|token create|\*' "$policy"; then printf '%s\n' 'operator policy exceeds its recovery scope' >&2; exit 1; fi
printf '%s\n' 'PASS operator auth configuration mock contract (not AWS login proof).'
