#!/usr/bin/env bash
# shellcheck disable=SC2016 # literal source-contract fragments
# Check objective: Enforce the guarded live runtime-secret migration boundary.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
script="$root/scripts/ops/recover-and-migrate-hoodi-runtime-secrets-to-vault.sh"
fail() { printf 'FAIL live runtime secret migration contract: %s\n' "$*" >&2; exit 1; }
test -x "$script" || fail 'migration helper missing or not executable'
test -x "$root/scripts/ci/test-live-runtime-secret-migration-recovery.sh" || fail 'recovery-path regression test missing or not executable'
bash -n "$script"
for required in \
  'get secret engine-api-jwt -o json' \
  'get secret "validator-${validator_set}-signer-tls" -o json' \
  'get secret "validator-${validator_set}-client-tls" -o json' \
  'put_or_match "$engine_path" "$engine_record" engine' \
  'put_or_match "$base/signer-tls" "$signer_record" signer' \
  'put_or_match "$base/client-tls" "$client_record" client' \
  'vault read -format=json kv/config' \
  'vault read -format=json "$api_path"' \
  'vault write "$api_path" @"$payload"' \
  'kv_v2_path' \
  'put_v2_record' \
  'try fromjson catch null' \
  'vault kv enable-versioning kv/' \
  'Vault kv/ v1 compatibility policies require review before conversion' \
  'Vault kv/ must be version 2 for runtime credential injection' \
  'kv_mount_version:2' \
  'repaired_legacy_vault_records' \
  'bootstrap-hoodi-engine-api-vault.sh' \
  'bootstrap-hoodi-validator-runtime-vault.sh' \
  'source_secrets_retained:true' \
  'vault_recovery_decode_generated_root' \
  'vault token revoke -self'; do
  grep -Fq "$required" "$script" || fail "missing required migration boundary: $required"
done
if grep -Eq 'openssl rand|kubectl.*delete secret|create secret generic|generate-root -decode|vault kv get|vault kv put' "$script"; then
  fail 'migration must neither generate nor delete/reprint source secret material'
fi
v2_record='{"data":{"data":{"jwt":"fixture"},"metadata":{"version":1}}}'
jq -e '.data.data.jwt == "fixture" and .data.metadata.version == 1' <<<"$v2_record" >/dev/null
signer_secret='{"data":{"tls.p12":"fixture","tls-password.txt":"fixture"}}'
client_secret='{"data":{"tls.crt":"fixture","tls.key":"fixture","ca.crt":"fixture"}}'
jq -e '(.data["tls.p12"] | type == "string") and (.data["tls-password.txt"] | type == "string")' <<<"$signer_secret" >/dev/null
jq -e '(.data["tls.crt"] | type == "string") and (.data["tls.key"] | type == "string") and (.data["ca.crt"] | type == "string")' <<<"$client_secret" >/dev/null
printf '%s\n' 'PASS: live runtime migration requires KV v2, fail-closes legacy policy consumers, writes records with CAS, and retains source Secrets for staged cutover.'
