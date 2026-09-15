#!/usr/bin/env bash
set -euo pipefail

# Exercise the migration through a complete synthetic recovery ceremony. The
# share is deliberately arbitrary: Vault, not the shell script, validates a
# real recovery share. This proves the value is consumed only on stdin and
# that the ceremony reaches the KV-v2/bootstrap path without exposing it.
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
script="$root/scripts/ops/recover-and-migrate-hoodi-runtime-secrets-to-vault.sh"
scratch="$(mktemp -d)"
mock_bin="$scratch/bin"
trace="$scratch/trace"
mkdir -p "$mock_bin"
cleanup() { rm -rf "$scratch"; }
trap cleanup EXIT INT TERM

jwt="$(printf 'a%.0s' {1..64})"
jwt_b64="$(printf '%s' "$jwt" | base64 | tr -d '\n')"
cat > "$mock_bin/kubectl" <<'SCRIPT'
#!/usr/bin/env bash
set -euo pipefail
case "$*" in
  *'secret engine-api-jwt -o json'*) printf '{"data":{"jwt":"%s"}}\n' "$MOCK_JWT_B64" ;;
  *'signer-tls -o json'*) printf '%s\n' '{"data":{"tls.p12":"Zm9v","tls-password.txt":"Zm9v"}}' ;;
  *'client-tls -o json'*) printf '%s\n' '{"data":{"tls.crt":"Zm9v","tls.key":"Zm9v","ca.crt":"Zm9v"}}' ;;
  *'known-clients -o json'*) printf '%s\n' '{"data":{"known-clients":"AA"}}' ;;
  *) printf 'unexpected kubectl: %s\n' "$*" >&2; exit 1 ;;
esac
SCRIPT
cat > "$mock_bin/openssl" <<'SCRIPT'
#!/usr/bin/env bash
case "$1" in verify|pkcs12) exit 0 ;; x509) printf '%s\n' 'sha256 Fingerprint=AA';; *) exit 1;; esac
SCRIPT
cat > "$mock_bin/vault" <<'SCRIPT'
#!/usr/bin/env bash
set -euo pipefail
case "$*" in
  'status -format=json') printf '%s\n' '{"initialized":true,"sealed":false,"version":"1.18.0"}' ;;
  'operator generate-root -status -format=json') printf '%s\n' '{"started":false}' ;;
  'operator generate-root -init -format=json') printf '%s\n' '{"nonce":"n","otp":"A","required":1}' ;;
  'operator generate-root -nonce=n -format=json -')
    share="$(cat)"; [ "$share" = test-recovery-share ] || exit 1
    printf '%s\n' '{"complete":true,"encoded_token":"Mw"}'
    ;;
  'secrets list -format=json') printf '%s\n' '{"kv/":{"type":"kv","options":{"version":"2"}}}' ;;
  'policy list -format=json') printf '%s\n' '[]' ;;
  'read -format=json kv/config') printf '%s\n' '{"data":{"max_versions":10}}' ;;
  'read -format=json kv/data/nodes/hoodi/engine-api-jwt') printf '%s\n' "{\"data\":{\"data\":{\"jwt\":\"$MOCK_JWT\"},\"metadata\":{\"version\":1}}}" ;;
  'read -format=json kv/data/'*) exit 2 ;;
  'read -format=json auth/kubernetes/config') printf '%s\n' '{}' ;;
  'policy write '*|'write auth/kubernetes/role/'*|'write kv/data/'*|'token revoke -self') printf '%s\n' "$*" >> "$MOCK_TRACE" ;;
  *) printf 'unexpected vault: %s\n' "$*" >&2; exit 1 ;;
esac
SCRIPT
chmod 700 "$mock_bin/kubectl" "$mock_bin/openssl" "$mock_bin/vault"

printf 'test-recovery-share\n' | env \
  MOCK_JWT="$jwt" MOCK_JWT_B64="$jwt_b64" MOCK_TRACE="$trace" PATH="$mock_bin:$PATH" \
  PRIVATE_VAULT_SESSION=1 PRIVATE_EKS_SESSION=1 VAULT_ADDR=https://mock VAULT_TOKEN=ceremony-token \
  "$script" --validator-set hoodi-example --evidence-output "$scratch/evidence.json"
jq -e '.kv_mount_version == 2 and .source_secrets_retained == true and .secret_values_emitted == false' "$scratch/evidence.json" >/dev/null
grep -Fq 'token revoke -self' "$trace"
printf '%s\n' 'PASS: arbitrary synthetic recovery share reaches the redacted KV-v2 migration ceremony.'
