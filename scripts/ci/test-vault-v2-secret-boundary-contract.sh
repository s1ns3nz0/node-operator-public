#!/usr/bin/env bash
# Check objective: Enforce Vault v2 secret inventory and recovery scripts remain within the reviewed boundary.
# shellcheck disable=SC2016 # literal source-contract assertions
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
fail() { printf 'FAIL Vault v2 secret-boundary contract: %s\n' "$*" >&2; exit 1; }
inventory="$root/docs/security/vault-v2-secret-inventory.md"
bootstrap="$root/scripts/ops/bootstrap-node-operator-vault-v2.sh"
coordinator="$root/scripts/ops/recover-and-bootstrap-hoodi-vault-v2.sh"
onboard="$root/scripts/ops/recover-and-onboard-hoodi-validator-keystore.sh"

for file in "$inventory" "$bootstrap" "$coordinator" "$onboard"; do test -f "$file" || fail "missing $file"; done
for path in \
  'nodes/hoodi/engine-api-jwt' \
  'validators/hoodi/<set>/runtime/keystore' \
  'node-operator-pki/' \
  'Never store in Vault'; do
  grep -Fq "$path" "$inventory" || fail "inventory missing $path"
done
grep -Fq 'vault secrets enable -path="$mount" -version=2 kv' "$root/scripts/ops/ensure-node-operator-runtime-kv-v2.sh" || fail 'runtime engine does not create KV v2'
grep -Fq 'vault secrets enable -path=node-operator-pki pki' "$bootstrap" || fail 'PKI engine bootstrap missing'
grep -Fq 'node-operator-pki/issue/validator-mtls' "$onboard" || fail 'onboarding does not use Vault PKI issuance'
grep -Fq 'bootstrap-hoodi-engine-api-vault.sh' "$coordinator" || fail 'coordinator misses Engine JWT role bootstrap'
grep -Fq 'bootstrap-hoodi-validator-runtime-vault.sh' "$coordinator" || fail 'coordinator misses validator role bootstrap'
scan_rc=0
grep -REn 'kv/(data|metadata)' "$root/deploy/nethermind" "$root/deploy/prysm" "$root/deploy/validator" "$root/deploy/vault/policies" >/dev/null || scan_rc=$?
if [ "$scan_rc" -eq 0 ]; then
  fail 'new workload manifests or policies still reference legacy kv/'
fi
[ "$scan_rc" -eq 1 ] || fail 'legacy path scan could not complete'
scan_rc=0
grep -En 'openssl req -x509|ca\.key|CAkey' "$onboard" "$root/scripts/ops/rotate-hoodi-validator-signer-tls.sh" >/dev/null || scan_rc=$?
if [ "$scan_rc" -eq 0 ]; then
  fail 'runtime onboarding or rotation handles a CA private key outside Vault PKI'
fi
[ "$scan_rc" -eq 1 ] || fail 'CA private-key scan could not complete'
bash -n "$bootstrap" "$coordinator" "$onboard"
grep -Fq 'configure-hoodi-vault-kubernetes-auth.sh' "$onboard" || fail 'onboarding does not delegate Kubernetes auth configuration'
if grep -Eq 'kubectl config view --raw|vault (auth list|auth enable|write auth/kubernetes/config)|kubernetes_ca_cert' "$onboard"; then
  fail 'onboarding retains inline Kubernetes auth or cluster-CA handling'
fi
transport_validator="$root/scripts/ops/verify-hoodi-vault-v2-transport-records.sh"
grep -Fq 'printf '\''%s %s\n'\'' "$client" "$fingerprint"' "$transport_validator" || fail 'shared transport known-client name differs from issued CN'
grep -Fq 'verify-hoodi-vault-v2-transport-records.sh' "$root/scripts/ops/prepare-hoodi-vault-v2-transport.sh" || fail 'preparation does not use shared transport validation'
grep -Fq 'verify-hoodi-vault-v2-transport-records.sh' "$onboard" || fail 'onboarding does not use shared transport validation'
grep -Fq '"$tmp/verified-public/known-clients.txt" "$known_out"' "$onboard" || fail 'existing onboarding output is not reconstructed from verified stored records'
grep -Fq '"$tmp/winner-public/known-clients.txt" "$known_out"' "$onboard" || fail 'onboarding output is not reconstructed from verified winning records'
grep -Fq 'printf '\''validator-%s-client.%s.svc %s\n'\'' "$validator_set" "$namespace"' "$root/scripts/ops/rotate-hoodi-validator-signer-tls.sh" || fail 'rotation known-client name differs from issued CN'

# Exercise the refresh-only custody boundary with a fake canonical helper.
# The onboarding script must delegate after authenticated recovery; it must not
# recreate an auth mount or read a kubeconfig/CA itself.
temporary="$(mktemp -d)"
trap 'rm -rf "$temporary"' EXIT
mkdir -p "$temporary/ops/lib" "$temporary/bin" "$temporary/keys"
cp "$onboard" "$temporary/ops/recover-and-onboard-hoodi-validator-keystore.sh"
cat > "$temporary/ops/lib/vault-recovery-auth.sh" <<'SCRIPT'
vault_recovery_auth_preflight() { :; }
vault_recovery_decode_generated_root() { printf 'root-sentinel'; }
SCRIPT
cat > "$temporary/ops/configure-hoodi-vault-kubernetes-auth.sh" <<'SCRIPT'
#!/usr/bin/env bash
set -euo pipefail
[ "${VAULT_TOKEN:-}" = root-sentinel ] || exit 65
printf 'canonical-helper\n' >> "$AUTH_TRACE"
SCRIPT
cat > "$temporary/bin/vault" <<'SCRIPT'
#!/usr/bin/env bash
set -euo pipefail
case "${1:-}:${2:-}" in
  operator:generate-root)
    case " $* " in
      *' -status '*) printf '%s\n' '{"started":false}' ;;
      *' -init '*) printf '%s\n' '{"nonce":"n","otp":"o","required":1}' ;;
      *' -nonce=n '*) printf '%s\n' '{"complete":true,"encoded_token":"encoded"}' ;;
      *) exit 64 ;;
    esac
    ;;
  token:revoke) printf 'revoke\n' >> "$AUTH_TRACE" ;;
  *) printf 'unexpected-vault %s\n' "$*" >> "$AUTH_TRACE"; exit 64 ;;
esac
SCRIPT
chmod 700 "$temporary/ops/recover-and-onboard-hoodi-validator-keystore.sh" "$temporary/ops/configure-hoodi-vault-kubernetes-auth.sh" "$temporary/bin/vault"
printf '{}' > "$temporary/keys/keystore-test.json"
: > "$temporary/auth-trace"
if ! PATH="$temporary/bin:$PATH" PRIVATE_VAULT_SESSION=1 VAULT_ADDR=https://vault.test AUTH_TRACE="$temporary/auth-trace" \
  bash "$temporary/ops/recover-and-onboard-hoodi-validator-keystore.sh" --validator-set hoodi-example --keystore-dir "$temporary/keys" --signer-ca-output "$temporary/signer-ca.crt" --known-clients-output "$temporary/known-clients.txt" --refresh-auth-only <<< 'recovery-share' >/dev/null 2>&1; then
  fail 'onboarding refresh-only path did not delegate to canonical Kubernetes auth helper'
fi
grep -Fxq 'canonical-helper' "$temporary/auth-trace" || fail 'onboarding did not invoke canonical Kubernetes auth helper'
if grep -Fq 'unexpected-vault' "$temporary/auth-trace"; then
  fail 'onboarding still performs inline Kubernetes auth configuration'
fi
grep -Fxq 'revoke' "$temporary/auth-trace" || fail 'onboarding did not revoke its temporary recovery token'

printf '%s\n' 'PASS: Vault v2 inventory, isolated engines, workload paths, PKI issuance, and recovery coordinator are consistent.'
