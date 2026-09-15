#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
values="$root/docs/gitops/cert-manager-values.example.yaml"
tls="$root/docs/gitops/vault-tls-internal-ca.example.yaml"
network_policy="$root/docs/gitops/vault-network-policy.example.yaml"
runbook="$root/docs/gitops/vault-internal-ca-runbook.md"
fail() { printf 'FAIL Vault internal TLS contract: %s\n' "$*" >&2; exit 1; }

for file in "$values" "$tls" "$network_policy" "$runbook"; do test -f "$file" || fail "missing $file"; done

private_repository='123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/node-operator-baseline-gitops-cert-manager'
for digest in \
  '416a2d76870d996460e62bd7f521bf14fa017be9e3e904aab92163a331fcb61a' \
  'd8b3961b51c8c7320633f8208dc46bf88aa13804d0f7cbe48a096b2c523cee42' \
  'ccf6b919ec0500745a47a910118f834f9636d0aac1ff221245cd2557ed8c7c98' \
  'd8ab6416e6e7303a86fa0a8daa82c94a8001f21c9d78eb2e7db20534e5d07ae8'; do
  grep -Fq "repository: $private_repository" "$values" || fail 'cert-manager image repository is not private ECR'
  grep -Fq "tag: $digest" "$values" || fail 'cert-manager image tag is not immutable'
  grep -Fq "digest: sha256:$digest" "$values" || fail 'cert-manager image digest is not pinned'
done

grep -Fqx '  enabled: true' "$values" || fail 'cert-manager CRDs must be enabled'
grep -Fq 'kind: Secret' "$tls" && fail 'TLS manifest must not create a Secret directly'
for required in 'name: vault-selfsigned-bootstrap' 'name: vault-internal-ca' 'secretName: vault-internal-ca' 'name: vault-server-tls' 'secretName: vault-tls' 'rotationPolicy: Always' 'vault-2.vault-internal.vault.svc.cluster.local' 'vault-active.vault.svc' 'client auth'; do
  grep -Fq "$required" "$tls" || fail "TLS manifest omits $required"
done

for required in 'kind: NetworkPolicy' 'name: vault-ingress-private-only' 'node-operator.io/vault-client-access: "true"' 'node-operator.io/vault-client: "true"' 'port: 8201'; do
  grep -Fq "$required" "$network_policy" || fail "network policy omits $required"
done
if grep -Fq 'rollout status statefulset/vault' "$root/scripts/release/prepare-vault-bootstrap-tls.sh"; then
  fail 'TLS-only preparation must not require Vault StatefulSet rollout readiness'
fi
grep -Fq 'verify-hoodi-vault-readiness.sh" --mode post-init-ready' "$root/scripts/release/interactive-hoodi-release.sh" || fail 'post-install Vault readiness gate is missing'
grep -Fq 'kubectl label namespace vault --overwrite' "$root/scripts/release/prepare-vault-bootstrap-tls.sh" || fail 'Vault namespace labels are not reconciled for an interrupted first preparation'
"$root/scripts/ci/test-prepare-vault-bootstrap-tls.sh"

if rg -n -i '(secret(data)?\s*:|tls\.key:|BEGIN (CERTIFICATE|.*PRIVATE KEY))' "$values" "$tls" "$network_policy" "$runbook" >/dev/null; then
  fail 'TLS delivery inputs contain Secret data or key material'
fi

printf 'PASS Vault internal CA delivery inputs are private, digest-pinned, and secret-value free.\n'
