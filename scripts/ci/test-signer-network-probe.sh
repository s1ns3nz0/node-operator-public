#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
renderer="$root/scripts/ops/render-signer-network-probe.py"
scratch="$(mktemp -d)"; trap 'rm -rf "$scratch"' EXIT
key="0x$(printf 'a%.0s' {1..96})"
output="$scratch/probe.json"
PYTHONDONTWRITEBYTECODE=1 python3 "$renderer" --validator-set hoodi-example --expected-public-key "$key" --output "$output"
jq -e --arg key "$key" '
  .apiVersion == "v1" and .kind == "List" and (.items | type == "array" and length == 2) and
  (.items[0].metadata.name == "signer-probe-direct-hoodi-example") and
  (.items[0].metadata.labels["app.kubernetes.io/component"] == "validator-client") and
  (.items[0].metadata.annotations["node-operator.io/expected-result"] | startswith("must fail")) and
  (.items[1].metadata.name == "signer-probe-control-hoodi-example") and
  (.items[1].metadata.labels["app.kubernetes.io/component"] == "validator-signing-fence") and
  (.items[1].metadata.annotations["node-operator.io/expected-result"] | startswith("must succeed")) and
  all(.items[]; .metadata.namespace == "validator-operations" and .metadata.annotations["vault.hashicorp.com/role"] == "hoodi-hoodi-example-client-tls" and .metadata.annotations["vault.hashicorp.com/agent-inject-secret-tls.crt"] == "node-operator-runtime/data/validators/hoodi/hoodi-example/runtime/client-tls" and (.metadata.annotations["vault.hashicorp.com/agent-inject-template-tls.key"] | contains("node-operator-runtime/data/validators/hoodi/hoodi-example/runtime/client-tls")) and .spec.restartPolicy == "Never" and .spec.activeDeadlineSeconds == 120 and .spec.automountServiceAccountToken == false and .spec.enableServiceLinks == false and .spec.serviceAccountName == "validator-client" and .spec.securityContext.runAsUser == 65532 and .spec.securityContext.runAsGroup == 65532 and .spec.securityContext.fsGroup == 65532 and .spec.securityContext.seccompProfile.type == "RuntimeDefault" and (.spec.containers | length == 1) and .spec.containers[0].name == "get-only-identity-probe" and .spec.containers[0].image == "123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/node-operator-baseline-validator-signer-identity-probe@sha256:11212189c98afaeb719eaaa8ac7d3c86179884c84986c97c9c1a35b6b4f4ec8f" and .spec.containers[0].args == ["--validator-set","hoodi-example","--expected-public-key",$key] and .spec.containers[0].securityContext.readOnlyRootFilesystem == true and .spec.containers[0].securityContext.allowPrivilegeEscalation == false and .spec.containers[0].securityContext.capabilities.drop == ["ALL"] and .spec.containers[0].resources.requests.cpu == "10m" and .spec.containers[0].resources.limits.memory == "64Mi" and .spec.volumes[0].projected.sources[0].serviceAccountToken.audience == "vault" and .spec.volumes[0].projected.sources[0].serviceAccountToken.expirationSeconds == 600)
' "$output" >/dev/null
jq -e 'all(.items[];
  .metadata.annotations["vault.hashicorp.com/secret-volume-path"] == "/tls" and
  ([.metadata.annotations | to_entries[] | select(.key | contains("agent-inject-template")) | .value] |
   all(.[]; contains("with secret \"node-operator-runtime/") and (contains("\\") | not))) and
  ([.spec.volumes[] | select(has("secret"))] | length == 0)
)' "$output" >/dev/null
for bad_set in hoodi-INVALID hoodi-1234567890123456789012; do
  if PYTHONDONTWRITEBYTECODE=1 python3 "$renderer" --validator-set "$bad_set" --expected-public-key "$key" --output "$scratch/bad.json" >/dev/null 2>&1; then echo "accepted bad set: $bad_set" >&2; exit 1; fi
done
if PYTHONDONTWRITEBYTECODE=1 python3 "$renderer" --validator-set hoodi-example --expected-public-key "0x$(printf 'g%.0s' {1..96})" --output "$scratch/bad.json" >/dev/null 2>&1; then echo 'accepted malformed public key' >&2; exit 1; fi
if PYTHONDONTWRITEBYTECODE=1 python3 "$renderer" --validator-set hoodi-example --expected-public-key "$key" --output relative.json >/dev/null 2>&1; then echo 'accepted relative output path' >&2; exit 1; fi
test ! -d "$root/scripts/ops/__pycache__"
printf '%s\n' 'PASS: signer network probe renderer emits bounded GET-only negative/control Pods.'
