#!/usr/bin/env bash
set -euo pipefail

context="kind-node-operator-cilium"
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

if ! kubectl config get-contexts -o name | grep -Fxq "$context"; then
  echo "Required local-only context $context is unavailable." >&2
  exit 1
fi

cleanup() {
  kubectl --context "$context" -n node-operator delete pod/local-policy-probe --ignore-not-found --wait=true --timeout=60s >/dev/null 2>&1 || true
}
trap cleanup EXIT

kubectl --context "$context" apply -f "$root/deploy/base/namespace.yaml"
kubectl --context "$context" apply -f "$root/deploy/base/network-policies.yaml"
kubectl --context "$context" apply -f "$root/deploy/local-cilium/policy-probe.yaml"
kubectl --context "$context" -n node-operator wait --for=condition=Ready pod/local-policy-probe --timeout=90s

kubectl --context "$context" -n node-operator exec local-policy-probe -- nslookup kubernetes.default.svc.cluster.local >/dev/null

if kubectl --context "$context" -n node-operator exec local-policy-probe -- nc -z -w 3 1.1.1.1 443; then
  echo "Unexpected external HTTPS egress: default-deny policy was not enforced." >&2
  exit 1
fi

echo "PASS Cilium enforced DNS-only egress for the disposable local probe."
