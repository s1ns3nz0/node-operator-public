#!/usr/bin/env bash
set -euo pipefail

# Validate the local-only overlay against the explicitly named Kind cluster.
# The overlay keeps both blockchain clients scaled to zero, so this checks API
# admission and RBAC only; it never starts a Hoodi client or contacts AWS.

context="kind-node-operator-local"
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

if ! kubectl config get-contexts -o name | grep -Fxq "$context"; then
  printf 'Required local-only context %s is unavailable.\n' "$context" >&2
  exit 1
fi

kubectl --context "$context" apply --dry-run=server -k "$root/deploy/local-kind" >/dev/null
kubectl --context "$context" apply -k "$root/deploy/local-kind" >/dev/null

for statefulset in prysm-beacon nethermind-execution; do
  replicas="$(kubectl --context "$context" -n node-operator get statefulset "$statefulset" -o jsonpath='{.spec.replicas}')"
  [ "$replicas" = "0" ] || { printf '%s replicas must remain zero, got %s\n' "$statefulset" "$replicas" >&2; exit 1; }
done

kubectl --context "$context" auth can-i get configmaps \
  --as=system:serviceaccount:node-operator:node-workload \
  --namespace=node-operator | grep -Fxq yes
if kubectl --context "$context" auth can-i list configmaps \
  --as=system:serviceaccount:node-operator:node-workload \
  --namespace=node-operator | grep -Fxq yes; then
  printf 'node-workload must not list ConfigMaps\n' >&2
  exit 1
fi

printf 'PASS local Kind admission, zero-replica, and RBAC checks.\n'
