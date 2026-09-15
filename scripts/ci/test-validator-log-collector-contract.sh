#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
dir="$root/deploy/observability"
for file in namespace.yaml service-accounts.yaml rbac.yaml network-policies.yaml fluent-bit-config.yaml fluent-bit-daemonset.template.yaml; do
  test -f "$dir/$file" || { printf 'missing observability file: %s\n' "$file" >&2; exit 1; }
done
kubectl kustomize "$dir" >/dev/null
grep -Fq 'pod-security.kubernetes.io/enforce: privileged' "$dir/namespace.yaml"
grep -Fq 'REPLACE_WITH_APPROVED_PRIVATE_ECR_DIGEST' "$dir/fluent-bit-daemonset.template.yaml"
grep -Fq 'log_group_name /aws/eks/node-operator/validator-security' "$dir/fluent-bit-config.yaml"
grep -Fq 'Exclude_Path /var/log/containers/*validator-log-collector*.log' "$dir/fluent-bit-config.yaml"
grep -Fq 'cidr: 172.20.0.1/32' "$dir/network-policies.yaml"
grep -Fq 'cidr: 169.254.170.23/32' "$dir/network-policies.yaml"
printf 'PASS validator log collector is isolated, private-image-gated, and prevents self-log recursion.\n'
