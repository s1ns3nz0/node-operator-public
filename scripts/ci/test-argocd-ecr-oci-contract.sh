#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
manifest="$root/deploy/argocd/ecr-oci-credentials.yaml"
application="$root/deploy/argocd/node-operator-client-application.yaml"
terraform="$root/infra/terraform/argocd-ecr-credentials.tf"

fail() { printf 'FAIL Argo CD ECR OCI contract: %s\n' "$*" >&2; exit 1; }

for file in "$manifest" "$application" "$terraform"; do
  test -f "$file" || fail "missing required file: $file"
done

for expected in \
  'name: argocd-ecr-refresher' \
  'name: argocd-ecr-oci' \
  'argocd.argoproj.io/secret-type: repo-creds' \
  'schedule: "17 */6 * * *"' \
  'concurrencyPolicy: Forbid' \
  'readOnlyRootFilesystem: true' \
  'mountPath: /tmp' \
  'ecr get-login-password --region ap-northeast-2' \
  'node-operator-baseline-gitops-client'; do
  grep -Fq "$expected" "$manifest" || fail "missing ECR refresher invariant: $expected"
done

if grep -Eq 'verbs:.*(create|delete|\*)' "$manifest"; then
  fail 'credential refresher RBAC grants create, delete, or wildcard access'
fi

if grep -Eqi '^[[:space:]]*(password|token|client_token|vault_token):[[:space:]]*[^$[:space:]]+' "$manifest"; then
  fail 'credential refresher manifest contains a literal credential'
fi

for expected in \
  'aws_iam_role" "argocd_ecr_refresher' \
  'aws_eks_pod_identity_association" "argocd_ecr_refresher' \
  'ecr:GetAuthorizationToken' \
  'enable_gitops_client_ecr_publisher ? 1 : 0'; do
  grep -Fq "$expected" "$terraform" || fail "missing Terraform least-privilege invariant: $expected"
done

for expected in \
  'kind: Application' \
  'name: node-operator-client' \
  'chart: node-operator-client' \
  'targetRevision: 0.1.32' \
  'prune: false' \
  'selfHeal: false'; do
  grep -Fq "$expected" "$application" || fail "missing Application invariant: $expected"
done

printf 'PASS Argo CD private ECR OCI credentials and pinned Application contracts.\n'
