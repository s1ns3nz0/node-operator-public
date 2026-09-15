#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$script_dir/lib/common.sh"
root="$(repo_root)"
values="$root/docs/gitops/argocd-private-values.example.yaml"
fail() { printf 'FAIL private Argo CD values contract: %s\n' "$*" >&2; exit 1; }

test -f "$values" || fail "missing values file: $values"
for required in \
  '123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/node-operator-baseline-gitops-argocd' \
  '0deb1a1c917629b960ead995ae3b6069450a866992676599658687ef9a641ee8' \
  '8499afd690c437f52301efd2b05b2455da5bd2dfc20332cd697dc9937f808462' \
  '2cc044fc5a07c9b701f8f1255a309ae9ad7856e694ac03513bf3648c01e40763' \
  'type: ClusterIP' \
  'enabled: false'; do
  grep -Fq "$required" "$values" || fail "private override omits: $required"
done

if rg -n 'quay\.io|ghcr\.io|public\.ecr\.aws|ecr-public\.aws\.com|LoadBalancer' "$values" >/dev/null; then
  fail 'private override retains an external registry or public service'
fi

printf 'PASS private Argo CD values use only immutable private ECR references.\n'
