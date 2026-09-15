#!/usr/bin/env bash
# shellcheck disable=SC2016 # literal shell fragments are contract assertions
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
script="$root/scripts/release/configure-gitops-publisher.sh"
grep -Fq 'GITOPS_CLIENT_ECR_PUBLISHER_ROLE_ARN' "$script"
grep -Fq 'AWS_ACCOUNT_ID' "$script"
grep -Fq 'gitops-client-ecr-publish' "$script"
grep -Fq '[ ! -L "$handoff" ]' "$script"
grep -Fq 'github() { gh "$@"; }' "$script"
if grep -Fq 'env -u GITHUB_TOKEN' "$script"; then
  printf '%s\n' 'GitOps publisher configuration must preserve GITHUB_TOKEN' >&2
  exit 1
fi
if grep -Ein 'vault.*token|recovery.*key|keystore|mnemonic|secret.*access' "$script"; then
  printf '%s\n' 'GitOps publisher configuration must not accept custody or credential material' >&2
  exit 1
fi
printf '%s\n' 'PASS GitOps publisher configuration remains non-secret and environment-scoped.'
