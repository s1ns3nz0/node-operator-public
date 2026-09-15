#!/usr/bin/env bash
# shellcheck disable=SC2016 # Literal Markdown fragments intentionally contain backticks.
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$script_dir/lib/common.sh"
root="$(repo_root)"
contract="$root/docs/gitops/private-source-vault-boundary.md"
fail() { printf 'FAIL private source and Vault boundary: %s\n' "$*" >&2; exit 1; }

test -f "$contract" || fail 'missing contract document'
for required in \
  'private ECR GitOps repositories' \
  'must not connect directly to `github.com`' \
  'Contents: read' \
  'Metadata: read' \
  '`kv/platform/argocd/repository-credentials`' \
  '`argocd` namespace' \
  'githubAppPrivateKey' \
  'No PAT, deploy key, static AWS credential, or public-network exception'; do
  grep -Fq "$required" "$contract" || fail "contract omits: $required"
done

if rg -n '(BEGIN (RSA |OPENSSH )?PRIVATE KEY|ghp_[A-Za-z0-9]+|github_pat_[A-Za-z0-9_]+|vault[._-]?token)' "$contract" >/dev/null; then
  fail 'contract contains credential material'
fi

printf 'PASS private GitOps source and Vault boundary is explicit and secret-free.\n'
