#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$script_dir/lib/common.sh"
root="$(repo_root)"
fail() { printf 'FAIL %s\n' "$*" >&2; exit 1; }

contract="$root/docs/gitops/private-release-runner-contract.md"
test -f "$contract" || fail "missing private release runner contract"

# shellcheck disable=SC2016 # The GitHub expression is a literal contract fragment.
for required in \
  'node-operator-baseline-private-release' \
  'WORKFLOW_JOB_QUEUED' \
  'runs-on: codebuild-node-operator-baseline-private-release-${{ github.run_id }}-${{ github.run_attempt }}' \
  'destroyed after one job' \
  "\`vault.node-operator.internal\`" \
  'TCP 8200 only to the private Vault endpoint' \
  'certificate' \
  'hostname/SNI' \
  'GitHub OIDC JWKS availability' \
  'token.actions.githubusercontent.com/.well-known/openid-configuration' \
  'stale cache or failed JWKS refresh' \
  "\`release\` GitHub Environment requires an approval" \
  'Self-approval is' \
  "repository, owner, \`refs/tags/v*\`" \
  "\`release-bundle.yml\` workflow reference" \
  'GitHub repository ID, run ID, run attempt' \
  'Vault login request ID, Vault AWS lease ID' \
  'CodeBuild build ID' \
  'is fail-closed for the release'; do
  grep -Fq "$required" "$contract" || fail "private runner contract omits: $required"
done

if grep -Eqi '(http://|curl[[:space:]].*-[^-[:space:]]*k|AWS_(ACCESS|SECRET)_ACCESS_KEY|vault[[:space:]_-]*token[[:space:]]*=)' "$contract"; then
  fail "private runner contract permits a public, plaintext, or static-credential path"
fi

printf 'PASS Vault private release runner contract is structurally constrained.\n'
