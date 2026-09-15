#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$script_dir/lib/common.sh"
root="$(repo_root)"
fail() { printf 'FAIL CodeBuild signing input contract: %s\n' "$*" >&2; exit 1; }

contract="$root/docs/gitops/codebuild-signing-input-contract.md"
buildspec="$root/deploy/vault/buildspec-release-sign.yml"
verifier="$root/scripts/ci/verify-release-signature.sh"
for file in "$contract" "$buildspec" "$verifier"; do
  test -f "$file" || fail "missing contract dependency: $file"
done

for required in \
  'release-input/sha256/<source-revision>.zip' \
  'node-operator-release-bundle.tar' \
  'node-operator-release-bundle.sha256' \
  'provenance-input.json' \
  'buildspec-release-sign.yml' \
  'exactly these reviewed files' \
  'source-location override' \
  "same \`<source-revision>\`" \
  'archive-local buildspec explicitly' \
  'release-verification.json' \
  'scripts/ci/verify-release-signature.sh' \
  "not raw \`signature.json\` or \`verify.json\`" \
  'bundle digest, provenance-file' \
  'CodeBuild build ID' \
  'digest, never a tag-only' \
  'approved atomic change' \
  "Terraform \`aws_codebuild_project\`" \
  "\`release-bundle.yml\` input archive packaging"; do
  grep -Fq "$required" "$contract" || fail "contract omits required boundary: $required"
done

for prohibited in 'bootstrap.zip' 'a branch' 'a tag' 'Vault tokens' 'static credentials' 'key material'; do
  grep -Fq "$prohibited" "$contract" || fail "contract must explicitly reject: $prohibited"
done

# This asserts the candidate buildspec emits exactly the evidence that the
# consumer gate requires. It deliberately does not inspect Terraform or
# release.yml: their conversion is a future atomic activation change.
artifacts=()
while IFS= read -r artifact; do
  artifacts+=("$artifact")
done < <(awk '
  /^artifacts:/ { in_artifacts=1; next }
  in_artifacts && /^  files:/ { in_files=1; next }
  in_files && /^    - / { sub(/^    - /, ""); print; next }
  in_files && /^[^[:space:]]/ { exit }
' "$buildspec")
expected_artifacts=(
  'node-operator-release-bundle.tar'
  'node-operator-release-bundle.sha256'
  'provenance-input.json'
  'release-verification.json'
)
test "${#artifacts[@]}" -eq "${#expected_artifacts[@]}" || fail 'buildspec must emit exactly four gate artifacts'
for index in "${!expected_artifacts[@]}"; do
  test "${artifacts[$index]}" = "${expected_artifacts[$index]}" || fail 'buildspec output layout differs from the consumer gate'
done
if grep -Eq '^    - (signature|verify)\.json$' "$buildspec"; then
  fail 'buildspec must not emit raw signature or verification response files'
fi

for required in 'release-verification.json' 'node-operator-release-bundle.tar' 'node-operator-release-bundle.sha256' 'provenance-input.json'; do
  grep -Fq "$required" "$verifier" || fail "existing verifier does not consume required artifact: $required"
done
grep -Fq 'transit.signature' "$verifier" || fail 'existing verifier must validate the format-bound Transit signature evidence'

printf 'PASS CodeBuild signing input/output contract is immutable, archive-local, and compatible with the fail-closed consumer gate.\n'
