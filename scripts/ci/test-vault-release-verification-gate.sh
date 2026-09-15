#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$script_dir/lib/common.sh"
require_command jq
require_command shasum
root="$(repo_root)"
temporary_directory="$(mktemp -d)"
trap 'rm -rf "$temporary_directory"' EXIT
fail() { printf 'FAIL vault release verification test: %s\n' "$*" >&2; exit 1; }
expect_failure() {
  if "$script_dir/verify-release-signature.sh" "$temporary_directory" >/dev/null 2>&1; then
    fail "$1 unexpectedly passed"
  fi
}

policy="$root/deploy/vault/policies/release-signer.hcl"
buildspec="$root/deploy/vault/buildspec-release-sign.yml"
documentation="$root/docs/gitops/vault-codebuild-signing.md"
for file in "$policy" "$buildspec" "$documentation"; do
  test -f "$file" || fail "missing verification contract file: $file"
done
test "$(grep -Ec '^path "transit/(sign|verify)/node-operator-release" \{' "$policy")" -eq 2 || fail 'signer policy must expose only sign and verify Transit paths'
if grep -Eq '^path "transit/(keys|export|backup|restore|config)/' "$policy"; then
  fail 'signer policy exposes Transit key administration'
fi
for required in \
  'transit/verify/node-operator-release' \
  'release-verification.json' \
  'node-operator-release-bundle.sha256' \
  'CODEBUILD_BUILD_ID' \
  'unset vault_token payload'; do
  grep -Fq "$required" "$buildspec" || fail "buildspec omits required verification boundary: $required"
done
grep -Fq 'fails closed' "$documentation" || fail 'fail-closed gate behavior is undocumented'

printf 'deterministic release fixture\n' > "$temporary_directory/node-operator-release-bundle.tar"
digest="sha256:$(shasum -a 256 "$temporary_directory/node-operator-release-bundle.tar" | awk '{print $1}')"
printf '%s  node-operator-release-bundle.tar\n' "$digest" > "$temporary_directory/node-operator-release-bundle.sha256"
cat > "$temporary_directory/provenance-input.json" <<'JSON'
{"_type":"https://in-toto.io/Statement/v1","subject":[{"name":"node-operator-release-bundle.tar","digest":{"sha256":"REPLACE_DIGEST"}}],"predicate":{"buildDefinition":{"resolvedDependencies":[{"uri":"git+node-operator","digest":{"gitCommit":"0123456789abcdef0123456789abcdef01234567"}}]},"runDetails":{"builder":{"id":"local://node-operator/scripts/ci/build-release-bundle.sh"}}}}
JSON
digest_hex="${digest#sha256:}"
sed -i.bak "s/REPLACE_DIGEST/$digest_hex/" "$temporary_directory/provenance-input.json"
rm "$temporary_directory/provenance-input.json.bak"
provenance_digest="sha256:$(shasum -a 256 "$temporary_directory/provenance-input.json" | awk '{print $1}')"
write_result() {
  jq -n --arg digest "$digest" --arg provenance "$provenance_digest" '
    {schema_version:"v1",artifact:{name:"node-operator-release-bundle.tar",digest:$digest},provenance:{sha256:$provenance,subject_digest:$digest,source_revision:"0123456789abcdef0123456789abcdef01234567",builder_id:"local://node-operator/scripts/ci/build-release-bundle.sh"},transit:{key:"node-operator-release",signature:"vault:v1:ZmFrZS1zaWduYXR1cmU=",verified:true},signer:{auth_method:"aws",vault_role:"release-signer"},codebuild:{build_id:"node-operator-baseline-release-signer:fixture"}}' > "$temporary_directory/release-verification.json"
}
write_result
"$script_dir/verify-release-signature.sh" "$temporary_directory" >/dev/null
rm "$temporary_directory/release-verification.json"
expect_failure 'missing verification result'
write_result
jq '.transit.verified = false' "$temporary_directory/release-verification.json" > "$temporary_directory/changed.json"
mv "$temporary_directory/changed.json" "$temporary_directory/release-verification.json"
expect_failure 'unverified Transit result'
write_result
jq '.artifact.digest = "sha256:0000000000000000000000000000000000000000000000000000000000000000"' "$temporary_directory/release-verification.json" > "$temporary_directory/changed.json"
mv "$temporary_directory/changed.json" "$temporary_directory/release-verification.json"
expect_failure 'mismatched artifact digest'
write_result
jq '.transit.signature = "vault-token-should-not-persist"' "$temporary_directory/release-verification.json" > "$temporary_directory/changed.json"
mv "$temporary_directory/changed.json" "$temporary_directory/release-verification.json"
expect_failure 'malformed Transit signature'
write_result
jq '.codebuild.build_id = "vault_token=must-not-persist"' "$temporary_directory/release-verification.json" > "$temporary_directory/changed.json"
mv "$temporary_directory/changed.json" "$temporary_directory/release-verification.json"
expect_failure 'credential-like verification artifact'
printf 'PASS Vault release verification gate fails closed for missing, invalid, mismatched, and sensitive evidence.\n'
