#!/usr/bin/env bash
# Check objective: Verify release signature evidence is bound to the exact bundle and provenance.
set -euo pipefail

# Validate non-sensitive release evidence. Transit verifies cryptography inside
# the private CodeBuild boundary; this gate checks the verified result is bound
# to the exact bundle and provenance about to be released.
if [ "$#" -ne 1 ]; then
  printf 'usage: %s RELEASE_DIRECTORY\n' "$0" >&2
  exit 64
fi

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$script_dir/lib/common.sh"
require_command jq
require_command shasum

release_directory="$1"
fail() { printf 'FAIL release verification: %s\n' "$*" >&2; exit 1; }
bundle="$release_directory/node-operator-release-bundle.tar"
checksum="$release_directory/node-operator-release-bundle.sha256"
provenance="$release_directory/provenance-input.json"
result="$release_directory/release-verification.json"
for file in "$bundle" "$checksum" "$provenance" "$result"; do
  test -f "$file" || fail "missing required evidence: $(basename "$file")"
done

expected_digest="$(awk 'NR == 1 { print $1 }' "$checksum")"
[[ "$expected_digest" =~ ^sha256:[0-9a-f]{64}$ ]] || fail 'invalid bundle checksum record'
actual_digest="sha256:$(shasum -a 256 "$bundle" | awk '{print $1}')"
[ "$expected_digest" = "$actual_digest" ] || fail 'bundle bytes do not match checksum record'
provenance_digest="sha256:$(shasum -a 256 "$provenance" | awk '{print $1}')"
source_revision="$(jq -er '.predicate.buildDefinition.resolvedDependencies[] | select(.uri == "git+node-operator") | .digest.gitCommit' "$provenance")" || fail 'provenance has no source revision'
builder_id="$(jq -er '.predicate.runDetails.builder.id' "$provenance")" || fail 'provenance has no builder identity'

jq -e \
  --arg artifact_digest "$actual_digest" \
  --arg provenance_digest "$provenance_digest" \
  --arg source_revision "$source_revision" \
  --arg builder_id "$builder_id" '
  .schema_version == "v1" and
  .artifact == {name:"node-operator-release-bundle.tar", digest:$artifact_digest} and
  .provenance.sha256 == $provenance_digest and
  .provenance.subject_digest == $artifact_digest and
  .provenance.source_revision == $source_revision and
  .provenance.builder_id == $builder_id and
  .transit.key == "node-operator-release" and
  (.transit.signature | type == "string" and test("^vault:v[0-9]+:[A-Za-z0-9+/=_-]+$")) and
  .transit.verified == true and
  .signer == {auth_method:"aws", vault_role:"release-signer"} and
  (.codebuild.build_id | type == "string" and length > 0)
  ' "$result" >/dev/null || fail 'verification result is missing, malformed, or not bound to this release'

if jq -er '.. | strings | select(test("(?i)(vault[_-]?token|client_token|aws_secret_access_key|-----BEGIN( [A-Z]+)? PRIVATE KEY-----)"))' \
  "$provenance" "$result" >/dev/null; then
  fail 'verification evidence contains credential or key material'
fi
printf 'PASS release bundle, provenance, and verified Vault Transit result are bound.\n'
