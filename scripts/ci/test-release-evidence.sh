#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$script_dir/lib/common.sh"
require_command jq

temporary_directory="$(mktemp -d)"
trap 'rm -rf "$temporary_directory"' EXIT
fixture_directory="$temporary_directory/fixtures"
output_directory="$temporary_directory/evidence"
mkdir -p "$fixture_directory"
artifact_digest="sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

printf '%s\n' '{"scorecard_score":10,"branch_protection":true,"commit_signing":true,"workflow_pinning":true,"token":"DO_NOT_PERSIST_POSTURE"}' > "$fixture_directory/posture.json"
printf '%s\n' '{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"name":"fixture-package","version":"1.0.0","properties":[{"name":"secret","value":"DO_NOT_PERSIST_SBOM"}]}],"metadata":{"component":{"name":"raw-artifact","version":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}}' > "$fixture_directory/sbom.json"
printf '%s\n' '[{"critical":{"image":{"docker-manifest-digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"identity":{"docker-reference":"private.example/DO_NOT_PERSIST_SIGNATURE"}},"optional":{"Subject":"https://github.com/owner/repo/.github/workflows/release-bundle.yml@refs/heads/main","Issuer":"https://token.actions.githubusercontent.com","Bundle":"DO_NOT_PERSIST_SIGNATURE"}}]' > "$fixture_directory/signature.json"
printf '%s\n' '{"_type":"https://in-toto.io/Statement/v1","subject":[{"name":"raw-artifact","digest":{"sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}],"predicate":{"buildDefinition":{"buildType":"https://slsa.dev/container-based-build/v1","externalParameters":{"secret":"DO_NOT_PERSIST_PROVENANCE"},"resolvedDependencies":[{"uri":"git+https://private.example/DO_NOT_PERSIST_PROVENANCE","digest":{"gitCommit":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}]},"runDetails":{"builder":{"id":"https://github.com/Attestations/GitHubHostedActions@v1"}}}}' > "$fixture_directory/provenance.json"
printf '%s\n' '{"descriptor":{"name":"grype","timestamp":"2026-09-01T00:00:00Z"},"source":{"target":{"userInput":"DO_NOT_PERSIST_SCAN"}},"matches":[{"artifact":{"name":"private-package","version":"1.0.0"},"vulnerability":{"id":"CVE-DO-NOT-PERSIST","severity":"High","description":"DO_NOT_PERSIST_SCAN"}},{"vulnerability":{"severity":"Critical"}},{"vulnerability":{"severity":"Unrecognized"}}]}' > "$fixture_directory/scan.json"

"$script_dir/collect-release-evidence.sh" "$output_directory" "$artifact_digest" "$fixture_directory/posture.json" "$fixture_directory/sbom.json" "$fixture_directory/signature.json" "$fixture_directory/provenance.json" "$fixture_directory/scan.json"

for tool in posture sbom signature provenance scan; do
  jq -e --arg digest "$artifact_digest" '.schema_version == "v1" and (.tool | type == "string") and .artifact_digest == $digest and (.collected_at | type == "string") and (.result | type == "object")' "$output_directory/$tool.json" >/dev/null
done
jq -e '.result == {scorecard_score:10,branch_protection:true,commit_signing:true,workflow_pinning:true,status:"passed"}' "$output_directory/posture.json" >/dev/null
jq -e --arg digest "$artifact_digest" '.result == {status:"complete",format:"cyclonedx-json",component_count:1,artifact_digest:$digest}' "$output_directory/sbom.json" >/dev/null
jq -e --arg digest "$artifact_digest" '.result == {artifact_digest:$digest,identities:[{subject:"https://github.com/owner/repo/.github/workflows/release-bundle.yml@refs/heads/main",issuer:"https://token.actions.githubusercontent.com"}],status:"verified"}' "$output_directory/signature.json" >/dev/null
jq -e '.result == {subject_digests:["sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],builder_id:"https://github.com/Attestations/GitHubHostedActions@v1",build_type:"https://slsa.dev/container-based-build/v1",source_commit:"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",status:"verified"}' "$output_directory/provenance.json" >/dev/null
jq -e '.result.status == "completed" and .result.complete == true and (.result.age_seconds | type == "number") and .result.findings == {critical:1,high:1,medium:0,low:0,unknown:1}' "$output_directory/scan.json" >/dev/null
if rg -l 'DO_NOT_PERSIST_|CVE-DO-NOT-PERSIST|private-package|raw-artifact' "$output_directory" >/dev/null; then
  printf 'raw release evidence was retained in collector output\n' >&2
  exit 1
fi

"$script_dir/collect-release-evidence.sh" "$temporary_directory/no-grype" "$artifact_digest" "$fixture_directory/posture.json" "$fixture_directory/sbom.json" "$fixture_directory/signature.json" "$fixture_directory/provenance.json"
jq -e '.result == {status:"not_run",complete:false,scanned_at:null,age_seconds:null,findings:{critical:0,high:0,medium:0,low:0,unknown:0}}' "$temporary_directory/no-grype/scan.json" >/dev/null

printf '%s\n' '{"bomFormat":"CycloneDX","specVersion":"1.6","components":[],"metadata":{"component":{"name":"raw-artifact","version":"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}}}' > "$fixture_directory/mismatched-sbom.json"
if "$script_dir/collect-release-evidence.sh" "$temporary_directory/mismatched-sbom" "$artifact_digest" "$fixture_directory/posture.json" "$fixture_directory/mismatched-sbom.json" "$fixture_directory/signature.json" "$fixture_directory/provenance.json" 2>/dev/null; then
  printf 'collector accepted an SBOM bound to a different artifact digest\n' >&2
  exit 1
fi

printf '%s\n' '{"spdxVersion":"SPDX-2.3","packages":[]}' > "$fixture_directory/spdx-sbom.json"
if "$script_dir/collect-release-evidence.sh" "$temporary_directory/spdx-sbom" "$artifact_digest" "$fixture_directory/posture.json" "$fixture_directory/spdx-sbom.json" "$fixture_directory/signature.json" "$fixture_directory/provenance.json" 2>/dev/null; then
  printf 'collector accepted an SPDX SBOM without a verifiable artifact-digest binding\n' >&2
  exit 1
fi

printf '%s\n' '{"bomFormat":"CycloneDX","components":[]}' > "$fixture_directory/invalid-provenance.json"
if "$script_dir/collect-release-evidence.sh" "$temporary_directory/invalid" "$artifact_digest" "$fixture_directory/posture.json" "$fixture_directory/sbom.json" "$fixture_directory/signature.json" "$fixture_directory/invalid-provenance.json" 2>/dev/null; then
  printf 'collector accepted malformed provenance\n' >&2
  exit 1
fi
