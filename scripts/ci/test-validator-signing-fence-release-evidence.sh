#!/usr/bin/env bash
# Check objective: Require release evidence to bind the signing-fence image to its reviewed build inputs.
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"; collector="$root/scripts/ci/collect-validator-signing-fence-release-evidence.sh"
installer="$root/scripts/ci/install-validator-signing-fence-release-tools.sh"
scratch="$(mktemp -d)"; trap 'rm -rf "$scratch"' EXIT; mkdir "$scratch/bin"
digest="sha256:$(printf 'a%.0s' {1..64})"; revision="$(printf 'b%.0s' {1..40})"; image="123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/node-operator-baseline-validator-fence@$digest"
alternate_image="123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/hoodi-example-baseline-validator-fence@$digest"
input_sha="$(python3 "$root/scripts/release/fence_build_inputs.py" --root "$root")"
statement="$(jq -cn --arg d "${digest#sha256:}" --arg r "$revision" --arg input_sha "$input_sha" '{_type:"https://in-toto.io/Statement/v0.1",predicateType:"https://slsa.dev/provenance/v1",subject:[{digest:{sha256:$d}}],predicate:{buildDefinition:{buildType:"https://slsa.dev/container-based-build/v1",externalParameters:{input_sha256:$input_sha},resolvedDependencies:[{digest:{gitCommit:$r}}]},runDetails:{builder:{id:"https://github.com/Attestations/GitHubHostedActions@v1"}}}}' | base64 | tr -d '\n')"
cat > "$scratch/bin/cosign" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$MOCK_TRACE"
[ "${MOCK_COSIGN_FAIL:-false}" = false ] || exit 1
if [ "${MOCK_CURRENT_ONLY:-false}" = true ] && printf '%s\n' "$*" | grep -Fq 'validator-signing-fence-image.yml@refs/heads/main'; then exit 1; fi
case "$1" in
  verify)
    case "${MOCK_SIGNATURE_MODE:-valid}" in
      valid) printf '%s\n' '[{"critical":{"image":{"docker-manifest-digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}}]' ;;
      empty) printf '%s\n' '[]' ;;
      malformed) printf '%s\n' '{}' ;;
      wrong-digest) printf '%s\n' '[{"critical":{"image":{"docker-manifest-digest":"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}}}]' ;;
    esac ;;
  verify-attestation)
    case "$*" in
      *'--type cyclonedx'*) jq -cn --arg payload "$MOCK_SBOM_STATEMENT" '{payload:$payload}' ;;
      *'--type https://github.com/s1ns3nz0/node-operator/attestations/scan-summary/v1'*) jq -cn --arg payload "$MOCK_SCAN_STATEMENT" '{payload:$payload}' ;;
      *'--type slsaprovenance1'*) jq -cn --arg payload "$MOCK_STATEMENT" '{payload:$payload}' ;;
      *) exit 64 ;;
    esac ;;
esac
EOF
cat > "$scratch/bin/syft" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$MOCK_TRACE"; [ "${MOCK_SYFT_FAIL:-false}" = false ] || exit 1
output=''; version=''; while [ "$#" -gt 0 ]; do case "$1" in --output) output="${2#cyclonedx-json=}"; shift 2 ;; --source-version) version="$2"; shift 2 ;; *) shift ;; esac; done
jq -n --arg version "$version" '{bomFormat:"CycloneDX",metadata:{component:{version:$version}},components:[{name:"fence"}]}' > "$output"
EOF
cat > "$scratch/bin/grype" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$MOCK_TRACE"; [ "${MOCK_GRYPE_FAIL:-false}" = false ] || exit 1
output=''; while [ "$#" -gt 0 ]; do case "$1" in --file) output="$2"; shift 2 ;; *) shift ;; esac; done
jq -n --arg severity "${MOCK_SEVERITY:-}" '{descriptor:{name:"grype",version:"0.118.0",db:{status:{built:"2026-09-08T00:00:00Z",valid:true,schemaVersion:"6"}}},matches:(if $severity == "" then [] else [{vulnerability:{severity:$severity}}] end)}' > "$output"
EOF
chmod +x "$scratch/bin/"*
sbom_statement="$(jq -cn --arg d "$digest" '{predicate:{bomFormat:"CycloneDX",metadata:{component:{version:$d}}}}' | base64 | tr -d '\n')"
scan_statement="$(jq -cn --arg d "$digest" '{_type:"https://in-toto.io/Statement/v0.1",predicateType:"https://github.com/s1ns3nz0/node-operator/attestations/scan-summary/v1",subject:[{digest:{sha256:($d|sub("^sha256:";""))}}],predicate:{schema_version:"v1",tool:"grype",scanner:{version:"0.118.0",database_built:"2026-09-09T00:00:00Z",database_schema_version:"v6"},artifact_digest:$d,sbom_sha256:"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",scanned_at:"2026-09-09T00:00:00Z",status:"passed",findings:{critical:0,high:0,medium:0,low:0,unknown:0}}}' | base64 | tr -d '\n')"
run() { PATH="$scratch/bin:$PATH" MOCK_TRACE="$scratch/trace" MOCK_STATEMENT="$statement" MOCK_SBOM_STATEMENT="$sbom_statement" MOCK_SCAN_STATEMENT="$scan_statement" "$collector" "$image" "$revision" "$scratch/result.json"; }
expect_fail() { if "$@" >/dev/null 2>&1; then printf 'accepted %s\n' "$1" >&2; exit 1; fi; }
: > "$scratch/trace"; run >/dev/null
jq -e --arg d "$digest" --arg r "$revision" --arg input_sha "$input_sha" '.result == "PASS" and .artifact_digest == $d and .source_revision == $r and .input_sha256 == $input_sha and .cryptographic_verification.slsa_provenance == true and .vulnerability_scan.status == "passed"' "$scratch/result.json" >/dev/null
grep -Fq 'verify --certificate-identity' "$scratch/trace"; grep -Fq 'verify-attestation --type slsaprovenance1' "$scratch/trace"; grep -Fq "registry:$image" "$scratch/trace"
: > "$scratch/trace"
PATH="$scratch/bin:$PATH" MOCK_TRACE="$scratch/trace" MOCK_STATEMENT="$statement" MOCK_SBOM_STATEMENT="$sbom_statement" MOCK_SCAN_STATEMENT="$scan_statement" "$collector" "$alternate_image" "$revision" "$scratch/result-alternate.json" >/dev/null
jq -e --arg image "$alternate_image" '.image == $image and .result == "PASS"' "$scratch/result-alternate.json" >/dev/null
grep -Fq -- '--source-name hoodi-example-baseline-validator-fence' "$scratch/trace"
expect_fail "$collector" "123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/hoodi-example-baseline-validator-prysm@$digest" "$revision" "$scratch/fail.json"
expect_fail "$collector" "123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/hoodi_001-baseline-validator-fence@$digest" "$revision" "$scratch/fail.json"
: > "$scratch/trace"
PATH="$scratch/bin:$PATH" MOCK_CURRENT_ONLY=true MOCK_TRACE="$scratch/trace" MOCK_STATEMENT="$statement" MOCK_SBOM_STATEMENT="$sbom_statement" MOCK_SCAN_STATEMENT="$scan_statement" "$collector" "$image" "$revision" "$scratch/result-current.json" >/dev/null
jq -e '.cryptographic_verification.identity == "https://github.com/s1ns3nz0/node-operator/.github/workflows/image-publish.yml@refs/heads/main"' "$scratch/result-current.json" >/dev/null
grep -Fq 'verify-attestation --type slsaprovenance1 --certificate-identity https://github.com/s1ns3nz0/node-operator/.github/workflows/image-publish.yml@refs/heads/main' "$scratch/trace"
base_env=(env PATH="$scratch/bin:$PATH" MOCK_TRACE="$scratch/trace" MOCK_STATEMENT="$statement" MOCK_SBOM_STATEMENT="$sbom_statement" MOCK_SCAN_STATEMENT="$scan_statement")
expect_fail "${base_env[@]}" MOCK_COSIGN_FAIL=true "$collector" "$image" "$revision" "$scratch/fail.json"
expect_fail "${base_env[@]}" MOCK_SIGNATURE_MODE=empty "$collector" "$image" "$revision" "$scratch/fail.json"
expect_fail "${base_env[@]}" MOCK_SIGNATURE_MODE=malformed "$collector" "$image" "$revision" "$scratch/fail.json"
expect_fail "${base_env[@]}" MOCK_SIGNATURE_MODE=wrong-digest "$collector" "$image" "$revision" "$scratch/fail.json"
bad_statement="$(printf '%s' "$statement" | sed 's/.$/A/')"; expect_fail env PATH="$scratch/bin:$PATH" MOCK_TRACE="$scratch/trace" MOCK_STATEMENT="$bad_statement" MOCK_SBOM_STATEMENT="$sbom_statement" MOCK_SCAN_STATEMENT="$scan_statement" "$collector" "$image" "$revision" "$scratch/fail.json"
wrong_revision_statement="$(jq -cn --arg d "${digest#sha256:}" --arg input_sha "$input_sha" '{_type:"https://in-toto.io/Statement/v0.1",predicateType:"https://slsa.dev/provenance/v1",subject:[{digest:{sha256:$d}}],predicate:{buildDefinition:{buildType:"https://slsa.dev/container-based-build/v1",externalParameters:{input_sha256:$input_sha},resolvedDependencies:[{digest:{gitCommit:"0000000000000000000000000000000000000000"}}]},runDetails:{builder:{id:"https://github.com/Attestations/GitHubHostedActions@v1"}}}}' | base64 | tr -d '\n')"
expect_fail env PATH="$scratch/bin:$PATH" MOCK_TRACE="$scratch/trace" MOCK_STATEMENT="$wrong_revision_statement" MOCK_SBOM_STATEMENT="$sbom_statement" MOCK_SCAN_STATEMENT="$scan_statement" "$collector" "$image" "$revision" "$scratch/fail.json"
missing_input_statement="$(jq -cn --arg d "${digest#sha256:}" --arg r "$revision" '{_type:"https://in-toto.io/Statement/v0.1",predicateType:"https://slsa.dev/provenance/v1",subject:[{digest:{sha256:$d}}],predicate:{buildDefinition:{buildType:"https://slsa.dev/container-based-build/v1",resolvedDependencies:[{digest:{gitCommit:$r}}]},runDetails:{builder:{id:"https://github.com/Attestations/GitHubHostedActions@v1"}}}}' | base64 | tr -d '\n')"
expect_fail env PATH="$scratch/bin:$PATH" MOCK_TRACE="$scratch/trace" MOCK_STATEMENT="$missing_input_statement" MOCK_SBOM_STATEMENT="$sbom_statement" MOCK_SCAN_STATEMENT="$scan_statement" "$collector" "$image" "$revision" "$scratch/fail.json"
wrong_input_statement="$(jq -cn --arg d "${digest#sha256:}" --arg r "$revision" '{_type:"https://in-toto.io/Statement/v0.1",predicateType:"https://slsa.dev/provenance/v1",subject:[{digest:{sha256:$d}}],predicate:{buildDefinition:{buildType:"https://slsa.dev/container-based-build/v1",externalParameters:{input_sha256:"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"},resolvedDependencies:[{digest:{gitCommit:$r}}]},runDetails:{builder:{id:"https://github.com/Attestations/GitHubHostedActions@v1"}}}}' | base64 | tr -d '\n')"
expect_fail env PATH="$scratch/bin:$PATH" MOCK_TRACE="$scratch/trace" MOCK_STATEMENT="$wrong_input_statement" MOCK_SBOM_STATEMENT="$sbom_statement" MOCK_SCAN_STATEMENT="$scan_statement" "$collector" "$image" "$revision" "$scratch/fail.json"
bad_sbom="$(jq -cn '{predicate:{bomFormat:"CycloneDX",metadata:{component:{version:"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}}}}' | base64 | tr -d '\n')"
expect_fail env PATH="$scratch/bin:$PATH" MOCK_TRACE="$scratch/trace" MOCK_STATEMENT="$statement" MOCK_SBOM_STATEMENT="$bad_sbom" MOCK_SCAN_STATEMENT="$scan_statement" "$collector" "$image" "$revision" "$scratch/fail.json"
bad_scan="$(jq -cn --arg d "$digest" '{predicate:{artifact_digest:$d,status:"blocked",findings:{critical:1,high:0,unknown:0}}}' | base64 | tr -d '\n')"
expect_fail env PATH="$scratch/bin:$PATH" MOCK_TRACE="$scratch/trace" MOCK_STATEMENT="$statement" MOCK_SBOM_STATEMENT="$sbom_statement" MOCK_SCAN_STATEMENT="$bad_scan" "$collector" "$image" "$revision" "$scratch/fail.json"
expect_fail "${base_env[@]}" MOCK_SYFT_FAIL=true "$collector" "$image" "$revision" "$scratch/fail.json"
expect_fail "${base_env[@]}" MOCK_GRYPE_FAIL=true "$collector" "$image" "$revision" "$scratch/fail.json"
expect_fail "${base_env[@]}" MOCK_SEVERITY=High "$collector" "$image" "$revision" "$scratch/fail.json"
grep -Fq 'v3.1.2/cosign-linux-amd64' "$installer"; grep -Fq 'v1.42.4/syft_1.42.4_linux_amd64.tar.gz' "$installer"; grep -Fq 'install-release-sca-tool.sh' "$installer"
printf 'PASS collector executes authenticated exact-digest verification and rejects verifier, provenance, SBOM and scan failures.\n'
