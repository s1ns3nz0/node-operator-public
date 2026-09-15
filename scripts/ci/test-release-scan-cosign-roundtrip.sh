#!/usr/bin/env bash
# Check objective: Verify synthetic release-scan attestations survive a local Cosign signing round trip.
# Synthetic keys and offline bundles only. Never use these flags for releases.
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
cosign="${COSIGN_BIN:-cosign}"
scratch="$(mktemp -d)"
export COSIGN_TEST_WORKDIR="$scratch"
export COSIGN_PASSWORD=''
cleanup() { rm -rf -- "$scratch"; }
trap cleanup EXIT
printf 'synthetic scan attestation fixture\n' > "$scratch/blob"
digest="sha256:$(shasum -a 256 "$scratch/blob" | awk '{print $1}')"
uri='https://github.com/s1ns3nz0/node-operator/attestations/scan-summary/v1'
jq -n --arg digest "$digest" '{schema_version:"v1",tool:"grype",scanner:{version:"0.118.0",database_built:"2026-09-09T00:00:00Z",database_schema_version:"v6"},artifact_digest:$digest,sbom_sha256:"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",scanned_at:"2026-09-09T00:00:00Z",findings:{critical:0,high:0,medium:0,low:0,unknown:0},status:"passed"}' > "$scratch/summary.json"
# A local signing configuration omits remote signing/timestamp services. The
# synthetic bundle is not a GitHub OIDC or transparency-log release proof.
jq -n '{mediaType:"application/vnd.dev.sigstore.signingconfig.v0.2+json",caUrls:[],oidcUrls:[],rekorTlogUrls:[],tsaUrls:[]}' > "$scratch/offline.json"
"$cosign" generate-key-pair --output-key-prefix "$scratch/synthetic" >/dev/null 2>&1
"$cosign" attest-blob --yes --signing-config "$scratch/offline.json" --key "$scratch/synthetic.key" --predicate "$scratch/summary.json" --type "$uri" --bundle "$scratch/custom.bundle.json" "$scratch/blob" >/dev/null
"$cosign" verify-blob-attestation --insecure-ignore-tlog --key "$scratch/synthetic.pub" --bundle "$scratch/custom.bundle.json" --type "$uri" "$scratch/blob" >/dev/null
jq '.dsseEnvelope' "$scratch/custom.bundle.json" > "$scratch/verified.json"
bash "$root/scripts/ci/verify-release-scan-attestation.sh" "$scratch/verified.json" "$digest" "$scratch/summary.json"
# Reproduce the old bug with the same real CLI: a signature is not enough if
# the built-in vuln conversion drops the release summary fields.
"$cosign" attest-blob --yes --signing-config "$scratch/offline.json" --key "$scratch/synthetic.key" --predicate "$scratch/summary.json" --type vuln --bundle "$scratch/legacy.bundle.json" "$scratch/blob" >/dev/null
jq '.dsseEnvelope' "$scratch/legacy.bundle.json" > "$scratch/legacy.json"
if bash "$root/scripts/ci/verify-release-scan-attestation.sh" "$scratch/legacy.json" "$digest" "$scratch/summary.json" >/dev/null 2>&1; then
  printf '%s\n' 'legacy lossy predicate unexpectedly accepted' >&2; exit 1
fi
printf 'tampered synthetic blob\n' > "$scratch/blob"
if "$cosign" verify-blob-attestation --insecure-ignore-tlog --key "$scratch/synthetic.pub" --bundle "$scratch/custom.bundle.json" --type "$uri" "$scratch/blob" >/dev/null 2>&1; then
  printf '%s\n' 'tampered blob unexpectedly verified' >&2; exit 1
fi
printf '%s\n' 'PASS: real Cosign custom summary roundtrip, legacy rejection, and tamper rejection (synthetic/offline only).'
