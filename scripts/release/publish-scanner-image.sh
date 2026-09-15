#!/usr/bin/env bash
# Check objective: Publish the scanner image release.
# Purpose: Verify a staged scanner image's inputs and publish immutable and main tags.
# Inputs: IMAGE, GITHUB_SHA, REGISTRY_TOKEN, REGISTRY_USERNAME, and SCANNER_IMAGE_DIR (default /tmp/scanner-image).
# Outputs: Signed GHCR image/SBOM and verification evidence under RUNNER_TEMP.
# Side effects: Loads and pushes an image; promotes main only after signature verification.
set -euo pipefail
test "${GITHUB_REF:-}" = refs/heads/main
test "${GITHUB_REPOSITORY:-}" = s1ns3nz0/node-operator
[[ "${GITHUB_SHA:-}" =~ ^[0-9a-f]{40}$ ]]
[[ "${GITHUB_RUN_ID:-}" =~ ^[1-9][0-9]*$ ]]
test "${IMAGE:-}" = ghcr.io/s1ns3nz0/node-operator/security-scanners
: "${RUNNER_TEMP:?RUNNER_TEMP is required for signing evidence}"
command -v cosign >/dev/null
staged_dir="${SCANNER_IMAGE_DIR:-/tmp/scanner-image}"

expected="$({ sha256sum .ci/scanners/Dockerfile .ci/scanners/Dockerfile.dockerignore .ci/scanners/run-security-scan.sh scripts/ci/collect-pr-evidence.sh scripts/ci/collect-security-evidence.sh scripts/ci/lib/common.sh; } | awk '{print $1}' | sha256sum | awk '{print $1}')"
test "$expected" = "$(cat "$staged_dir/scanner-input.sha256")"
docker load --input "$staged_dir/scanner-image.tar"
build_image="$IMAGE:build-${GITHUB_SHA}"
test "$expected" = "$(docker image inspect --format '{{ index .Config.Labels "io.node-operator.scanner-input-sha" }}' "$build_image")"
local_config_digest="$(docker image inspect --format '{{.Id}}' "$build_image")"
python3 scripts/ci/image_sbom_evidence.py verify \
  --archive "$staged_dir/scanner-image.tar" --sbom "$staged_dir/scanner-sbom/sbom.cyclonedx.json" \
  --receipt "$staged_dir/scanner-sbom/receipt.json" --subject security-scanners --revision "$GITHUB_SHA" \
  --image-config-digest "$local_config_digest"
# Unification rejects a defined false decision before registry authentication.
opa eval --fail --format pretty --data policy/image_sbom.rego \
  --input "$staged_dir/scanner-sbom/receipt.json" 'true = data.nodeoperator.image_sbom.allow'
echo "$REGISTRY_TOKEN" | docker login ghcr.io -u "$REGISTRY_USERNAME" --password-stdin
docker tag "$build_image" "$IMAGE:${GITHUB_SHA}"
docker push "$IMAGE:${GITHUB_SHA}"
bash scripts/release/sign-ci-image-evidence.sh "$IMAGE" "$local_config_digest" \
  "$staged_dir/scanner-sbom/sbom.cyclonedx.json" "$staged_dir/scanner-sbom/receipt.json" \
  "${RUNNER_TEMP:?}/scanner-signing-evidence"
docker tag "$build_image" "$IMAGE:main"
docker push "$IMAGE:main"
