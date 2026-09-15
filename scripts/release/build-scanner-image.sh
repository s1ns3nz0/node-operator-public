#!/usr/bin/env bash
# Check objective: Build the scanner image release.
# Purpose: Build a scanner image from reviewed inputs and stage it for the publishing job.
# Inputs: IMAGE, GITHUB_SHA, GITHUB_OUTPUT, and the checked-out scanner source files.
# Outputs: scanner-image.tar, scanner-input.sha256, and changed=true in GITHUB_OUTPUT.
# Side effects: Builds and saves a local Docker image.
set -euo pipefail

input_sha="$({ sha256sum .ci/scanners/Dockerfile .ci/scanners/Dockerfile.dockerignore .ci/scanners/run-security-scan.sh scripts/ci/collect-pr-evidence.sh scripts/ci/collect-security-evidence.sh scripts/ci/lib/common.sh; } | awk '{print $1}' | sha256sum | awk '{print $1}')"
docker build --build-arg "SCANNER_INPUT_SHA=$input_sha" --file .ci/scanners/Dockerfile --tag "$IMAGE:build-${GITHUB_SHA}" .
docker save --output scanner-image.tar "$IMAGE:build-${GITHUB_SHA}"
bash scripts/ci/generate-image-sbom.sh scanner-image.tar scanner-sbom security-scanners "$GITHUB_SHA" \
  "$(docker image inspect --format '{{.Id}}' "$IMAGE:build-${GITHUB_SHA}")"
printf '%s\n' "$input_sha" > scanner-input.sha256
echo 'changed=true' >> "$GITHUB_OUTPUT"
