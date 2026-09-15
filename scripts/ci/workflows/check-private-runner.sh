#!/usr/bin/env bash
# Check objective: Verify the ephemeral runner and pinned build image without releasing artifacts.
# Purpose: Prove the private CodeBuild runner can authenticate and pull the pinned release-build image.
# Inputs: Runner IDs, registry credentials, RELEASE_BUILD_IMAGE and its independently
# approved RELEASE_BUILD_SOURCE_SHA, RELEASE_BUILD_SBOM and RELEASE_BUILD_RECEIPT.
# Outputs: Exit status only.
# Side effects: Read-only Docker daemon and GHCR login/pull; no artifact publication.
set -euo pipefail

mode="${1:-verify}"
[[ "$#" -le 1 && ( "$mode" = verify || "$mode" = --preflight ) ]] || exit 64
: "${RELEASE_BUILD_SOURCE_SHA:?approved image source SHA is required}"
[[ "$RELEASE_BUILD_SOURCE_SHA" =~ ^[0-9a-f]{40}$ ]] || exit 65
[[ "${RELEASE_BUILD_IMAGE:-}" =~ ^ghcr\.io/s1ns3nz0/node-operator/release-build@sha256:[0-9a-f]{64}$ ]] || exit 65
if [ "$mode" = --preflight ]; then
  [[ "${RELEASE_BUILD_PUBLICATION_RUN_ID:-}" =~ ^[1-9][0-9]*$ ]] || exit 65
  exit 0
fi
test -n "$CODEBUILD_BUILD_ID"
test -n "$GITHUB_RUN_ID"
: "${RELEASE_BUILD_SBOM:?producer SBOM path is required}"
: "${RELEASE_BUILD_RECEIPT:?producer receipt path is required}"
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd -P)"
# Verification must precede daemon access and credential use. The source SHA
# must come from release approval, never from the image under examination.
bash "$root/scripts/ci/verify-ci-image-evidence.sh" "$RELEASE_BUILD_IMAGE" \
  "$RELEASE_BUILD_SOURCE_SHA" "$RELEASE_BUILD_SBOM" "$RELEASE_BUILD_RECEIPT"
docker version --format '{{.Server.Version}}' >/dev/null
echo "$REGISTRY_TOKEN" | docker login ghcr.io -u "$REGISTRY_USERNAME" --password-stdin
docker pull "$RELEASE_BUILD_IMAGE" >/dev/null
