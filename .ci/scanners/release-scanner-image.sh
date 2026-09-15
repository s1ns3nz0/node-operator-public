#!/usr/bin/env bash
set -euo pipefail

: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}"
: "${GITHUB_SHA:?GITHUB_SHA is required}"

scanner_input_sha="$({
  sha256sum \
    .ci/scanners/Dockerfile \
    .ci/scanners/Dockerfile.dockerignore \
    .ci/scanners/run-security-scan.sh \
    scripts/ci/collect-pr-evidence.sh \
    scripts/ci/collect-security-evidence.sh \
    scripts/ci/lib/common.sh
} | awk '{print $1}' | sha256sum | awk '{print $1}')"
repository_slug="$(printf '%s' "$GITHUB_REPOSITORY" | tr '[:upper:]' '[:lower:]')"
image_repository="ghcr.io/$repository_slug/security-scanners"
main_image="$image_repository:main"

docker pull "$main_image" >/dev/null 2>&1 || :
published_input_sha="$(docker image inspect --format '{{ index .Config.Labels "io.node-operator.scanner-input-sha" }}' "$main_image" 2>/dev/null || :)"
if [ -n "$published_input_sha" ] && [ "$published_input_sha" = "$scanner_input_sha" ]; then
  printf 'scanner image inputs are unchanged; skipping build and push\n'
  exit 0
fi

commit_image="$image_repository:$GITHUB_SHA"
docker build --build-arg "SCANNER_INPUT_SHA=$scanner_input_sha" --file .ci/scanners/Dockerfile --tag "$commit_image" --tag "$main_image" .
docker push "$commit_image"
docker push "$main_image"
