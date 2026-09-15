#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -lt 2 ]; then
  printf 'usage: %s IMAGE_NAME DOCKERFILE [INPUT_FILE ...]\n' "$0" >&2
  exit 64
fi

: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}"
: "${GITHUB_SHA:?GITHUB_SHA is required}"

image_name="$1"
dockerfile="$2"
shift 2
toolchain_input_sha="$({ sha256sum "$dockerfile" "$@"; } | awk '{print $1}' | sha256sum | awk '{print $1}')"
repository_slug="$(printf '%s' "$GITHUB_REPOSITORY" | tr '[:upper:]' '[:lower:]')"
image_repository="ghcr.io/$repository_slug/$image_name"
main_image="$image_repository:main"

docker pull "$main_image" >/dev/null 2>&1 || :
published_input_sha="$(docker image inspect --format '{{ index .Config.Labels "io.node-operator.toolchain-input-sha" }}' "$main_image" 2>/dev/null || :)"
if [ -n "$published_input_sha" ] && [ "$published_input_sha" = "$toolchain_input_sha" ]; then
  printf '%s image inputs are unchanged; skipping build and push\n' "$image_name"
  exit 0
fi

commit_image="$image_repository:$GITHUB_SHA"
docker build --build-arg "TOOLCHAIN_INPUT_SHA=$toolchain_input_sha" --file "$dockerfile" --tag "$commit_image" --tag "$main_image" .
docker push "$commit_image"
docker push "$main_image"
