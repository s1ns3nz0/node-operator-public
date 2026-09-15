#!/usr/bin/env bash
# Check objective: Publish the toolchain image release.
# Purpose: Verify a staged toolchain image's inputs and publish immutable and main tags.
# Inputs: DOCKERFILE, IMAGE, IMAGE_NAME, GITHUB_SHA, GITHUB_RUN_ID, REGISTRY_TOKEN, REGISTRY_USERNAME, staged files under TOOLCHAIN_IMAGE_DIR, and optional INPUT_FILE.
# Outputs: Signed GHCR image/SBOM, verification evidence and installer-owned publication records.
# Side effects: Loads a Docker image, authenticates to GHCR, pushes two tags, reads the published immutable-tag manifest, and writes a non-sensitive record under RUNNER_TEMP.
set -euo pipefail
test "${GITHUB_REF:-}" = refs/heads/main
test "${GITHUB_REPOSITORY:-}" = s1ns3nz0/node-operator
[[ "${GITHUB_SHA:-}" =~ ^[0-9a-f]{40}$ ]]
[[ "${GITHUB_RUN_ID:-}" =~ ^[1-9][0-9]*$ ]]
case "${IMAGE_NAME:-}" in
  terraform-validation|release-build|vault-release-signer|gitops-oci-mirror|argocd-bootstrap|vault-bootstrap) ;;
  *) printf '%s\n' 'unapproved toolchain repository' >&2; exit 65 ;;
esac
test "${IMAGE:-}" = "ghcr.io/s1ns3nz0/node-operator/$IMAGE_NAME"
: "${RUNNER_TEMP:?RUNNER_TEMP is required for signing evidence}"
command -v cosign >/dev/null

input_files=("$DOCKERFILE")
if [ -n "${INPUT_FILE:-}" ]; then
  IFS=',' read -r -a extra_input_files <<<"$INPUT_FILE"
  input_files+=("${extra_input_files[@]}")
fi
expected="$(sha256sum "${input_files[@]}" | awk '{print $1}' | sha256sum | awk '{print $1}')"
staged_dir="${TOOLCHAIN_IMAGE_DIR:-/tmp/toolchain-image}"
test "$expected" = "$(cat "$staged_dir/toolchain-input.sha256")"
docker load --input "$staged_dir/toolchain-image.tar"
build_image="$IMAGE:build-${GITHUB_SHA}"
test "$expected" = "$(docker image inspect --format '{{ index .Config.Labels "io.node-operator.toolchain-input-sha" }}' "$build_image")"
local_config_digest="$(docker image inspect --format '{{.Id}}' "$build_image")"
[[ "$local_config_digest" =~ ^sha256:[0-9a-f]{64}$ ]] || { printf '%s\n' 'local toolchain image config digest is invalid' >&2; exit 65; }
python3 scripts/ci/image_sbom_evidence.py verify \
  --archive "$staged_dir/toolchain-image.tar" --sbom "$staged_dir/toolchain-sbom/sbom.cyclonedx.json" \
  --receipt "$staged_dir/toolchain-sbom/receipt.json" --subject "$IMAGE_NAME" --revision "$GITHUB_SHA" \
  --image-config-digest "$local_config_digest"
# Unification rejects a defined false decision before registry authentication.
opa eval --fail --format pretty --data policy/image_sbom.rego \
  --input "$staged_dir/toolchain-sbom/receipt.json" 'true = data.nodeoperator.image_sbom.allow'
echo "$REGISTRY_TOKEN" | docker login ghcr.io -u "$REGISTRY_USERNAME" --password-stdin
docker tag "$build_image" "$IMAGE:${GITHUB_SHA}"
docker push "$IMAGE:${GITHUB_SHA}"
mkdir -m 0700 -p "${RUNNER_TEMP:?}/toolchain-signing-evidence"
bash scripts/release/sign-ci-image-evidence.sh "$IMAGE" "$local_config_digest" \
  "$staged_dir/toolchain-sbom/sbom.cyclonedx.json" "$staged_dir/toolchain-sbom/receipt.json" \
  "${RUNNER_TEMP:?}/toolchain-signing-evidence/$IMAGE_NAME"
docker tag "$build_image" "$IMAGE:main"
docker push "$IMAGE:main"

case "$IMAGE_NAME" in
  vault-bootstrap|gitops-oci-mirror)
    [[ "$GITHUB_SHA" =~ ^[0-9a-f]{40}$ ]] || { printf '%s\n' 'release revision is invalid' >&2; exit 65; }
    [[ "$expected" =~ ^[0-9a-f]{64}$ ]] || { printf '%s\n' 'toolchain input hash is invalid' >&2; exit 65; }
    [[ "${GITHUB_RUN_ID:-}" =~ ^[0-9]+$ ]] || { printf '%s\n' 'publication run id is invalid' >&2; exit 65; }

    manifest="$(mktemp)"
    pinned_manifest="$(mktemp)"
    trap 'rm -f "$manifest" "$pinned_manifest"' EXIT
    docker buildx imagetools inspect --raw "$IMAGE:${GITHUB_SHA}" > "$manifest"
    manifest_digest="sha256:$(sha256sum "$manifest" | awk '{print $1}')"
    [[ "$manifest_digest" =~ ^sha256:[0-9a-f]{64}$ ]] || { printf '%s\n' 'registry manifest digest is invalid' >&2; exit 65; }
    docker buildx imagetools inspect --raw "$IMAGE@$manifest_digest" > "$pinned_manifest"
    cmp -s "$manifest" "$pinned_manifest" || { printf '%s\n' 'pinned registry manifest does not match the SHA-tag manifest' >&2; exit 65; }
    python3 - "$manifest" "$local_config_digest" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    manifest = json.load(handle)
if not isinstance(manifest, dict) or manifest.get("config", {}).get("digest") != sys.argv[2]:
    raise SystemExit("published manifest does not bind the just-built local image")
PY

    record_dir="${RUNNER_TEMP:?RUNNER_TEMP is required for publication records}/toolchain-publication-records"
    mkdir -p "$record_dir"
    record="$record_dir/${IMAGE_NAME}-publication-record.json"
    [ ! -e "$record" ] && [ ! -L "$record" ] || { printf '%s\n' 'refusing to overwrite toolchain publication record' >&2; exit 65; }
    record_tmp="$(mktemp "$record_dir/.${IMAGE_NAME}-publication-record.XXXXXX")"
    chmod 600 "$record_tmp"
    if ! python3 - "$record_tmp" "$IMAGE_NAME" "$GITHUB_SHA" "$IMAGE@$manifest_digest" "$manifest_digest" "$expected" "$GITHUB_RUN_ID" <<'PY'
import json
import os
import sys

path, component, revision, image_ref, digest, input_sha, run_id = sys.argv[1:]
record = {
    "schema_version": 1,
    "component": component,
    "kind": "image",
    "release_revision": revision,
    "build_revision": revision,
    "third_party_source_revision": None,
    "image_ref": image_ref,
    "manifest_digest": digest,
    "input_sha256": input_sha,
    "publication": {"workflow": "image-publish.yml", "run_id": run_id, "invocation": "toolchain-publish"},
    "verification": {"method": "input-hash-and-registry-digest", "status": "passed"},
}
with open(path, "w", encoding="utf-8") as handle:
    json.dump(record, handle, sort_keys=True, separators=(",", ":"))
    handle.write("\n")
    handle.flush()
    os.fsync(handle.fileno())
PY
    then
      rm -f "$record_tmp"
      exit 65
    fi
    ln "$record_tmp" "$record" || { rm -f "$record_tmp"; printf '%s\n' 'refusing to overwrite toolchain publication record' >&2; exit 65; }
    rm -f "$record_tmp"
    ;;
esac
