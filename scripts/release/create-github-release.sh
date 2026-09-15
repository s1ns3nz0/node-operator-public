#!/usr/bin/env bash
# Check objective: Publish exactly the reviewed release bundle and signer verification assets.
# Purpose: Create the GitHub Release for the current tag with the signed bundle assets.
# Inputs: GITHUB_REF_NAME, GH_TOKEN, APPROVED_ARTIFACT_DIGEST, optional OCI_PAYLOAD_DIR, and required files under RUNNER_TEMP/release.
# Outputs: A GitHub Release containing the named bundle, SBOM, provenance, and signer verification assets.
# Side effects: Writes a GitHub Release and uploads its assets.
set -euo pipefail
tag="${GITHUB_REF_NAME}"
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
payload_arguments=()
if [ -n "${OCI_PAYLOAD_DIR:-}" ]; then
  payload_arguments=(--payload "$OCI_PAYLOAD_DIR")
fi
# Validate the exact payload before the first remote write. Command substitution
# propagates failure; a process-substitution read loop would hide verifier errors.
chunk_list="$(PYTHONDONTWRITEBYTECODE=1 python3 -B "$script_dir/release_oci_assets.py" \
  --bundle "$RUNNER_TEMP/release/node-operator-release-bundle.tar" \
  --approved-digest "${APPROVED_ARTIFACT_DIGEST:?approved reproducibility digest is required}" \
  ${payload_arguments[@]+"${payload_arguments[@]}"})"
chunks=()
while IFS= read -r chunk; do
  [ -z "$chunk" ] || chunks+=("$chunk")
done <<< "$chunk_list"
gh release create "$tag" \
  "$RUNNER_TEMP/release/node-operator-release-bundle.tar" \
  "$RUNNER_TEMP/release/node-operator-release-bundle.sha256" \
  "$RUNNER_TEMP/release/manifest.json" \
  "$RUNNER_TEMP/release/sbom.cyclonedx.json" \
  "$RUNNER_TEMP/release/provenance-input.json" \
  "$RUNNER_TEMP/release/signer-output/release-verification.json" \
  ${chunks[@]+"${chunks[@]}"} \
  --title "$tag" --generate-notes
