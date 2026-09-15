#!/usr/bin/env bash
# Check objective: Rebuild the source-bound release twice with frozen publication records and optional OCI payload manifest, then compare output.
set -eo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../../.."
oci_payload_mount=(); oci_payload_arg=()
if [ -n "${OCI_PAYLOAD_MANIFEST:-}" ]; then
  case "$OCI_PAYLOAD_MANIFEST" in
    /*) ;;
    *) printf '%s\n' 'OCI_PAYLOAD_MANIFEST must be an absolute file' >&2; exit 64 ;;
  esac
  [ -f "$OCI_PAYLOAD_MANIFEST" ] && [ ! -L "$OCI_PAYLOAD_MANIFEST" ] || { printf '%s\n' 'OCI_PAYLOAD_MANIFEST must be a regular non-symlink file' >&2; exit 65; }
  oci_payload_mount=(--volume "$OCI_PAYLOAD_MANIFEST:/oci-payload-manifest.json:ro")
  oci_payload_arg=(--oci-payload-manifest /oci-payload-manifest.json)
fi
echo "$REGISTRY_TOKEN" | docker login ghcr.io -u "$REGISTRY_USERNAME" --password-stdin
docker pull "$RELEASE_BUILD_IMAGE"
mkdir -p "$RUNNER_TEMP/current"
prysm_mount=(); prysm_arg=(); fence_mount=(); fence_arg=(); signer_probe_mount=(); signer_probe_arg=(); chart_mount=(); chart_arg=()
if [ -f release/prysm-publication-authorization.json ]; then
  prysm_mount=(--volume "$RUNNER_TEMP/prysm-publication-record/prysm-mtls-publication-record.json:/prysm-publication-record.json:ro")
  prysm_arg=(--prysm-publication-record /prysm-publication-record.json)
fi
if [ -f release/fence-publication-authorization.json ]; then
  fence_mount=(--volume "$RUNNER_TEMP/fence-publication-record/fence-release-verification.json:/fence-release-verification.json:ro")
  fence_arg=(--fence-publication-record /fence-release-verification.json)
fi
if [ -f release/signer-probe-publication-authorization.json ]; then
  signer_probe_mount=(--volume "$RUNNER_TEMP/signer-probe-publication-record/signer-identity-probe-publication-record.json:/signer-probe-publication-record.json:ro")
  signer_probe_arg=(--signer-probe-publication-record /signer-probe-publication-record.json)
fi
if [ -f release/client-chart-publication-authorization.json ]; then
  chart_mount=(--volume "$RUNNER_TEMP/client-chart-publication-records:/client-chart-publication-records:ro")
  chart_arg=(--client-chart-publication-records /client-chart-publication-records)
fi
docker run --rm --user "$(id -u):$(id -g)" --volume "$GITHUB_WORKSPACE:/workspace:ro" --volume "$RUNNER_TEMP/current:/output/current" --volume "$RUNNER_TEMP/release-publication-records:/publication-records:ro" "${prysm_mount[@]}" "${fence_mount[@]}" "${signer_probe_mount[@]}" "${chart_mount[@]}" "${oci_payload_mount[@]}" --workdir /workspace "$RELEASE_BUILD_IMAGE" bash scripts/ci/test-build-release-bundle.sh --publication-records-dir /publication-records "${prysm_arg[@]}" "${fence_arg[@]}" "${signer_probe_arg[@]}" "${chart_arg[@]}" "${oci_payload_arg[@]}" /output/current
