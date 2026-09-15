#!/usr/bin/env bash
# Check objective: Build the approved release bundle and bind its SBOM to the reproducibility digest.
# Purpose: Rebuild the release bundle and reject it unless its tarball and SBOM match the approved digest.
# Inputs: REGISTRY_TOKEN, REGISTRY_USERNAME, RELEASE_BUILD_IMAGE, APPROVED_ARTIFACT_DIGEST, GITHUB_WORKSPACE, RUNNER_TEMP, PUBLICATION_RECORDS_DIR, and optional OCI_PAYLOAD_MANIFEST.
# Outputs: Bundle and SBOM under RUNNER_TEMP/release.
# Side effects: Authenticates to GHCR, pulls an image, and runs a local Docker build container.
set -euo pipefail

publication_records_directory="${PUBLICATION_RECORDS_DIR:-}"
case "$publication_records_directory" in
  /*) ;;
  *) printf '%s\n' 'PUBLICATION_RECORDS_DIR must be an absolute directory' >&2; exit 64 ;;
esac
[ -d "$publication_records_directory" ] && [ ! -L "$publication_records_directory" ] || { printf '%s\n' 'PUBLICATION_RECORDS_DIR must be a regular directory' >&2; exit 65; }
record_count="$(find "$publication_records_directory" -mindepth 1 -maxdepth 1 -print | wc -l | tr -d '[:space:]')"
[ "$record_count" = 3 ] || { printf '%s\n' 'PUBLICATION_RECORDS_DIR must contain exactly three publication records' >&2; exit 65; }
for component in vault-bootstrap vault-audit-relay gitops-oci-mirror; do
  record="$publication_records_directory/$component-publication-record.json"
  [ -f "$record" ] && [ ! -L "$record" ] || { printf 'missing regular publication record: %s\n' "$component" >&2; exit 65; }
done

workspace="${GITHUB_WORKSPACE:?GITHUB_WORKSPACE is required}"
[ -d "$workspace" ] && [ ! -L "$workspace" ] || { printf '%s\n' 'GITHUB_WORKSPACE must be a regular directory' >&2; exit 65; }
indexer="$workspace/scripts/release/create-installer-artifact-index.py"
catalog="$workspace/.ci/gitops/approved-oci-artifacts.json"
prysm_authorization="$workspace/release/prysm-publication-authorization.json"
fence_authorization="$workspace/release/fence-publication-authorization.json"
client_chart_authorization="$workspace/release/client-chart-publication-authorization.json"
signer_probe_authorization="$workspace/release/signer-probe-publication-authorization.json"
[ -f "$indexer" ] && [ ! -L "$indexer" ] || { printf '%s\n' 'checked-out publication index helper is unavailable' >&2; exit 65; }
[ -f "$catalog" ] && [ ! -L "$catalog" ] || { printf '%s\n' 'checked-out approved artifact catalog is unavailable' >&2; exit 65; }
release_revision="$(git -C "$workspace" rev-parse HEAD)"
[[ "$release_revision" =~ ^[0-9a-f]{40}$ ]] || { printf '%s\n' 'checked-out release revision is invalid' >&2; exit 65; }
umask 077
validation_directory="$(mktemp -d "${RUNNER_TEMP:?RUNNER_TEMP is required}/.release-publication-record-validation.XXXXXX")"
trap 'rm -rf "$validation_directory"' EXIT
python3 "$indexer" \
  --release-sha "$release_revision" \
  --approved-catalog "$catalog" \
  --vault-bootstrap-record "$publication_records_directory/vault-bootstrap-publication-record.json" \
  --audit-relay-record "$publication_records_directory/vault-audit-relay-publication-record.json" \
  --gitops-oci-mirror-record "$publication_records_directory/gitops-oci-mirror-publication-record.json" \
  --output "$validation_directory/installer-artifact-index.json"

prysm_mount=()
prysm_argument=()
if [ -f "$prysm_authorization" ] && [ ! -L "$prysm_authorization" ]; then
  prysm_record="${PRYSM_PUBLICATION_RECORD:-}"
  case "$prysm_record" in /*) ;; *) printf '%s\n' 'authorized Prysm release requires a frozen absolute publication record' >&2; exit 65 ;; esac
  [ -f "$prysm_record" ] && [ ! -L "$prysm_record" ] || { printf '%s\n' 'trusted Prysm publication retrieval produced no regular record' >&2; exit 65; }
  PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$workspace/scripts/release" python3 -B - "$prysm_authorization" "$prysm_record" "$workspace" <<'PY'
import hashlib
from pathlib import Path
import sys
from prysm_publication_record import validate_record
from prysm_release_authorization import SHA40, SHA256, RUN, _obj, _read, _text

authorization_path, record_path, source_root = map(Path, sys.argv[1:])
authorization, _ = _read(authorization_path)
authorization = _obj(authorization, {"schema_version", "candidate_revision", "record_sha256", "publication", "target", "approvals"}, "Prysm authorization")
if type(authorization["schema_version"]) is not int or authorization["schema_version"] != 1:
    raise ValueError("Prysm authorization version is invalid")
candidate = _text(authorization["candidate_revision"], "Prysm candidate revision", SHA40)
publication = _obj(authorization["publication"], {"repository", "workflow", "run_id", "artifact_id"}, "Prysm publication")
if publication["repository"] != "s1ns3nz0/node-operator" or publication["workflow"] != "image-publish.yml" or not isinstance(publication["run_id"], str) or not RUN.fullmatch(publication["run_id"]) or not isinstance(publication["artifact_id"], str) or not RUN.fullmatch(publication["artifact_id"]):
    raise ValueError("Prysm publication identity is invalid")
target = _obj(authorization["target"], {"image_ref", "manifest_digest", "input_sha256"}, "Prysm target")
approvals = _obj(authorization["approvals"], {"stage_approved", "activation_approved"}, "Prysm approvals")
if any(type(value) is not bool for value in approvals.values()) or not approvals["stage_approved"]:
    raise ValueError("Prysm stage approval is absent")
record, raw = _read(record_path)
if _text(authorization["record_sha256"], "Prysm record hash", SHA256) != hashlib.sha256(raw).hexdigest():
    raise ValueError("Prysm frozen record hash differs from authorization")
validated = validate_record(record, source_root, expected_release_revision=candidate)
if str(validated["publication"]["run_id"]) != publication["run_id"] or {
    "image_ref": validated["target"]["image_ref"],
    "manifest_digest": validated["target"]["manifest_digest"],
    "input_sha256": validated["input_sha256"],
} != target:
    raise ValueError("Prysm frozen record context differs from authorization")
PY
  prysm_mount=(--volume "$prysm_record:/prysm-publication-record.json:ro")
  prysm_argument=(--prysm-publication-record /prysm-publication-record.json)
elif [ -e "$prysm_authorization" ] || [ -L "$prysm_authorization" ]; then
  printf '%s\n' 'selected release Prysm authorization is unsafe' >&2; exit 65
fi

client_chart_mount=(); client_chart_argument=()
if [ -f "$client_chart_authorization" ] && [ ! -L "$client_chart_authorization" ]; then
  client_chart_records="${CLIENT_CHART_PUBLICATION_RECORDS:-}"
  case "$client_chart_records" in /*) ;; *) printf '%s\n' 'authorized client chart release requires frozen absolute publication records' >&2; exit 65 ;; esac
  [ -d "$client_chart_records" ] && [ ! -L "$client_chart_records" ] || { printf '%s\n' 'trusted client chart publication retrieval produced no regular directory' >&2; exit 65; }
  PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$workspace/scripts/release" python3 -B - "$client_chart_authorization" "$client_chart_records" <<'PY'
from pathlib import Path
import sys
from client_chart_release_authorization import NAMES, _read, validate_candidate_authorization
auth, _ = _read(Path(sys.argv[1])); directory = Path(sys.argv[2])
evidence = {name: _read(directory / name)[1] for name in NAMES}
if {path.name for path in directory.iterdir()} != set(NAMES): raise ValueError("client chart record directory is incomplete")
validate_candidate_authorization(auth, evidence, "stage")
PY
  client_chart_mount=(--volume "$client_chart_records:/client-chart-publication-records:ro")
  client_chart_argument=(--client-chart-publication-records /client-chart-publication-records)
elif [ -e "$client_chart_authorization" ] || [ -L "$client_chart_authorization" ]; then
  printf '%s\n' 'selected release client chart authorization is unsafe' >&2; exit 65
elif [ -n "${CLIENT_CHART_PUBLICATION_RECORDS:-}" ]; then
  printf '%s\n' 'client chart publication records were supplied without a selected release authorization' >&2; exit 65
fi

fence_mount=()
fence_argument=()
if [ -f "$fence_authorization" ] && [ ! -L "$fence_authorization" ]; then
  fence_record="${FENCE_PUBLICATION_RECORD:-}"
  case "$fence_record" in /*) ;; *) printf '%s\n' 'authorized Fence release requires a frozen absolute publication record' >&2; exit 65 ;; esac
  [ -f "$fence_record" ] && [ ! -L "$fence_record" ] || { printf '%s\n' 'trusted Fence publication retrieval produced no regular record' >&2; exit 65; }
  PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$workspace/scripts/release" python3 -B - "$fence_authorization" "$fence_record" "$workspace" <<'PY'
from pathlib import Path
import sys
from fence_release_authorization import _read, validate_candidate_authorization

authorization, _ = _read(Path(sys.argv[1]))
record, raw = _read(Path(sys.argv[2]))
validate_candidate_authorization(authorization, record, raw, Path(sys.argv[3]), "stage")
PY
  fence_mount=(--volume "$fence_record:/fence-release-verification.json:ro")
  fence_argument=(--fence-publication-record /fence-release-verification.json)
elif [ -e "$fence_authorization" ] || [ -L "$fence_authorization" ]; then
  printf '%s\n' 'selected release Fence authorization is unsafe' >&2; exit 65
elif [ -n "${FENCE_PUBLICATION_RECORD:-}" ]; then
  printf '%s\n' 'Fence publication record was supplied without a selected release authorization' >&2; exit 65
fi

signer_probe_mount=()
signer_probe_argument=()
if [ -f "$signer_probe_authorization" ] && [ ! -L "$signer_probe_authorization" ]; then
  signer_probe_record="${SIGNER_PROBE_PUBLICATION_RECORD:-}"
  case "$signer_probe_record" in /*) ;; *) printf '%s\n' 'authorized signer-probe release requires a frozen absolute publication record' >&2; exit 65 ;; esac
  [ -f "$signer_probe_record" ] && [ ! -L "$signer_probe_record" ] || { printf '%s\n' 'trusted signer-probe publication retrieval produced no regular record' >&2; exit 65; }
  PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$workspace/scripts/release" python3 -B - "$signer_probe_authorization" "$signer_probe_record" "$workspace" <<'PY'
from pathlib import Path
import sys
from signer_probe_release_authorization import _read, validate_candidate_authorization

authorization, _ = _read(Path(sys.argv[1]))
record, raw = _read(Path(sys.argv[2]))
validate_candidate_authorization(authorization, record, raw, Path(sys.argv[3]), "stage")
PY
  signer_probe_mount=(--volume "$signer_probe_record:/signer-probe-publication-record.json:ro")
  signer_probe_argument=(--signer-probe-publication-record /signer-probe-publication-record.json)
elif [ -e "$signer_probe_authorization" ] || [ -L "$signer_probe_authorization" ]; then
  printf '%s\n' 'selected release signer-probe authorization is unsafe' >&2; exit 65
elif [ -n "${SIGNER_PROBE_PUBLICATION_RECORD:-}" ]; then
  printf '%s\n' 'signer-probe publication record was supplied without a selected release authorization' >&2; exit 65
fi

oci_payload_mount=()
oci_payload_argument=()
oci_payload_manifest="${OCI_PAYLOAD_MANIFEST:-}"
if [ -n "$oci_payload_manifest" ]; then
  case "$oci_payload_manifest" in
    /*) ;;
    *) printf '%s\n' 'OCI_PAYLOAD_MANIFEST must be an absolute file' >&2; exit 64 ;;
  esac
  [ -f "$oci_payload_manifest" ] && [ ! -L "$oci_payload_manifest" ] || { printf '%s\n' 'OCI_PAYLOAD_MANIFEST must be a regular non-symlink file' >&2; exit 65; }
  oci_payload_mount=(--volume "$oci_payload_manifest:/oci-payload-manifest.json:ro")
  oci_payload_argument=(--oci-payload-manifest /oci-payload-manifest.json)
fi

release_output="$RUNNER_TEMP/release"
mkdir -p "$release_output"
[ -d "$release_output" ] && [ ! -L "$release_output" ] || { printf '%s\n' 'release output directory must be a regular directory' >&2; exit 65; }
PYTHONDONTWRITEBYTECODE=1 python3 -B - "$release_output" "$publication_records_directory" "${prysm_record:-}" "${fence_record:-}" "${client_chart_records:-}" "${signer_probe_record:-}" <<'PY'
import os
from pathlib import Path
import sys

output = os.path.realpath(sys.argv[1])
for raw in sys.argv[2:]:
    if not raw:
        continue
    input_path = os.path.realpath(raw)
    if os.path.commonpath((output, input_path)) in {output, input_path}:
        raise ValueError("release output directory overlaps a frozen publication input")
PY
echo "$REGISTRY_TOKEN" | docker login ghcr.io -u "$REGISTRY_USERNAME" --password-stdin
docker pull "$RELEASE_BUILD_IMAGE"
docker run --rm --user "$(id -u):$(id -g)" --volume "$GITHUB_WORKSPACE:/workspace:ro" --volume "$release_output:/output/release" --volume "$publication_records_directory:/publication-records:ro" ${prysm_mount[@]+"${prysm_mount[@]}"} ${fence_mount[@]+"${fence_mount[@]}"} ${client_chart_mount[@]+"${client_chart_mount[@]}"} ${signer_probe_mount[@]+"${signer_probe_mount[@]}"} ${oci_payload_mount[@]+"${oci_payload_mount[@]}"} --workdir /workspace "$RELEASE_BUILD_IMAGE" bash scripts/ci/build-release-bundle.sh --publication-records-dir /publication-records ${prysm_argument[@]+"${prysm_argument[@]}"} ${fence_argument[@]+"${fence_argument[@]}"} ${client_chart_argument[@]+"${client_chart_argument[@]}"} ${signer_probe_argument[@]+"${signer_probe_argument[@]}"} ${oci_payload_argument[@]+"${oci_payload_argument[@]}"} /output/release
actual_artifact_digest="sha256:$(sha256sum "$RUNNER_TEMP/release/node-operator-release-bundle.tar" | awk '{print $1}')"
test "$actual_artifact_digest" = "$APPROVED_ARTIFACT_DIGEST"
test "$(jq -er '.metadata.component.version' "$RUNNER_TEMP/release/sbom.cyclonedx.json")" = "$APPROVED_ARTIFACT_DIGEST"
