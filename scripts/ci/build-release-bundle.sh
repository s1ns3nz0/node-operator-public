#!/usr/bin/env bash
set -euo pipefail

# Build the node-operator release artifact without contacting a registry or a
# cluster.  The artifact is an uncompressed, deterministic POSIX tar archive:
# its entries have fixed ownership, permissions, and modification time.
#
# The bundle deliberately contains only deployable/rendered manifests and
# policy/IaC source needed to review them, plus the fixed reviewed Fence
# build/test inputs and, only when committed authorization selects them, the
# exact five non-secret client-chart evidence files. Other raw scanner evidence,
# credentials, and broad release-tool reports are outside this boundary.

publication_records_directory=''
prysm_publication_record=''
fence_publication_record=''
client_chart_publication_records=''
signer_probe_publication_record=''
oci_payload_manifest=''
while [ "$#" -gt 1 ]; do
  case "$1" in
    --publication-records-dir) publication_records_directory="${2:-}"; shift 2 ;;
    --prysm-publication-record) prysm_publication_record="${2:-}"; shift 2 ;;
    --fence-publication-record) fence_publication_record="${2:-}"; shift 2 ;;
    --client-chart-publication-records) client_chart_publication_records="${2:-}"; shift 2 ;;
    --signer-probe-publication-record) signer_probe_publication_record="${2:-}"; shift 2 ;;
    --oci-payload-manifest) oci_payload_manifest="${2:-}"; shift 2 ;;
    *) printf 'usage: %s [--publication-records-dir ABSOLUTE_DIRECTORY] [--prysm-publication-record ABSOLUTE_FILE] [--fence-publication-record ABSOLUTE_FILE] [--client-chart-publication-records ABSOLUTE_DIRECTORY] [--signer-probe-publication-record ABSOLUTE_FILE] [--oci-payload-manifest ABSOLUTE_FILE] OUTPUT_DIRECTORY\n' "$0" >&2; exit 64 ;;
  esac
done
[ "$#" -eq 1 ] || { printf 'usage: %s [--publication-records-dir ABSOLUTE_DIRECTORY] [--prysm-publication-record ABSOLUTE_FILE] [--fence-publication-record ABSOLUTE_FILE] [--client-chart-publication-records ABSOLUTE_DIRECTORY] [--signer-probe-publication-record ABSOLUTE_FILE] [--oci-payload-manifest ABSOLUTE_FILE] OUTPUT_DIRECTORY\n' "$0" >&2; exit 64; }
output_directory="$1"

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$script_dir/lib/common.sh"

root="$(repo_root)"
require_command kubectl
require_command node
require_command shasum
require_command syft
require_command jq
require_command python3

source_revision="$(git -C "$root" rev-parse HEAD)"
[[ "$source_revision" =~ ^[0-9a-f]{40}$ ]] || { printf 'unable to determine source revision\n' >&2; exit 1; }

if [ -n "$publication_records_directory" ]; then
  case "$publication_records_directory" in /*) ;; *) printf '%s\n' 'publication records directory must be absolute' >&2; exit 64 ;; esac
  [ -d "$publication_records_directory" ] && [ ! -L "$publication_records_directory" ] || { printf '%s\n' 'publication records directory must be a regular directory' >&2; exit 65; }
  expected_record_count=3
  actual_record_count="$(find "$publication_records_directory" -mindepth 1 -maxdepth 1 -print | wc -l | tr -d '[:space:]')"
  [ "$actual_record_count" = "$expected_record_count" ] || { printf '%s\n' 'publication records directory must contain exactly the three required component records' >&2; exit 65; }
  for record in vault-bootstrap vault-audit-relay gitops-oci-mirror; do
    path="$publication_records_directory/$record-publication-record.json"
    [ -f "$path" ] && [ ! -L "$path" ] || { printf 'missing regular publication record: %s\n' "$record" >&2; exit 65; }
  done
fi

if [ -n "$prysm_publication_record" ]; then
  case "$prysm_publication_record" in /*) ;; *) printf '%s\n' 'Prysm publication record must be an absolute regular file' >&2; exit 64 ;; esac
  [ -f "$prysm_publication_record" ] && [ ! -L "$prysm_publication_record" ] || { printf '%s\n' 'Prysm publication record must be an absolute regular file' >&2; exit 65; }
fi

if [ -n "$fence_publication_record" ]; then
  case "$fence_publication_record" in /*) ;; *) printf '%s\n' 'Fence publication record must be an absolute regular file' >&2; exit 64 ;; esac
  [ -f "$fence_publication_record" ] && [ ! -L "$fence_publication_record" ] || { printf '%s\n' 'Fence publication record must be an absolute regular file' >&2; exit 65; }
fi

if [ -n "$signer_probe_publication_record" ]; then
  case "$signer_probe_publication_record" in /*) ;; *) printf '%s\n' 'signer-probe publication record must be an absolute regular file' >&2; exit 64 ;; esac
  [ -f "$signer_probe_publication_record" ] && [ ! -L "$signer_probe_publication_record" ] || { printf '%s\n' 'signer-probe publication record must be an absolute regular file' >&2; exit 65; }
fi

if [ -n "$oci_payload_manifest" ]; then
  case "$oci_payload_manifest" in /*) ;; *) printf '%s\n' 'OCI payload manifest must be an absolute regular file' >&2; exit 64 ;; esac
  [ -f "$oci_payload_manifest" ] && [ ! -L "$oci_payload_manifest" ] || { printf '%s\n' 'OCI payload manifest must be an absolute regular file' >&2; exit 65; }
fi

if [ -n "$client_chart_publication_records" ]; then
  case "$client_chart_publication_records" in /*) ;; *) printf '%s\n' 'client chart publication records directory must be absolute' >&2; exit 64 ;; esac
  [ -d "$client_chart_publication_records" ] && [ ! -L "$client_chart_publication_records" ] || { printf '%s\n' 'client chart publication records directory must be a regular directory' >&2; exit 65; }
  client_chart_count="$(find "$client_chart_publication_records" -mindepth 1 -maxdepth 1 -print | wc -l | tr -d '[:space:]')"
  [ "$client_chart_count" = 5 ] || { printf '%s\n' 'client chart publication records directory must contain exactly five records' >&2; exit 65; }
  for client_chart_record in gitops-chart-subject.json gitops-chart-sbom.json gitops-chart-grype.json gitops-chart-provenance-predicate.json gitops-chart-provenance-verified.json; do
    [ -f "$client_chart_publication_records/$client_chart_record" ] && [ ! -L "$client_chart_publication_records/$client_chart_record" ] || { printf 'missing regular client chart publication record: %s\n' "$client_chart_record" >&2; exit 65; }
  done
fi

umask 077
temporary_directory="$(mktemp -d)"
trap 'rm -rf "$temporary_directory"' EXIT
stage_directory="$temporary_directory/stage"
mkdir -p "$stage_directory/source" "$stage_directory/rendered"

path_is_in_release_boundary() {
  case "$1" in
    .env.example|release/.env.example|release/env.example)
      return 0
      ;;
    # Temporary private publication transport is not a deployment dependency.
    release/oci-payload-source.json)
      return 1
      ;;
    # Operator-local inputs never ship, even if accidentally committed under
    # an otherwise eligible source directory. Keep example schemas only.
    */.env|*/env|*/.env.*|*/env.*.local|*/keystore-*.json|*/deposit_data-*.json|*/deposit-data-*.json|*/terraform.tfstate*|*/terraform.tfvars|*/terraform.tfvars.json|*.tfplan|*.p12|*.pfx|*.key)
      return 1
      ;;
    # Historical maintenance tools are bound to the maintainer's old identity,
    # validator key or deleted resource IDs, not a new installer deployment.
    scripts/ops/verify-hoodi-example-signer-tls-rejection.sh|scripts/ops/configure-private-vault-operator-auth.sh|scripts/ops/recover-and-configure-private-vault-operator-auth.sh|scripts/ops/with-private-vault-operator.sh|scripts/ops/publish-reviewed-vault-grpc-candidates.sh|scripts/ci/check-ops-access-ssm-retention-plan.sh)
      return 1
      ;;
    # Missing-history preparation verifies this exact non-secret source pin.
    .ci/web3signer-hardened/source.lock.json|scripts/ops/lib/uc5-beacon-reader.py)
      return 0
      ;;
    # Bind the reviewed, non-secret Prysm advisory and expiry policy in bundles.
    .ci/prysm-mtls-applicability.json|.ci/prysm-mtls-applicability/GO-2026-5932.json)
      return 0
      ;;
    # Package only the reviewed non-secret observability inputs, not local
    # telemetry, evidence, credentials, or arbitrary files in this directory.
    deploy/observability/kustomization.yaml|deploy/observability/namespace.yaml|deploy/observability/service-accounts.yaml|deploy/observability/rbac.yaml|deploy/observability/network-policies.yaml|deploy/observability/fluent-bit-config.yaml|deploy/observability/fluent-bit-daemonset.template.yaml|deploy/observability/evidence-envelope.schema.json|docs/gitops/vault-values.example.yaml|docs/gitops/vault-gp3-encrypted-storageclass.yaml|.ci/toolchains/vault-bootstrap.Dockerfile|.ci/toolchains/gitops-oci-mirror.Dockerfile|.ci/vault-audit-relay/Dockerfile)
      return 0
      ;;
    deploy/kyverno/kustomization.yaml|deploy/kyverno/policies/*.yaml)
      return 0
      ;;
    deploy/base/*.yaml|deploy/prysm/*.yaml|deploy/nethermind/*.yaml|deploy/vault/*.hcl|deploy/vault/*.json|deploy/validator/vault/onboarding-write.hcl|deploy/validator/vault/runtime-read.hcl|deploy/validator/vault/slashing-db-read.hcl|deploy/validator/vault/client-tls-read.hcl|deploy/validator/vault/runtime-kubernetes-auth-role.json|deploy/validator/vault/slashing-db-kubernetes-auth-role.json|deploy/validator/vault/client-tls-kubernetes-auth-role.json|deploy/argocd/node-operator-client-application.yaml|deploy/validator/*.yaml|docs/gitops/argocd-private-values.example.yaml|docs/gitops/cert-manager-values.example.yaml|docs/gitops/vault-tls-internal-ca.example.yaml|infra/terraform/*.tf|infra/terraform/*.json|infra/terraform/terraform.tfvars.example|infra/bootstrap-state/*.tf|infra/bootstrap-state/*.example|infra/foundation-network/*.tf|infra/foundation-network/*.example|infra/ops-access/*.tf|infra/ops-access/*.example|infra/ops-access/.terraform.lock.hcl|infra/baseline/*.tf|policy/data/*.rego|policy/data/*.json|policy/runtime/*.rego|policy/terraform/*.rego|policy/prysm/*.rego|policy/nethermind/hardening.rego|policy/schemas/*.json|policy/*.rego|release/*.json|release/*.example|.ci/gitops/approved-oci-artifacts.json|.ci/gitops/helm-oci/*.json|.ci/validator/approved-client-images.json|.ci/validator/approved-runtime-images.json|.ci/custody-verifier/source-lock.json|.ci/prysm-mtls/source.lock.json|.ci/prysm-mtls/Dockerfile|.ci/prysm-mtls/Dockerfile.dockerignore|.ci/prysm-mtls/patches/0001-web3signer-http-mtls.patch|.ci/prysm-mtls/patches/0002-security-dependencies.patch|cmd/vault-audit-relay/*.go|scripts/ci/check-ops-access-ssm-retention-plan.sh|scripts/release/*.sh|scripts/release/*.py|scripts/ops/*.sh|scripts/ops/verify-custody-validator-key.py|scripts/ops/verify-custody-keystore-secret.py|scripts/ops/recover-missing-hoodi-slashing-history.py)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

materialize_source_file() {
  local relative_path="$1"
  mkdir -p "$stage_directory/source/$(dirname "$relative_path")"
  git -C "$root" show "$source_revision:$relative_path" > "$stage_directory/source/$relative_path"
  case "$relative_path" in
    scripts/release/*.sh|scripts/release/*.py|scripts/ops/*|scripts/ci/check-ops-access-ssm-retention-plan.sh) chmod 0755 "$stage_directory/source/$relative_path" ;;
  esac
}

# Fence release evidence is assessed against this deliberately small reviewed
# input set.  It is materialized directly from the selected revision, never
# from the builder's working tree and never by copying a broad CI directory.
materialize_fence_build_input() {
  case "$1" in
    go.mod|.ci/validator-signing-fence/Dockerfile|cmd/validator-signing-fence/main.go|cmd/validator-signing-fence/main_test.go|scripts/ci/collect-validator-signing-fence-release-evidence.sh|.github/workflows/fence-security.yml|.ci/fence-security/Dockerfile|.ci/fence-security/blackbox.go|.ci/fence-security/tools.env|.ci/fence-security/zap-report.jq|scripts/ci/install-fence-security-tools.sh|scripts/ci/run-fence-security-sast.sh|scripts/ci/run-fence-security-dast.sh)
      materialize_source_file "$1"
      ;;
    *)
      printf 'unsafe Fence build input path: %s\n' "$1" >&2
      exit 65
      ;;
  esac
}

materialize_signer_probe_build_input() {
  case "$1" in
    go.mod|.ci/validator-signer-identity-probe/Dockerfile|.ci/validator-signer-identity-probe/Dockerfile.dockerignore|cmd/validator-signer-identity-probe/main.go|cmd/validator-signer-identity-probe/main_test.go)
      materialize_source_file "$1" ;;
    *) printf 'unsafe signer-probe build input path: %s\n' "$1" >&2; exit 65 ;;
  esac
}

while IFS= read -r relative_path; do
  path_is_in_release_boundary "$relative_path" && materialize_source_file "$relative_path"
done < <(git -C "$root" ls-tree -r --name-only "$source_revision" | LC_ALL=C sort)

for fence_build_input in \
  go.mod \
  .ci/validator-signing-fence/Dockerfile \
  cmd/validator-signing-fence/main.go \
  cmd/validator-signing-fence/main_test.go \
  scripts/ci/collect-validator-signing-fence-release-evidence.sh \
  .github/workflows/fence-security.yml \
  .ci/fence-security/Dockerfile \
  .ci/fence-security/blackbox.go \
  .ci/fence-security/tools.env \
  .ci/fence-security/zap-report.jq \
  scripts/ci/install-fence-security-tools.sh \
  scripts/ci/run-fence-security-sast.sh \
  scripts/ci/run-fence-security-dast.sh; do
  materialize_fence_build_input "$fence_build_input"
done

for signer_probe_build_input in \
  go.mod \
  .ci/validator-signer-identity-probe/Dockerfile \
  .ci/validator-signer-identity-probe/Dockerfile.dockerignore \
  cmd/validator-signer-identity-probe/main.go \
  cmd/validator-signer-identity-probe/main_test.go; do
  materialize_signer_probe_build_input "$signer_probe_build_input"
done

kubectl kustomize "$stage_directory/source/deploy/prysm" > "$stage_directory/rendered/prysm.yaml"
kubectl kustomize "$stage_directory/source/deploy/nethermind" > "$stage_directory/rendered/nethermind.yaml"

# OCI chunk assets are GitHub release assets, deliberately outside this primary
# bundle.  Bind only their bounded, strict manifest to the candidate bundle.
if [ -n "$oci_payload_manifest" ]; then
  cp "$oci_payload_manifest" "$stage_directory/rendered/installer-oci-payload-manifest.json"
  chmod 600 "$stage_directory/rendered/installer-oci-payload-manifest.json"
fi

# The committed authorization is the explicit decision to bind a prior
# candidate publication to this release.  The record itself is supplied only
# by the caller, copied byte-for-byte, and never inferred from a local path.
prysm_authorization="$stage_directory/source/release/prysm-publication-authorization.json"
staged_prysm_record="$stage_directory/rendered/prysm-mtls-publication-record.json"
if [ -f "$prysm_authorization" ] && [ ! -L "$prysm_authorization" ]; then
  [ -n "$prysm_publication_record" ] || { printf '%s\n' 'selected release authorizes Prysm publication evidence but no record was supplied' >&2; exit 65; }
  cp "$prysm_publication_record" "$staged_prysm_record"
  chmod 600 "$staged_prysm_record"
elif [ -e "$prysm_authorization" ] || [ -L "$prysm_authorization" ]; then
  printf '%s\n' 'selected release Prysm authorization is unsafe' >&2
  exit 65
elif [ -n "$prysm_publication_record" ]; then
  printf '%s\n' 'Prysm publication record was supplied without a selected release authorization' >&2
  exit 65
fi

signer_probe_authorization="$stage_directory/source/release/signer-probe-publication-authorization.json"
staged_signer_probe_record="$stage_directory/rendered/signer-probe-publication-record.json"
if [ -f "$signer_probe_authorization" ] && [ ! -L "$signer_probe_authorization" ]; then
  [ -n "$signer_probe_publication_record" ] || { printf '%s\n' 'selected release authorizes signer-probe publication evidence but no record was supplied' >&2; exit 65; }
  cp "$signer_probe_publication_record" "$staged_signer_probe_record"
  chmod 600 "$staged_signer_probe_record"
elif [ -e "$signer_probe_authorization" ] || [ -L "$signer_probe_authorization" ]; then
  printf '%s\n' 'selected release signer-probe authorization is unsafe' >&2; exit 65
elif [ -n "$signer_probe_publication_record" ]; then
  printf '%s\n' 'signer-probe publication record was supplied without a selected release authorization' >&2; exit 65
fi

# Like Prysm, Fence evidence is caller-supplied only when the selected release
# carries a committed authorization.  The raw collector output is copied as
# bytes so the authorization validator can bind that exact record and the
# manifest can bind both files.
fence_authorization="$stage_directory/source/release/fence-publication-authorization.json"
staged_fence_record="$stage_directory/rendered/fence-release-verification.json"
if [ -f "$fence_authorization" ] && [ ! -L "$fence_authorization" ]; then
  [ -n "$fence_publication_record" ] || { printf '%s\n' 'selected release authorizes Fence publication evidence but no record was supplied' >&2; exit 65; }
  cp "$fence_publication_record" "$staged_fence_record"
  chmod 600 "$staged_fence_record"
elif [ -e "$fence_authorization" ] || [ -L "$fence_authorization" ]; then
  printf '%s\n' 'selected release Fence authorization is unsafe' >&2
  exit 65
elif [ -n "$fence_publication_record" ]; then
  printf '%s\n' 'Fence publication record was supplied without a selected release authorization' >&2
  exit 65
fi

client_chart_authorization="$stage_directory/source/release/client-chart-publication-authorization.json"
client_chart_stage="$stage_directory/rendered/client-chart-publication-records"
if [ -f "$client_chart_authorization" ] && [ ! -L "$client_chart_authorization" ]; then
  [ -n "$client_chart_publication_records" ] || { printf '%s\n' 'selected release authorizes client chart publication evidence but no records were supplied' >&2; exit 65; }
  mkdir -p "$client_chart_stage"
  for client_chart_record in gitops-chart-subject.json gitops-chart-sbom.json gitops-chart-grype.json gitops-chart-provenance-predicate.json gitops-chart-provenance-verified.json; do
    cp "$client_chart_publication_records/$client_chart_record" "$client_chart_stage/$client_chart_record"
    chmod 600 "$client_chart_stage/$client_chart_record"
  done
elif [ -e "$client_chart_authorization" ] || [ -L "$client_chart_authorization" ]; then
  printf '%s\n' 'selected release client chart authorization is unsafe' >&2; exit 65
elif [ -n "$client_chart_publication_records" ]; then
  printf '%s\n' 'client chart publication records were supplied without a selected release authorization' >&2; exit 65
fi

# Publication evidence is optional while legacy release callers remain
# index-less and therefore not deploy-ready for Vault artifact authority.
# When explicitly supplied, rebuild the index from the selected revision's
# staged catalog and helper; never accept a prebuilt index from the caller or
# a dirty working-tree helper.
if [ -n "$publication_records_directory" ]; then
  PYTHONDONTWRITEBYTECODE=1 python3 -B "$stage_directory/source/scripts/release/create-installer-artifact-index.py" \
    --release-sha "$source_revision" \
    --approved-catalog "$stage_directory/source/.ci/gitops/approved-oci-artifacts.json" \
    --vault-bootstrap-record "$publication_records_directory/vault-bootstrap-publication-record.json" \
    --audit-relay-record "$publication_records_directory/vault-audit-relay-publication-record.json" \
    --gitops-oci-mirror-record "$publication_records_directory/gitops-oci-mirror-publication-record.json" \
    --output "$stage_directory/rendered/installer-artifact-index.json"
  # Check the generated real catalog with the same validator used by mirroring,
  # before a reproducible but unusable index can become release evidence.
  PYTHONDONTWRITEBYTECODE=1 python3 -B - "$stage_directory/source/scripts/release" "$stage_directory/rendered/installer-artifact-index.json" <<'PY'
import json
from pathlib import Path
import sys
sys.path.insert(0, sys.argv[1])
from installer_artifact_receipt import _validate_index, _validate_raw_index
raw = Path(sys.argv[2]).read_bytes()
index = json.loads(raw)
_validate_raw_index(index, raw)
_validate_index(index)
PY
fi

# Kubernetes Secret objects and common private-key encodings do not belong in
# a distributable release bundle.  This is a boundary check, not a substitute
# for a secret scanner in CI.
secret_pattern='(^|[[:space:]])kind:[[:space:]]*Secret([[:space:]]|$)|-----BEGIN( [A-Z]+)? PRIVATE KEY-----|DO_NOT_PERSIST_'
if command -v rg >/dev/null 2>&1; then
  secret_scan=(rg -n --glob '*')
else
  command -v grep >/dev/null 2>&1 || { printf '%s\n' 'missing command: rg or grep' >&2; exit 69; }
  secret_scan=(grep -R -n -E)
fi
if "${secret_scan[@]}" "$secret_pattern" "$stage_directory" >/dev/null; then
  printf 'release bundle input crosses the non-sensitive artifact boundary\n' >&2
  exit 1
fi

node - "$stage_directory" "$source_revision" <<'NODE'
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const [stage, revision] = process.argv.slice(2);

function files(dir) {
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const absolute = path.join(dir, entry.name);
    return entry.isDirectory() ? files(absolute) : [absolute];
  });
}

const entries = files(stage).map((absolute) => {
  const bytes = fs.readFileSync(absolute);
  return {
    path: path.relative(stage, absolute).split(path.sep).join('/'),
    sha256: crypto.createHash('sha256').update(bytes).digest('hex'),
    size: bytes.length,
  };
}).sort((a, b) => a.path.localeCompare(b.path));

const manifest = {
  schema_version: 'v1',
  artifact: { name: 'node-operator-release-bundle.tar', media_type: 'application/x-tar' },
  source_revision: revision,
  entries,
};
fs.writeFileSync(path.join(stage, 'bundle-manifest.json'), `${JSON.stringify(manifest, null, 2)}\n`);
NODE

if [ -f "$prysm_authorization" ]; then
  PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$stage_directory/source/scripts/release" python3 -B - "$stage_directory" "$source_revision" <<'PY'
from pathlib import Path
import sys
from prysm_release_authorization import validate_release_authorization

validate_release_authorization(Path(sys.argv[1]), sys.argv[2], "stage")
PY
fi

if [ -f "$fence_authorization" ]; then
  PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$stage_directory/source/scripts/release" python3 -B - "$stage_directory" "$source_revision" <<'PY'
from pathlib import Path
import sys
from fence_release_authorization import validate_release_authorization

validate_release_authorization(Path(sys.argv[1]), sys.argv[2], "stage")
PY
fi

if [ -f "$signer_probe_authorization" ]; then
  PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$stage_directory/source/scripts/release" python3 -B - "$stage_directory" "$source_revision" <<'PY'
from pathlib import Path
import sys
from signer_probe_release_authorization import validate_release_authorization

validate_release_authorization(Path(sys.argv[1]), sys.argv[2], "stage")
PY
fi

if [ -f "$client_chart_authorization" ]; then
  PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$stage_directory/source/scripts/release" python3 -B - "$stage_directory" "$source_revision" <<'PY'
from pathlib import Path
import sys
from client_chart_release_authorization import validate_release_authorization

validate_release_authorization(Path(sys.argv[1]), sys.argv[2], "stage")
PY
fi

# Bind an OCI payload only to the exact approved roots from this candidate's
# source.  These placeholders affect destination projection only; no AWS call,
# credential lookup, image approval, or image creation occurs here.
if [ -n "$oci_payload_manifest" ]; then
  PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$stage_directory/source/scripts/release" python3 -B - "$stage_directory" "$source_revision" <<'PY'
import json
import re
import sys
from pathlib import Path
from pathlib import PurePosixPath

from installer_artifact_inventory import InventoryError, build_inventory
from installer_oci_selection import SelectionError, approved_roots
from installer_oci_payload import MAX_ENTRIES, MAX_METADATA_BYTES, OciPayloadError

stage, revision = Path(sys.argv[1]), sys.argv[2]
path = stage / "rendered/installer-oci-payload-manifest.json"

def reject(message):
    raise OciPayloadError(message)

def no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            reject("payload manifest contains duplicate JSON object key")
        result[key] = value
    return result

try:
    raw = path.read_bytes()
    if len(raw) > MAX_METADATA_BYTES:
        reject("payload manifest metadata is too large")
    manifest = json.loads(raw.decode("utf-8"), object_pairs_hook=no_duplicates)
    if not isinstance(manifest, dict) or set(manifest) != {"schema_version", "roots", "entries", "chunks"} or manifest["schema_version"] != 1:
        reject("payload manifest schema is invalid")
    roots = manifest["roots"]
    if not isinstance(roots, dict) or not roots:
        reject("payload manifest roots are invalid")
    digest = re.compile(r"sha256:[0-9a-f]{64}\Z")
    label = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
    actual = {}
    for name, value in roots.items():
        if not isinstance(name, str) or not label.fullmatch(name) or not isinstance(value, dict) or set(value) != {"root_digest", "root_media_type", "root_annotations"} or not isinstance(value["root_digest"], str) or not digest.fullmatch(value["root_digest"]) or not isinstance(value["root_media_type"], str) or not isinstance(value["root_annotations"], dict):
            reject("payload manifest root is invalid")
        actual[name] = value["root_digest"]
    if not isinstance(manifest["entries"], list) or not isinstance(manifest["chunks"], list) or len(manifest["entries"]) > MAX_ENTRIES or not manifest["chunks"]:
        reject("payload manifest entries or chunks are invalid")
    def safe_member(name):
        if not isinstance(name, str) or not name or "\\" in name:
            reject("payload manifest member path is invalid")
        item = PurePosixPath(name)
        if item.is_absolute() or any(part in ("", ".", "..") for part in item.parts) or str(item) != name:
            reject("payload manifest member path is invalid")
        return name
    entries = {}
    for item in manifest["entries"]:
        if not isinstance(item, dict) or set(item) != {"path", "sha256", "size"}:
            reject("payload manifest entry schema is invalid")
        name = safe_member(item.get("path"))
        if name in entries or not isinstance(item.get("sha256"), str) or not re.fullmatch(r"[0-9a-f]{64}", item["sha256"]) or not isinstance(item.get("size"), int) or isinstance(item["size"], bool) or item["size"] < 0:
            reject("payload manifest entry is invalid")
        entries[name] = item
    chunk_members = []
    chunk_names = set()
    for item in manifest["chunks"]:
        if not isinstance(item, dict) or set(item) != {"name", "sha256", "size", "entries"} or not isinstance(item.get("name"), str) or not re.fullmatch(r"chunks/oci-payload-[0-9]{5}\.tar", item["name"]) or not isinstance(item.get("sha256"), str) or not re.fullmatch(r"[0-9a-f]{64}", item["sha256"]) or not isinstance(item.get("size"), int) or isinstance(item["size"], bool) or item["size"] <= 0 or item["size"] >= 2 * 1024 * 1024 * 1024 or not isinstance(item.get("entries"), list):
            reject("payload manifest chunk is invalid")
        members = [safe_member(name) for name in item["entries"]]
        if item["name"] in chunk_names:
            reject("payload manifest chunk names are duplicated")
        chunk_names.add(item["name"])
        if len(members) != len(set(members)) or any(name not in entries for name in members):
            reject("payload manifest chunk members are invalid")
        chunk_members.extend(members)
    if sorted(chunk_members) != sorted(entries) or len(chunk_members) != len(set(chunk_members)):
        reject("payload manifest chunks do not cover entries exactly")
    expected = approved_roots(build_inventory(stage, revision, "000000000000", "ap-northeast-2", "release-check", require_signer_probe=True))
    if actual != expected:
        reject("payload roots differ from this release candidate inventory")
except (OSError, UnicodeDecodeError, json.JSONDecodeError, InventoryError, SelectionError, OciPayloadError) as error:
    print(f"OCI payload manifest binding failed: {error}", file=sys.stderr)
    raise SystemExit(65)
PY
fi

mkdir -p "$output_directory"
artifact_path="$output_directory/node-operator-release-bundle.tar"

node - "$stage_directory" "$artifact_path" <<'NODE'
const fs = require('node:fs');
const path = require('node:path');
const [stage, destination] = process.argv.slice(2);

function files(dir) {
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const absolute = path.join(dir, entry.name);
    return entry.isDirectory() ? files(absolute) : [absolute];
  });
}
function octal(value, length) {
  return `${value.toString(8).padStart(length - 1, '0')}\0`;
}
function writeString(buffer, offset, length, value) {
  Buffer.from(value, 'utf8').copy(buffer, offset, 0, Math.min(Buffer.byteLength(value), length));
}
function header(name, size, mode) {
  if (Buffer.byteLength(name) > 100) throw new Error(`tar entry name is too long: ${name}`);
  const block = Buffer.alloc(512, 0);
  writeString(block, 0, 100, name);
  writeString(block, 100, 8, octal(mode, 8));
  writeString(block, 108, 8, octal(0, 8));
  writeString(block, 116, 8, octal(0, 8));
  writeString(block, 124, 12, octal(size, 12));
  writeString(block, 136, 12, octal(0, 12));
  block.fill(0x20, 148, 156);
  block[156] = '0'.charCodeAt(0);
  writeString(block, 257, 6, 'ustar\0');
  writeString(block, 263, 2, '00');
  const checksum = block.reduce((sum, byte) => sum + byte, 0);
  writeString(block, 148, 8, octal(checksum, 8));
  return block;
}

const output = fs.openSync(destination, 'w', 0o600);
try {
  for (const absolute of files(stage).sort()) {
    const bytes = fs.readFileSync(absolute);
    const name = path.relative(stage, absolute).split(path.sep).join('/');
    const mode = name.startsWith('source/scripts/release/') || name.startsWith('source/scripts/ops/') || name === 'source/scripts/ci/check-ops-access-ssm-retention-plan.sh' ? 0o755 : 0o644;
    fs.writeSync(output, header(name, bytes.length, mode));
    fs.writeSync(output, bytes);
    const padding = (512 - (bytes.length % 512)) % 512;
    if (padding) fs.writeSync(output, Buffer.alloc(padding));
  }
  fs.writeSync(output, Buffer.alloc(1024));
} finally {
  fs.closeSync(output);
}
NODE

artifact_hash="$(shasum -a 256 "$artifact_path" | awk '{print $1}')"
artifact_digest="sha256:$artifact_hash"
printf '%s  %s\n' "$artifact_digest" "$(basename "$artifact_path")" > "$output_directory/node-operator-release-bundle.sha256"

# Scan the already-built local file only.  Disable Syft's update check; Syft
# enrichment is disabled by default and is not enabled here.
SYFT_CHECK_FOR_APP_UPDATE=false syft scan "file:$artifact_path" \
  --source-name "$(basename "$artifact_path")" \
  --source-version "$artifact_digest" \
  --output "cyclonedx-json=$output_directory/sbom.cyclonedx.json" \
  --quiet
# A manifest-only archive can have no discoverable package components. Some
# Syft CycloneDX versions omit that optional field, while the release collector
# requires an array. Preserve an existing value exactly; add [] only if absent.
jq 'if has("components") then . else . + {components: []} end' \
  "$output_directory/sbom.cyclonedx.json" > "$temporary_directory/sbom.cyclonedx.json"
mv "$temporary_directory/sbom.cyclonedx.json" "$output_directory/sbom.cyclonedx.json"

node - "$stage_directory/bundle-manifest.json" "$output_directory/manifest.json" "$output_directory/provenance-input.json" "$artifact_digest" "$source_revision" <<'NODE'
const fs = require('node:fs');
const [contentsManifest, outputManifest, provenance, digest, revision] = process.argv.slice(2);
const contents = JSON.parse(fs.readFileSync(contentsManifest, 'utf8'));
const manifest = { ...contents, artifact: { ...contents.artifact, digest } };
const provenanceInput = {
  _type: 'https://in-toto.io/Statement/v1',
  subject: [{ name: 'node-operator-release-bundle.tar', digest: { sha256: digest.slice('sha256:'.length) } }],
  predicateType: 'https://slsa.dev/provenance/v1',
  predicate: {
    buildDefinition: {
      buildType: 'https://node-operator.example/release-bundle/v1',
      externalParameters: { bundle_format: 'deterministic-posix-tar-v1' },
      resolvedDependencies: [{ uri: 'git+node-operator', digest: { gitCommit: revision } }],
    },
    runDetails: { builder: { id: 'local://node-operator/scripts/ci/build-release-bundle.sh' } },
  },
};
fs.writeFileSync(outputManifest, `${JSON.stringify(manifest, null, 2)}\n`);
fs.writeFileSync(provenance, `${JSON.stringify(provenanceInput, null, 2)}\n`);
NODE

printf 'built %s\n' "$artifact_digest"
