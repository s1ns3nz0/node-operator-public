#!/usr/bin/env bash
# Check objective: Prove the release wrapper requires bounded publication records before registry access.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
wrapper="$root/scripts/release/build-release-bundle.sh"
workspace="$(mktemp -d)"
trap 'rm -rf "$workspace"' EXIT
log="$workspace/docker.log"
fail() { printf 'FAIL release publication record inputs: %s\n' "$*" >&2; exit 1; }

mkdir -p "$workspace/bin" "$workspace/runner" "$workspace/repository"
# shellcheck disable=SC2016 # The fake Docker program must receive these expansions literally.
printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' \
  'printf "%s\\n" "$*" >> "$FAKE_DOCKER_LOG"' \
  'case "$1" in' \
  '  login) cat >/dev/null ;;' \
  '  pull) ;;' \
  '  run)' \
  '    records_mount=""; output_mount=""; prysm_mount=""; fence_mount=""; has_records=false; has_output=false; previous=""' \
  '    for argument in "$@"; do' \
  '      if [ "$previous" = --volume ]; then case "$argument" in *:/publication-records:ro) records_mount="$argument" ;; *:/prysm-publication-record.json:ro) prysm_mount="$argument" ;; *:/fence-release-verification.json:ro) fence_mount="$argument" ;; *:/output/release) output_mount="$argument" ;; esac; fi' \
  '      [ "$argument" = --publication-records-dir ] && has_records=true; [ "$argument" = /output/release ] && has_output=true' \
  '      previous="$argument"' \
  '    done' \
  '    [ -n "$records_mount" ] && [ -n "$output_mount" ] || exit 91' \
  '    [ "$has_records" = true ] && [ "$has_output" = true ] || exit 92' \
  '    output="${output_mount%:/output/release}"; mkdir -p "$output"' \
  '    printf "%s\\n" fake-release-bundle > "$output/node-operator-release-bundle.tar"' \
  '    digest="sha256:$(sha256sum "$output/node-operator-release-bundle.tar" | cut -d " " -f 1)"' \
  '    printf "{\\\"metadata\\\":{\\\"component\\\":{\\\"version\\\":\\\"%s\\\"}}}\\n" "${FAKE_SBOM_DIGEST:-$digest}" > "$output/sbom.cyclonedx.json" ;;' \
  '  *) exit 93 ;;' \
  'esac' > "$workspace/bin/docker"
chmod +x "$workspace/bin/docker"

legacy_workspace="$workspace/legacy-repository"
git clone --quiet --no-local "$root" "$legacy_workspace"
python3 "$root/scripts/ci/reset-release-authorization-fixture.py" "$legacy_workspace"
git -C "$legacy_workspace" -c user.name=Fixture -c user.email=fixture@example.invalid -c commit.gpgsign=false commit --allow-empty -qm 'Legacy publication test fixture'
source_revision="$(git -C "$legacy_workspace" rev-parse HEAD)"
write_records() {
  local directory="$1" revision="$2" mode="${3:-valid}"
  python3 - "$directory" "$revision" "$mode" <<'PY'
import json
import sys
from pathlib import Path

directory, revision, mode = Path(sys.argv[1]), sys.argv[2], sys.argv[3]
for component, method, letter in (
    ("vault-bootstrap", "input-hash-and-registry-digest", "a"),
    ("vault-audit-relay", "cosign-and-slsa", "b"),
    ("gitops-oci-mirror", "input-hash-and-registry-digest", "c"),
):
    digest = "sha256:" + letter * 64
    record = {
        "schema_version": 1, "component": component, "kind": "image",
        "release_revision": revision, "build_revision": revision,
        "third_party_source_revision": None,
        "image_ref": f"ghcr.io/example/{component}@{digest}",
        "manifest_digest": digest, "input_sha256": letter * 64,
        "publication": {"workflow": "image-publish.yml", "run_id": "1", "invocation": "test"},
        "verification": {"method": method, "status": "passed"},
    }
    if mode == "wrong-revision" and component == "vault-bootstrap":
        record["release_revision"] = "f" * 40
    if mode == "wrong-status" and component == "vault-audit-relay":
        record["verification"]["status"] = "failed"
    if mode == "wrong-schema" and component == "gitops-oci-mirror":
        record.pop("input_sha256")
    (directory / f"{component}-publication-record.json").write_text(json.dumps(record), encoding="utf-8")
PY
}

valid_records="$workspace/records"
mkdir "$valid_records"
write_records "$valid_records" "$source_revision"

invoke() {
  local workspace_root="${TEST_WORKSPACE:-$legacy_workspace}"
  PATH="$workspace/bin:$PATH" FAKE_DOCKER_LOG="$log" REGISTRY_TOKEN=token REGISTRY_USERNAME=actor \
    RELEASE_BUILD_IMAGE=ghcr.io/example/release-build APPROVED_ARTIFACT_DIGEST="${APPROVED_ARTIFACT_DIGEST:-}" \
    GITHUB_WORKSPACE="$workspace_root" RUNNER_TEMP="$workspace/runner" PUBLICATION_RECORDS_DIR="${PUBLICATION_RECORDS_DIR:-}" FENCE_PUBLICATION_RECORD="${FENCE_PUBLICATION_RECORD:-}" CLIENT_CHART_PUBLICATION_RECORDS="${CLIENT_CHART_PUBLICATION_RECORDS:-}" SIGNER_PROBE_PUBLICATION_RECORD="${SIGNER_PROBE_PUBLICATION_RECORD:-}" \
    bash "$wrapper"
}
assert_no_docker() { [ ! -s "$log" ] || fail "Docker was invoked for rejected $1"; }

: > "$log"
if PUBLICATION_RECORDS_DIR="$workspace/does-not-exist" invoke >/dev/null 2>&1; then fail 'missing directory succeeded'; fi
assert_no_docker 'missing directory'

missing_files="$workspace/missing-files"
mkdir "$missing_files"
cp "$valid_records/vault-bootstrap-publication-record.json" "$missing_files/"
: > "$log"
if PUBLICATION_RECORDS_DIR="$missing_files" invoke >/dev/null 2>&1; then fail 'missing files succeeded'; fi
assert_no_docker 'missing files'

symlink_records="$workspace/symlink-records"
mkdir "$symlink_records"
cp "$valid_records/vault-bootstrap-publication-record.json" "$symlink_records/"
cp "$valid_records/vault-audit-relay-publication-record.json" "$symlink_records/"
ln -s "$valid_records/gitops-oci-mirror-publication-record.json" "$symlink_records/gitops-oci-mirror-publication-record.json"
: > "$log"
if PUBLICATION_RECORDS_DIR="$symlink_records" invoke >/dev/null 2>&1; then fail 'symlink record succeeded'; fi
assert_no_docker 'symlink record'

for mode in wrong-revision wrong-status wrong-schema; do
  rejected_records="$workspace/$mode"
  mkdir "$rejected_records"
  write_records "$rejected_records" "$source_revision" "$mode"
  : > "$log"
  if PUBLICATION_RECORDS_DIR="$rejected_records" invoke >/dev/null 2>&1; then fail "$mode record succeeded"; fi
  assert_no_docker "$mode record"
done

bundle="$workspace/runner/release/node-operator-release-bundle.tar"
expected="sha256:$(printf '%s\n' fake-release-bundle | sha256sum | awk '{print $1}')"
: > "$log"
APPROVED_ARTIFACT_DIGEST="$expected" PUBLICATION_RECORDS_DIR="$valid_records" invoke
grep -F -- "--volume $valid_records:/publication-records:ro" "$log" >/dev/null || fail 'publication record mount was not read-only and fixed'
grep -F -- "--volume $workspace/runner/release:/output/release" "$log" >/dev/null || fail 'release output mount was not narrowly scoped'
if grep -F -- "--volume $workspace/runner:/output" "$log" >/dev/null; then fail 'release output mount overlaps frozen input parent'; fi
grep -F -- '--publication-records-dir /publication-records /output/release' "$log" >/dev/null || fail 'CI builder did not receive fixed publication record arguments'
[ -f "$bundle" ] || fail 'positive wrapper invocation did not receive a bundle'

# The workflow exports an empty Fence path for legacy releases.  That explicit
# environment value must retain the no-Fence-authorization behavior.
rm -rf "$workspace/runner/release"
: > "$log"
APPROVED_ARTIFACT_DIGEST="$expected" PUBLICATION_RECORDS_DIR="$valid_records" FENCE_PUBLICATION_RECORD='' invoke
if grep -Fq '/fence-release-verification.json:ro' "$log"; then fail 'legacy release mounted an absent Fence record'; fi

: > "$log"
if APPROVED_ARTIFACT_DIGEST="$expected" PUBLICATION_RECORDS_DIR="$valid_records" FENCE_PUBLICATION_RECORD="$workspace/absent-fence-record.json" invoke >/dev/null 2>&1; then fail 'legacy release accepted an unsolicited Fence record'; fi
assert_no_docker 'unsolicited legacy Fence record'

overlap_records="$workspace/runner/release/records"
mkdir -p "$overlap_records"
write_records "$overlap_records" "$source_revision"
: > "$log"
if APPROVED_ARTIFACT_DIGEST="$expected" PUBLICATION_RECORDS_DIR="$overlap_records" invoke >/dev/null 2>&1; then fail 'release accepted publication records under writable output'; fi
assert_no_docker 'writable output overlap'

rm -rf "$workspace/runner/release"
: > "$log"
if APPROVED_ARTIFACT_DIGEST="sha256:$(printf '%064d' 0)" PUBLICATION_RECORDS_DIR="$valid_records" invoke >/dev/null 2>&1; then fail 'digest mismatch succeeded'; fi
grep -F 'login ghcr.io' "$log" >/dev/null || fail 'digest mismatch did not reach the unchanged wrapper verification path'
[ -f "$bundle" ] || fail 'digest mismatch did not run the fake builder'

# An authorized release accepts only the exact frozen candidate record.  The
# wrapper performs this source/hash/context validation before any registry call
# and mounts the same immutable file for the in-container bundle builder.
prysm_workspace="$workspace/repository"
git clone --quiet --no-local "$root" "$prysm_workspace"
python3 "$root/scripts/ci/reset-release-authorization-fixture.py" "$prysm_workspace"
git -C "$prysm_workspace" config user.email test@example.invalid
git -C "$prysm_workspace" config user.name 'release wrapper test'
cp "$root/scripts/release/prysm_publication_record.py" "$prysm_workspace/scripts/release/"
cp "$root/scripts/release/prysm_release_authorization.py" "$prysm_workspace/scripts/release/"
printf '%s\n' 'synthetic Prysm candidate revision' > "$prysm_workspace/.release-wrapper-test-prysm-candidate"
git -C "$prysm_workspace" add scripts/release/prysm_publication_record.py scripts/release/prysm_release_authorization.py .release-wrapper-test-prysm-candidate
git -C "$prysm_workspace" commit --quiet -m 'Prysm candidate'
candidate_revision="$(git -C "$prysm_workspace" rev-parse HEAD)"
prysm_record="$workspace/prysm-mtls-publication-record.json"
python3 - "$root" "$prysm_workspace" "$candidate_revision" "$prysm_record" <<'PY'
import hashlib, json, sys
from pathlib import Path
root, source, candidate, record_path = map(Path, sys.argv[1:])
sys.path.insert(0, str(root / "scripts/release"))
import prysm_publication_record as publication
digest = "sha256:" + "d" * 64
record = publication.create_record(
    source, release_revision=str(candidate), build_revision=str(candidate),
    input_sha256=publication.build_input_sha256(source), run_id="42",
    aws_account_id="123456789012", aws_region="ap-northeast-2", deployment_name="node-operator",
    repository="node-operator-baseline-validator-prysm",
    image_ref=f"123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/node-operator-baseline-validator-prysm@{digest}",
    manifest_digest=digest,
)
raw = json.dumps(record, sort_keys=True).encode() + b"\n"
record_path.write_bytes(raw)
auth = {
    "schema_version": 1, "candidate_revision": str(candidate), "record_sha256": hashlib.sha256(raw).hexdigest(),
    "publication": {"repository": "s1ns3nz0/node-operator", "workflow": "image-publish.yml", "run_id": "42", "artifact_id": "123"},
    "target": {"image_ref": record["target"]["image_ref"], "manifest_digest": record["target"]["manifest_digest"], "input_sha256": record["input_sha256"]},
    "approvals": {"stage_approved": True, "activation_approved": False},
}
path = source / "release/prysm-publication-authorization.json"
path.write_text(json.dumps(auth, sort_keys=True) + "\n")
PY
git -C "$prysm_workspace" add release/prysm-publication-authorization.json
git -C "$prysm_workspace" commit --quiet -m 'Authorize Prysm candidate'
prysm_revision="$(git -C "$prysm_workspace" rev-parse HEAD)"
prysm_records="$workspace/prysm-records"
mkdir "$prysm_records"
write_records "$prysm_records" "$prysm_revision"

rm -rf "$workspace/runner/release"
: > "$log"
APPROVED_ARTIFACT_DIGEST="$expected" PUBLICATION_RECORDS_DIR="$prysm_records" \
  TEST_WORKSPACE="$prysm_workspace" PRYSM_PUBLICATION_RECORD="$prysm_record" invoke
grep -F -- "--volume $prysm_record:/prysm-publication-record.json:ro" "$log" >/dev/null || fail 'frozen Prysm record was not mounted read-only'
grep -F -- '--prysm-publication-record /prysm-publication-record.json /output/release' "$log" >/dev/null || fail 'CI builder did not receive frozen Prysm record argument'

: > "$log"
if APPROVED_ARTIFACT_DIGEST="$expected" PUBLICATION_RECORDS_DIR="$prysm_records" TEST_WORKSPACE="$prysm_workspace" invoke >/dev/null 2>&1; then fail 'authorized release accepted missing frozen Prysm record'; fi
assert_no_docker 'missing frozen Prysm record'

tampered_prysm_record="$workspace/tampered-prysm-record.json"
cp "$prysm_record" "$tampered_prysm_record"
python3 - "$tampered_prysm_record" <<'PY'
import json, sys
path = sys.argv[1]
value = json.load(open(path))
value["publication"]["run_id"] = "43"
open(path, "w").write(json.dumps(value, sort_keys=True) + "\n")
PY
: > "$log"
if APPROVED_ARTIFACT_DIGEST="$expected" PUBLICATION_RECORDS_DIR="$prysm_records" TEST_WORKSPACE="$prysm_workspace" PRYSM_PUBLICATION_RECORD="$tampered_prysm_record" invoke >/dev/null 2>&1; then fail 'authorized release accepted tampered frozen Prysm record'; fi
assert_no_docker 'tampered frozen Prysm record'

# Fence follows the same caller-supplied, authorization-bound handoff.  Check
# the real canonical validator before Docker, then the narrow immutable mount.
fence_workspace="$workspace/fence-repository"
git clone --quiet --no-local "$root" "$fence_workspace"
python3 "$root/scripts/ci/reset-release-authorization-fixture.py" "$fence_workspace"
git -C "$fence_workspace" config user.email test@example.invalid
git -C "$fence_workspace" config user.name 'release wrapper test'
cp "$root/scripts/release/fence_build_inputs.py" "$root/scripts/release/fence_release_authorization.py" "$fence_workspace/scripts/release/"
printf '%s\n' 'synthetic Fence candidate revision' > "$fence_workspace/.release-wrapper-test-fence-candidate"
git -C "$fence_workspace" add scripts/release/fence_build_inputs.py scripts/release/fence_release_authorization.py .release-wrapper-test-fence-candidate
git -C "$fence_workspace" commit --quiet -m 'Fence candidate helpers'
fence_candidate="$(git -C "$fence_workspace" rev-parse HEAD)"
fence_record="$workspace/fence-release-verification.json"
python3 - "$root" "$fence_workspace" "$fence_candidate" "$fence_record" <<'PY'
import hashlib, json, sys
from pathlib import Path
root, source, candidate, record_path = map(Path, sys.argv[1:])
sys.path.insert(0, str(root / "scripts/release"))
from fence_build_inputs import fence_input_sha256
from fence_release_authorization import IDENTITY, ISSUER
digest = "sha256:" + "e" * 64
record = {"schema_version": 1, "event_type": "validator-signing-fence-release-verification", "collected_at_utc": "2026-09-13T00:00:00Z", "image": f"123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/node-operator-baseline-validator-fence@{digest}", "artifact_digest": digest, "source_revision": str(candidate), "input_sha256": fence_input_sha256(source), "result": "PASS", "cryptographic_verification": {"tool": "cosign", "signature_count": 1, "identity": IDENTITY, "issuer": ISSUER, "slsa_provenance": True, "transparency_log_verified": True}, "sbom": {"tool": "syft", "format": "cyclonedx-json", "component_count": 1, "sha256": "a" * 64}, "vulnerability_scan": {"schema_version": "v1", "tool": "grype", "scanner": {"version": "1", "database_built": "2026-09-13T00:00:00Z", "database_schema_version": "1"}, "artifact_digest": digest, "sbom_sha256": "a" * 64, "scanned_at": "2026-09-13T00:00:00Z", "findings": {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0}, "status": "passed"}}
raw = json.dumps(record, sort_keys=True).encode() + b"\n"; record_path.write_bytes(raw)
auth = {"schema_version": 1, "candidate_revision": str(candidate), "record_sha256": hashlib.sha256(raw).hexdigest(), "publication": {"repository": "s1ns3nz0/node-operator", "workflow": "image-publish.yml", "run_id": "42", "artifact_id": "123"}, "target": {"image_ref": record["image"], "manifest_digest": digest, "input_sha256": record["input_sha256"]}, "approvals": {"stage_approved": True, "activation_approved": False}}
(source / "release/fence-publication-authorization.json").write_text(json.dumps(auth, sort_keys=True) + "\n")
PY
git -C "$fence_workspace" add release/fence-publication-authorization.json
git -C "$fence_workspace" commit --quiet -m 'Authorize Fence candidate'
fence_revision="$(git -C "$fence_workspace" rev-parse HEAD)"
fence_records="$workspace/fence-records"; mkdir "$fence_records"; write_records "$fence_records" "$fence_revision"
rm -rf "$workspace/runner/release"
: > "$log"
APPROVED_ARTIFACT_DIGEST="$expected" PUBLICATION_RECORDS_DIR="$fence_records" TEST_WORKSPACE="$fence_workspace" FENCE_PUBLICATION_RECORD="$fence_record" invoke
grep -F -- "--volume $fence_record:/fence-release-verification.json:ro" "$log" >/dev/null || fail 'frozen Fence record was not mounted read-only'
grep -F -- '--fence-publication-record /fence-release-verification.json /output/release' "$log" >/dev/null || fail 'CI builder did not receive frozen Fence record argument'

: > "$log"
if APPROVED_ARTIFACT_DIGEST="$expected" PUBLICATION_RECORDS_DIR="$fence_records" TEST_WORKSPACE="$fence_workspace" invoke >/dev/null 2>&1; then fail 'authorized release accepted missing frozen Fence record'; fi
assert_no_docker 'missing frozen Fence record'

tampered_fence_record="$workspace/tampered-fence-record.json"
cp "$fence_record" "$tampered_fence_record"
python3 - "$tampered_fence_record" <<'PY'
import json, sys
path = sys.argv[1]; value = json.load(open(path)); value["result"] = "FAIL"; open(path, "w").write(json.dumps(value, sort_keys=True) + "\n")
PY
: > "$log"
if APPROVED_ARTIFACT_DIGEST="$expected" PUBLICATION_RECORDS_DIR="$fence_records" TEST_WORKSPACE="$fence_workspace" FENCE_PUBLICATION_RECORD="$tampered_fence_record" invoke >/dev/null 2>&1; then fail 'authorized release accepted tampered frozen Fence record'; fi
assert_no_docker 'tampered frozen Fence record'

chart_workspace="$workspace/chart-repository"; git clone --quiet --no-local "$root" "$chart_workspace"
python3 "$root/scripts/ci/reset-release-authorization-fixture.py" "$chart_workspace"
git -C "$chart_workspace" config user.email test@example.invalid; git -C "$chart_workspace" config user.name 'release wrapper test'
cp "$root/scripts/release/client_chart_release_authorization.py" "$chart_workspace/scripts/release/"
printf '%s\n' 'synthetic chart candidate revision' > "$chart_workspace/.release-wrapper-test-chart-candidate"
git -C "$chart_workspace" add scripts/release/client_chart_release_authorization.py .release-wrapper-test-chart-candidate; git -C "$chart_workspace" commit --quiet -m 'chart helper'
chart_records="$workspace/chart-records"; mkdir "$chart_records"
python3 - "$root" "$chart_workspace" "$chart_records" <<'PY'
import base64, hashlib, json, sys
from pathlib import Path
root, source, directory = map(Path, sys.argv[1:]); sys.path.insert(0, str(root / 'scripts/release'))
import client_chart_release_authorization as c
revision = 'a' * 40; digest='sha256:'+'a'*64; archive='sha256:'+'b'*64
p={'buildDefinition':{'buildType':'https://node-operator.example/gitops-chart/v1','resolvedDependencies':[{'uri':'git+https://github.com/s1ns3nz0/node-operator-gitops','digest':{'gitCommit':revision}}]},'runDetails':{'builder':{'id':c.BUILDER}}}
s={'_type':'https://in-toto.io/Statement/v1','subject':[{'name':'123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/node-operator-baseline-gitops-client/node-operator-client','digest':{'sha256':digest[7:]}}],'predicateType':'https://slsa.dev/provenance/v1','predicate':p}
v={c.NAMES[0]:{'schema_version':'v1','oci_digest':digest,'chart_archive_digest':archive,'chart_version':'0.1.37'},c.NAMES[1]:{'bomFormat':'CycloneDX','metadata':{'component':{'name':'node-operator-client-0.1.37.tgz','version':archive},'tools':{'components':[{'name':'syft'}]}}},c.NAMES[2]:{'matches':[],'descriptor':{'name':'grype','version':'1','db':{'status':{'valid':True}},'configuration':{'ignore':[],'exclude':[],'only-fixed':False,'only-notfixed':False,'show-suppressed':True}},'source':{'type':'file','target':'node-operator-client-0.1.37.tgz'}},c.NAMES[3]:p,c.NAMES[4]:{'payloadType':'application/vnd.in-toto+json','payload':base64.b64encode(json.dumps(s).encode()).decode(),'signatures':[{'sig':'x'}]}}
raw={n:json.dumps(x,sort_keys=True).encode() for n,x in v.items()}
for n,b in raw.items():(directory/n).write_bytes(b)
auth={'schema_version':1,'source_revision':revision,'publication':{'repository':c.REPOSITORY,'workflow':c.WORKFLOW,'run_id':'1','artifact_id':'2','artifact_name':'gitops-chart-evidence-test','run_number':'37'},'target':{'image_ref':f'123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/node-operator-baseline-gitops-client/node-operator-client@{digest}','manifest_digest':digest,'chart_archive_digest':archive,'chart_version':'0.1.37'},'evidence_sha256':{n:hashlib.sha256(b).hexdigest() for n,b in raw.items()},'approvals':{'stage_approved':True,'activation_approved':False}}
(source/'release/client-chart-publication-authorization.json').write_text(json.dumps(auth,sort_keys=True))
PY
git -C "$chart_workspace" add release/client-chart-publication-authorization.json; git -C "$chart_workspace" commit --quiet -m 'chart auth'
chart_revision="$(git -C "$chart_workspace" rev-parse HEAD)"; chart_vault_records="$workspace/chart-vault-records"; mkdir "$chart_vault_records"; write_records "$chart_vault_records" "$chart_revision"
: > "$log"; APPROVED_ARTIFACT_DIGEST="$expected" PUBLICATION_RECORDS_DIR="$chart_vault_records" TEST_WORKSPACE="$chart_workspace" CLIENT_CHART_PUBLICATION_RECORDS="$chart_records" invoke
grep -F -- "--volume $chart_records:/client-chart-publication-records:ro" "$log" >/dev/null || fail 'frozen client chart records were not mounted read-only'
grep -F -- '--client-chart-publication-records /client-chart-publication-records /output/release' "$log" >/dev/null || fail 'CI builder did not receive client chart records'
: > "$log"; if APPROVED_ARTIFACT_DIGEST="$expected" PUBLICATION_RECORDS_DIR="$chart_vault_records" TEST_WORKSPACE="$chart_workspace" invoke >/dev/null 2>&1; then fail 'authorized release accepted missing client chart records'; fi; assert_no_docker 'missing client chart records'
tampered_chart="$workspace/tampered-chart-records"; cp -R "$chart_records" "$tampered_chart"; printf '{}' > "$tampered_chart/gitops-chart-subject.json"
: > "$log"; if APPROVED_ARTIFACT_DIGEST="$expected" PUBLICATION_RECORDS_DIR="$chart_vault_records" TEST_WORKSPACE="$chart_workspace" CLIENT_CHART_PUBLICATION_RECORDS="$tampered_chart" invoke >/dev/null 2>&1; then fail 'authorized release accepted tampered client chart records'; fi; assert_no_docker 'tampered client chart records'
overlap_chart="$workspace/runner/release/chart-records"; mkdir -p "$overlap_chart"; cp "$chart_records"/* "$overlap_chart/"
: > "$log"; if APPROVED_ARTIFACT_DIGEST="$expected" PUBLICATION_RECORDS_DIR="$chart_vault_records" TEST_WORKSPACE="$chart_workspace" CLIENT_CHART_PUBLICATION_RECORDS="$overlap_chart" invoke >/dev/null 2>&1; then fail 'authorized release accepted chart records under writable output'; fi; assert_no_docker 'client chart output overlap'
git -C "$chart_workspace" checkout --quiet HEAD~1
chart_legacy_revision="$(git -C "$chart_workspace" rev-parse HEAD)"
chart_legacy_records="$workspace/chart-legacy-vault-records"; mkdir "$chart_legacy_records"; write_records "$chart_legacy_records" "$chart_legacy_revision"
rm -rf "$workspace/runner/release"
: > "$log"; APPROVED_ARTIFACT_DIGEST="$expected" PUBLICATION_RECORDS_DIR="$chart_legacy_records" TEST_WORKSPACE="$chart_workspace" invoke
: > "$log"; orphan_output="$(APPROVED_ARTIFACT_DIGEST="$expected" PUBLICATION_RECORDS_DIR="$chart_legacy_records" TEST_WORKSPACE="$chart_workspace" CLIENT_CHART_PUBLICATION_RECORDS="$chart_records" invoke 2>&1 || true)"
if ! grep -Fq 'client chart publication records were supplied without a selected release authorization' <<<"$orphan_output"; then fail 'orphan client chart records did not reach the chart authorization gate'; fi
assert_no_docker 'orphan client chart records'

# Signer-probe follows the same no-fetch, caller-supplied handoff.  Its source
# context is independently checked before Docker and only the exact record is
# mounted into the builder.
signer_workspace="$workspace/signer-repository"; git clone --quiet --no-local "$root" "$signer_workspace"
python3 "$root/scripts/ci/reset-release-authorization-fixture.py" "$signer_workspace"
git -C "$signer_workspace" config user.email test@example.invalid; git -C "$signer_workspace" config user.name 'release wrapper test'
cp "$root/scripts/release/fence_build_inputs.py" "$root/scripts/release/signer_probe_build_inputs.py" "$root/scripts/release/signer_probe_publication_record.py" "$root/scripts/release/signer_probe_release_authorization.py" "$signer_workspace/scripts/release/"
printf '%s\n' 'synthetic signer candidate revision' > "$signer_workspace/.release-wrapper-test-signer-candidate"
git -C "$signer_workspace" add scripts/release .release-wrapper-test-signer-candidate; git -C "$signer_workspace" commit --quiet -m 'signer helpers'
signer_candidate="$(git -C "$signer_workspace" rev-parse HEAD)"; signer_record="$workspace/signer-probe-record.json"
python3 - "$signer_workspace" "$signer_candidate" "$signer_record" <<'PY'
import hashlib,json,sys
from pathlib import Path
source,candidate,out=map(Path,sys.argv[1:]); sys.path.insert(0,str(source/'scripts/release'))
from signer_probe_build_inputs import signer_probe_input_sha256
from signer_probe_publication_record import create_record
d='sha256:'+'f'*64; image='111111111111.dkr.ecr.ap-northeast-1.amazonaws.com/source-node-baseline-validator-signer-identity-probe@'+d
r=create_record(source,release_revision=str(candidate),build_revision=str(candidate),input_sha256=signer_probe_input_sha256(source),aws_account_id='111111111111',aws_region='ap-northeast-1',deployment_name='source-node',repository='source-node-baseline-validator-signer-identity-probe',image_ref=image,manifest_digest=d,run_id='42')
raw=json.dumps(r,sort_keys=True,separators=(',',':')).encode()+b'\n'; out.write_bytes(raw)
a={'schema_version':1,'candidate_revision':str(candidate),'record_sha256':hashlib.sha256(raw).hexdigest(),'publication':{'repository':'s1ns3nz0/node-operator','workflow':'image-publish.yml','run_id':'42','artifact_id':'123'},'target':{k:r[k] for k in ('image_ref','manifest_digest','input_sha256')},'approvals':{'stage_approved':True}}
(source/'release/signer-probe-publication-authorization.json').write_text(json.dumps(a))
PY
git -C "$signer_workspace" add release; git -C "$signer_workspace" commit --quiet -m 'signer authorization'; signer_revision="$(git -C "$signer_workspace" rev-parse HEAD)"
signer_records="$workspace/signer-records"; mkdir "$signer_records"; write_records "$signer_records" "$signer_revision"
rm -rf "$workspace/runner/release"; : > "$log"
APPROVED_ARTIFACT_DIGEST="$expected" PUBLICATION_RECORDS_DIR="$signer_records" TEST_WORKSPACE="$signer_workspace" SIGNER_PROBE_PUBLICATION_RECORD="$signer_record" invoke
grep -F -- "--volume $signer_record:/signer-probe-publication-record.json:ro" "$log" >/dev/null || fail 'signer record was not mounted read-only'
grep -F -- '--signer-probe-publication-record /signer-probe-publication-record.json' "$log" >/dev/null || fail 'builder did not receive signer record'
for mode in missing tampered symlink orphan overlap; do
  : > "$log"; cp "$signer_record" "$workspace/good-signer.json"; test_record="$signer_record"; test_workspace="$signer_workspace"
  case "$mode" in missing) test_record='';; tampered) printf ' ' >> "$test_record";; symlink) rm "$test_record"; ln -s "$workspace/good-signer.json" "$test_record";; orphan) rm "$test_workspace/release/signer-probe-publication-authorization.json";; overlap) test_record="$workspace/runner/release/signer.json"; mkdir -p "$(dirname "$test_record")"; cp "$workspace/good-signer.json" "$test_record";; esac
  if APPROVED_ARTIFACT_DIGEST="$expected" PUBLICATION_RECORDS_DIR="$signer_records" TEST_WORKSPACE="$test_workspace" SIGNER_PROBE_PUBLICATION_RECORD="$test_record" invoke >/dev/null 2>&1; then fail "signer $mode succeeded"; fi
  assert_no_docker "signer $mode"; rm -f "$signer_record"; cp "$workspace/good-signer.json" "$signer_record"
  if [ "$mode" = orphan ]; then git -C "$signer_workspace" checkout --quiet HEAD -- release/signer-probe-publication-authorization.json; fi
done

# Legacy bundle remains usable with no signer authorization or supplied record.
git -C "$signer_workspace" checkout --quiet HEAD~1; legacy_revision="$(git -C "$signer_workspace" rev-parse HEAD)"; legacy_records="$workspace/signer-legacy-records"; mkdir "$legacy_records"; write_records "$legacy_records" "$legacy_revision"
rm -rf "$workspace/runner/release"; : > "$log"; APPROVED_ARTIFACT_DIGEST="$expected" PUBLICATION_RECORDS_DIR="$legacy_records" TEST_WORKSPACE="$signer_workspace" SIGNER_PROBE_PUBLICATION_RECORD='' invoke
if grep -Fq '/signer-probe-publication-record.json:ro' "$log"; then fail 'legacy release mounted absent signer record'; fi

printf 'PASS release wrapper requires bounded publication-record inputs before registry access.\n'
