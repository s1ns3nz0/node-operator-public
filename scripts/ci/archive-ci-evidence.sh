#!/usr/bin/env bash
# Purpose: Canonicalize, sign, archive, and read back exact-head CI evidence.
# Inputs: EVIDENCE_DIRECTORY SUBJECT_SHA WORKFLOW_RUN_ID OUTPUT_DIRECTORY and CI_EVIDENCE_ARCHIVE_BUCKET.
# Outputs: A verified, signed, allowlisted evidence archive under the dedicated S3 ci/ prefix.
set -euo pipefail
umask 077

readonly allowed_members=(evidence.json decision.json cache-context.json baseline-summary.json)

reject() {
  printf 'CI evidence archive rejected: %s\n' "$1" >&2
  exit 65
}

regular_file() {
  [ -f "$1" ] && [ ! -L "$1" ]
}

[ "$#" -eq 4 ] || { printf 'usage: %s EVIDENCE_DIRECTORY SUBJECT_SHA WORKFLOW_RUN_ID OUTPUT_DIRECTORY\n' "$0" >&2; exit 64; }
evidence_directory="$1"
subject_sha="$2"
workflow_run_id="$3"
output_directory="$4"

[[ "$subject_sha" =~ ^[a-f0-9]{40}$ ]] || { printf 'subject SHA must be 40 lowercase hexadecimal characters\n' >&2; exit 64; }
[[ "$workflow_run_id" =~ ^[1-9][0-9]*$ ]] || { printf 'workflow run ID must be numeric\n' >&2; exit 64; }
[[ "$evidence_directory" = /* && "$output_directory" = /* ]] || { printf 'evidence and output directories must be absolute\n' >&2; exit 64; }
: "${CI_EVIDENCE_ARCHIVE_BUCKET:?CI_EVIDENCE_ARCHIVE_BUCKET is required}"

[ -d "$evidence_directory" ] && [ ! -L "$evidence_directory" ] || reject 'evidence directory must be a non-symlink directory'
output_parent="$(dirname "$output_directory")"
[ -d "$output_parent" ] && [ ! -L "$output_parent" ] || reject 'output parent must be a non-symlink directory'
[ ! -e "$output_directory" ] && [ ! -L "$output_directory" ] || reject 'output directory must be new'

for name in "${allowed_members[@]}"; do
  path="$evidence_directory/$name"
  case "$name" in
    evidence.json|decision.json)
      regular_file "$path" || reject "required evidence member is missing or unsafe: $name"
      ;;
    *)
      if [ -e "$path" ] || [ -L "$path" ]; then
        regular_file "$path" || reject "optional evidence member is unsafe: $name"
      fi
      ;;
  esac
done

python3 - "$evidence_directory/evidence.json" "$evidence_directory/decision.json" "$subject_sha" <<'PY'
import json
import sys

def load(path):
    with open(path, encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise SystemExit("evidence JSON must be an object")
    return value

evidence = load(sys.argv[1])
decision = load(sys.argv[2])
if evidence.get("subject", {}).get("commit_sha") != sys.argv[3]:
    raise SystemExit("evidence subject does not match requested SHA")
summary = decision.get("summary")
if (
    not isinstance(summary, dict)
    or type(summary.get("block")) is not int
    or type(summary.get("require_approval")) is not int
    or summary["block"] != 0
    or summary["require_approval"] != 0
):
    raise SystemExit("decision does not permit archival")
if not isinstance(decision.get("violations"), list):
    raise SystemExit("decision violations must be an array")
PY

scratch="$(mktemp -d)"
readback="$(mktemp -d)"
output_owned=0
cleanup() {
  rm -rf -- "$scratch" "$readback"
  if [ "$output_owned" -eq 1 ]; then
    rm -rf -- "$output_directory"
  fi
}
trap cleanup EXIT

mkdir -m 0700 "$output_directory"
output_owned=1

for name in "${allowed_members[@]}"; do
  if [ -e "$evidence_directory/$name" ] || [ -L "$evidence_directory/$name" ]; then
    regular_file "$evidence_directory/$name" || reject "source evidence member became unsafe: $name"
    cp -p "$evidence_directory/$name" "$output_directory/$name"
    regular_file "$output_directory/$name" || reject "copied evidence member is unsafe: $name"
  fi
done

python3 - "$output_directory" "$subject_sha" "$workflow_run_id" > "$output_directory/manifest.json" <<'PY'
import hashlib
import json
import os
import pathlib
import stat
import sys

root = pathlib.Path(sys.argv[1])
allowed = ("evidence.json", "decision.json", "cache-context.json", "baseline-summary.json")
items = []
for name in allowed:
    path = root / name
    if not path.exists():
        continue
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise SystemExit(f"unsafe evidence member: {name}")
    items.append({"name": name, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
if not {"evidence.json", "decision.json"} <= {item["name"] for item in items}:
    raise SystemExit("required members missing from manifest")
print(json.dumps({"schema_version": 1, "subject_sha": sys.argv[2], "workflow_run_id": int(sys.argv[3]), "members": items}, sort_keys=True, separators=(",", ":")))
PY
regular_file "$output_directory/manifest.json" || reject 'manifest is unsafe'

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
"$root/scripts/ci/install-validator-signing-fence-release-tools.sh" "$scratch/cosign-tools"
export PATH="$scratch/cosign-tools:$PATH"
cosign sign-blob --yes --bundle "$output_directory/manifest.sigstore.json" "$output_directory/manifest.json"
regular_file "$output_directory/manifest.sigstore.json" || reject 'signature bundle is unsafe'

identity="${COSIGN_CERTIFICATE_IDENTITY:-https://github.com/s1ns3nz0/node-operator/.github/workflows/evidence-archive.yml@refs/heads/main}"
verify_manifest() {
  cosign verify-blob --bundle "$1" --certificate-identity "$identity" \
    --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
    --certificate-github-workflow-repository 's1ns3nz0/node-operator' \
    --certificate-github-workflow-ref 'refs/heads/main' --certificate-github-workflow-trigger workflow_run \
    "$2" >/dev/null
}
verify_manifest "$output_directory/manifest.sigstore.json" "$output_directory/manifest.json"

prefix="ci/$subject_sha/$workflow_run_id"
python3 - "$output_directory/manifest.json" "$subject_sha" "$workflow_run_id" > "$scratch/data-members" <<'PY'
import json
import re
import sys

allowed = {"evidence.json", "decision.json", "cache-context.json", "baseline-summary.json"}
with open(sys.argv[1], encoding="utf-8") as handle:
    manifest = json.load(handle)
if set(manifest) != {"schema_version", "subject_sha", "workflow_run_id", "members"}:
    raise SystemExit("manifest has an unexpected shape")
if manifest["schema_version"] != 1 or manifest["subject_sha"] != sys.argv[2] or manifest["workflow_run_id"] != int(sys.argv[3]):
    raise SystemExit("manifest subject or run binding is invalid")
members = manifest["members"]
if not isinstance(members, list) or not members:
    raise SystemExit("manifest members are invalid")
seen = set()
for item in members:
    if not isinstance(item, dict) or set(item) != {"name", "sha256"}:
        raise SystemExit("manifest member shape is invalid")
    name, digest = item["name"], item["sha256"]
    if name not in allowed or name in seen or not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise SystemExit("manifest member is not allowlisted")
    seen.add(name)
if not {"evidence.json", "decision.json"} <= seen:
    raise SystemExit("manifest lacks required evidence members")
print(*[item["name"] for item in members], sep="\n")
PY
data_members=()
while IFS= read -r name; do
  [ -n "$name" ] || reject 'manifest emitted an empty member name'
  data_members+=("$name")
done < "$scratch/data-members"

for name in "${data_members[@]}" manifest.json manifest.sigstore.json; do
  regular_file "$output_directory/$name" || reject "archive member is unsafe: $name"
  aws s3 cp "$output_directory/$name" "s3://$CI_EVIDENCE_ARCHIVE_BUCKET/$prefix/$name" --only-show-errors
done

# Retrieve precisely the uploaded manifest, bundle, and allowlisted members into a
# separate private directory.  A HeadObject cannot establish byte-level integrity.
for name in manifest.json manifest.sigstore.json; do
  aws s3 cp "s3://$CI_EVIDENCE_ARCHIVE_BUCKET/$prefix/$name" "$readback/$name" --only-show-errors
  regular_file "$readback/$name" || reject "retrieved archive member is unsafe: $name"
done
verify_manifest "$readback/manifest.sigstore.json" "$readback/manifest.json"
# Require the exact signed manifest we uploaded, not merely another valid
# manifest for the same subject and run.
cmp -s "$output_directory/manifest.json" "$readback/manifest.json" || reject 'retrieved manifest differs from uploaded manifest'

for name in "${data_members[@]}"; do
  aws s3 cp "s3://$CI_EVIDENCE_ARCHIVE_BUCKET/$prefix/$name" "$readback/$name" --only-show-errors
  regular_file "$readback/$name" || reject "retrieved evidence member is unsafe: $name"
done

python3 - "$readback" "$output_directory/manifest.json" "$subject_sha" "$workflow_run_id" <<'PY'
import hashlib
import json
import pathlib
import re
import stat
import sys

root = pathlib.Path(sys.argv[1])
allowed = {"evidence.json", "decision.json", "cache-context.json", "baseline-summary.json"}
with open(sys.argv[2], encoding="utf-8") as handle:
    manifest = json.load(handle)
if manifest.get("subject_sha") != sys.argv[3] or manifest.get("workflow_run_id") != int(sys.argv[4]):
    raise SystemExit("retrieved manifest binding changed")
for item in manifest["members"]:
    name, expected = item["name"], item["sha256"]
    if name not in allowed or not isinstance(expected, str) or not re.fullmatch(r"[0-9a-f]{64}", expected):
        raise SystemExit("retrieved member is not allowlisted")
    path = root / name
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise SystemExit(f"retrieved member is unsafe: {name}")
    if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
        raise SystemExit(f"retrieved member hash mismatch: {name}")
PY

printf 'PASS: Cosign-verified CI evidence was archived and read back from s3://%s/%s/\n' "$CI_EVIDENCE_ARCHIVE_BUCKET" "$prefix"
