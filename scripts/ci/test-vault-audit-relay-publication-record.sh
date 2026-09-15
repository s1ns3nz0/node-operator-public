#!/usr/bin/env bash
# Check objective: Validate Vault audit relay publication records.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
publisher="$root/scripts/release/publish-vault-audit-relay.sh"
indexer="$root/scripts/release/create-installer-artifact-index.py"
workspace="$(mktemp -d)"
trap 'rm -rf "$workspace"' EXIT
fail() { printf 'FAIL relay publication record: %s\n' "$*" >&2; exit 1; }

# The record write must remain after every verification command; a failed
# verification exits under set -e before this suffix becomes reachable.
record_line="$(grep -n 'record="\$evidence/vault-audit-relay-publication-record.json"' "$publisher" | cut -d: -f1)"
scan_line="$(grep -n 'verify-release-scan-attestation.sh' "$publisher" | tail -1 | cut -d: -f1)"
[ "$record_line" -gt "$scan_line" ] || fail 'record is emitted before scan attestation verification'
grep -F 'cosign verify-attestation --type slsaprovenance1' "$publisher" >/dev/null || fail 'provenance verification missing'
grep -F 'cosign verify-attestation --type cyclonedx' "$publisher" >/dev/null || fail 'SBOM verification missing'
grep -F 'ln "$record_tmp" "$record"' "$publisher" >/dev/null || fail 'record publication is not atomic no-overwrite'
grep -F 'DEPLOYMENT_NAME="${DEPLOYMENT_NAME:-node-operator}"' "$publisher" >/dev/null || fail 'legacy relay deployment default is missing'
grep -F 'repository="${DEPLOYMENT_NAME}-baseline-vault-audit-relay"' "$publisher" >/dev/null || fail 'relay repository is not deployment-scoped'
if grep -Fq 'repository=node-operator-baseline-vault-audit-relay' "$publisher"; then fail 'relay repository remains globally hardcoded'; fi

# Execute the publisher's real post-verification suffix with prior verification
# represented by the harness entrypoint. This avoids Docker/AWS while proving
# emitted (not hand-built) JSON is accepted by the real index parser.
suffix="$workspace/publisher-suffix.sh"
awk '/^record="\$evidence\/vault-audit-relay-publication-record.json"/ {on=1} on' "$publisher" > "$suffix"
evidence="$workspace/evidence"; mkdir "$evidence"
export evidence GITHUB_SHA="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" GITHUB_RUN_ID=123 \
  subject="example.invalid/relay@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" \
  digest="sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" \
  input_sha="cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc" \
  GITHUB_STEP_SUMMARY="$workspace/summary"
bash "$suffix"
record="$evidence/vault-audit-relay-publication-record.json"
python3 - "$indexer" "$record" <<'PY'
import importlib.util, pathlib, sys
spec=importlib.util.spec_from_file_location("index",sys.argv[1]); module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
value=module._record(pathlib.Path(sys.argv[2]),"vault-audit-relay","a"*40,"cosign-and-slsa")
assert value["verification"]["status"] == "passed"
PY
python3 - "$record" <<'PY'
import os, stat, sys
assert stat.S_IMODE(os.stat(sys.argv[1]).st_mode) == 0o600
PY
before="$(shasum -a 256 "$record" | awk '{print $1}')"
if bash "$suffix" >/dev/null 2>&1; then fail 'existing publisher record was overwritten'; fi
[ "$before" = "$(shasum -a 256 "$record" | awk '{print $1}')" ] || fail 'existing publisher record changed'
rm -f "$record"
input_sha=bad
if bash "$suffix" >/dev/null 2>&1; then fail 'invalid input hash emitted a record'; fi
[ ! -e "$record" ] || fail 'invalid input hash left a record'
printf 'PASS relay publication record is post-verification, atomic, and index-compatible.\n'
