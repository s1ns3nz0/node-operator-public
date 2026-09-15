#!/usr/bin/env bash
# Check objective: Scan a release SBOM and bind a validated vulnerability summary to its artifact digest.
# Purpose: Scan one release SBOM and produce a digest-bound vulnerability summary with a valid scanner database.
# Inputs: SBOM JSON, summary destination, and locally installed grype/jq/shasum.
# Outputs: Summary JSON with findings counts, digest binding, database metadata, and pass/block status.
# Side effects: Local vulnerability database use and temporary/output file writes; no release publication.
set -euo pipefail

if [ "$#" -ne 2 ]; then
  printf 'usage: %s SBOM_JSON SUMMARY_JSON\n' "$0" >&2
  exit 64
fi

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$script_dir/lib/common.sh"
sbom="$1"
summary="$2"
require_command grype
require_command jq
require_command shasum
require_file "$sbom"

artifact_digest="$(jq -er '.metadata.component.version | select(test("^sha256:[0-9a-f]{64}$"))' "$sbom")"
sbom_sha256="$(shasum -a 256 "$sbom" | awk '{print $1}')"
temporary_directory="$(mktemp -d)"
trap 'rm -rf "$temporary_directory"' EXIT
raw="$temporary_directory/grype.json"

GRYPE_CHECK_FOR_APP_UPDATE=false grype "sbom:$sbom" --output json --file "$raw"
jq -e '
  (.matches | type == "array") and
  (.descriptor.name == "grype") and
  (.descriptor.version | type == "string" and length > 0) and
  (.descriptor.db.status.built | type == "string" and length > 0) and
  (.descriptor.db.status.valid == true) and
  all(.matches[]; (.vulnerability | type == "object") and (.vulnerability.severity | type == "string" and length > 0))
' "$raw" >/dev/null
mkdir -p "$(dirname "$summary")"
jq -n \
  --arg artifact_digest "$artifact_digest" \
  --arg sbom_sha256 "$sbom_sha256" \
  --arg scanned_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --slurpfile scan "$raw" '
    def count($severity):
      [$scan[0].matches[]?.vulnerability.severity? | select(type == "string") | ascii_downcase | select(. == $severity)] | length;
    {schema_version:"v1",tool:"grype",scanner:{version:$scan[0].descriptor.version,database_built:$scan[0].descriptor.db.status.built,database_schema_version:($scan[0].descriptor.db.status.schemaVersion | tostring)},artifact_digest:$artifact_digest,sbom_sha256:$sbom_sha256,scanned_at:$scanned_at,
     findings:{critical:count("critical"),high:count("high"),medium:count("medium"),low:count("low"),unknown:([$scan[0].matches[]?.vulnerability.severity? | select(type != "string" or (ascii_downcase | IN("critical","high","medium","low") | not))] | length)}} |
    . + {status:(if .findings.critical == 0 and .findings.high == 0 and .findings.unknown == 0 then "passed" else "blocked" end)}
  ' > "$summary"
