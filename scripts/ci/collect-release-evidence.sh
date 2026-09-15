#!/usr/bin/env bash
set -euo pipefail

# Convert release-tool reports into compact, artifact-safe envelopes. Raw SBOM,
# scan, signature, and provenance payloads are copied to a private temporary
# directory and are never written beneath OUTPUT_DIRECTORY.

if [ "$#" -lt 6 ] || [ "$#" -gt 7 ]; then
  printf 'usage: %s OUTPUT_DIRECTORY ARTIFACT_DIGEST POSTURE_JSON SBOM_JSON COSIGN_JSON PROVENANCE_JSON [GRYPE_JSON]\n' "$0" >&2
  exit 64
fi

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$script_dir/lib/common.sh"

output_directory="$1"
artifact_digest="$2"
posture_source="$3"
sbom_source="$4"
signature_source="$5"
provenance_source="$6"
scan_source="${7:-}"

[[ "$artifact_digest" =~ ^sha256:[0-9a-f]{64}$ ]] || { printf 'artifact digest must be sha256 followed by 64 lowercase hexadecimal characters\n' >&2; exit 64; }
require_command jq
require_file "$posture_source"
require_file "$sbom_source"
require_file "$signature_source"
require_file "$provenance_source"
if [ -n "$scan_source" ]; then
  require_file "$scan_source"
fi

umask 077
temporary_directory="$(mktemp -d)"
trap 'rm -rf "$temporary_directory"' EXIT
mkdir -p "$output_directory"

# Do not allow a source file to be read after its normalized form has started
# writing. This keeps all raw payload lifetimes contained by the temporary dir.
cp "$posture_source" "$temporary_directory/posture.json"
cp "$sbom_source" "$temporary_directory/sbom.json"
cp "$signature_source" "$temporary_directory/signature.json"
cp "$provenance_source" "$temporary_directory/provenance.json"
if [ -n "$scan_source" ]; then
  cp "$scan_source" "$temporary_directory/scan.json"
fi

require_json() {
  local name="$1" path="$2"
  jq -e . "$path" >/dev/null 2>&1 || { printf '%s is not valid JSON\n' "$name" >&2; exit 1; }
}

write_envelope() {
  local destination="$1" tool="$2" result_path="$3"
  jq -n \
    --arg tool "$tool" \
    --arg digest "$artifact_digest" \
    --arg collected_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --slurpfile result "$result_path" \
    '{schema_version:"v1", tool:$tool, artifact_digest:$digest, collected_at:$collected_at, result:$result[0]}' > "$destination"
}

collect_posture() {
  local source="$temporary_directory/posture.json" result="$temporary_directory/posture-result.json"
  require_json posture "$source"
  jq -e '
    (.scorecard_score | type == "number" and . >= 0 and . <= 10) and
    ([.branch_protection, .commit_signing, .workflow_pinning] | all(.[]; type == "boolean"))
  ' "$source" >/dev/null || { printf 'posture report is incomplete\n' >&2; exit 1; }
  jq -c '
    {
      scorecard_score,
      branch_protection,
      commit_signing,
      workflow_pinning,
      status: (if .branch_protection and .commit_signing and .workflow_pinning then "passed" else "failed" end)
    }
  ' "$source" > "$result"
  write_envelope "$output_directory/posture.json" posture "$result"
}

collect_sbom() {
  local source="$temporary_directory/sbom.json" result="$temporary_directory/sbom-result.json"
  require_json sbom "$source"
  jq -e --arg digest "$artifact_digest" '
    .bomFormat == "CycloneDX" and
    (.specVersion | type == "string" and test("^1(\\.|$)")) and
    (.components | type == "array") and
    (.metadata.component | type == "object") and
    (.metadata.component.version == $digest)
  ' "$source" >/dev/null || {
    if jq -e '.spdxVersion | type == "string"' "$source" >/dev/null 2>&1; then
      printf 'SPDX SBOM is unsupported: no verifiable artifact-digest binding is defined\n' >&2
    else
      printf 'SBOM must be CycloneDX v1 JSON with metadata.component.version equal to the artifact digest\n' >&2
    fi
    exit 1
  }
  jq -c --arg digest "$artifact_digest" '
    {status:"complete", format:"cyclonedx-json", component_count:(.components | length), artifact_digest:$digest}
  ' "$source" > "$result"
  write_envelope "$output_directory/sbom.json" syft "$result"
}

collect_signature() {
  local source="$temporary_directory/signature.json" result="$temporary_directory/signature-result.json"
  require_json cosign "$source"
  jq -e 'type == "array" and length > 0 and all(.[]; (.critical.image["docker-manifest-digest"] | type == "string" and test("^sha256:[0-9a-f]{64}$")) and (.optional.Subject | type == "string" and length > 0 and length <= 512) and (.optional.Issuer | type == "string" and length > 0 and length <= 512))' "$source" >/dev/null || {
    printf 'Cosign report is incomplete\n' >&2
    exit 1
  }
  jq -c --arg expected_digest "$artifact_digest" '
    {
      artifact_digest: .[0].critical.image["docker-manifest-digest"],
      identities: ([.[] | {subject:.optional.Subject, issuer:.optional.Issuer}] | unique),
      status: (if all(.[]; .critical.image["docker-manifest-digest"] == $expected_digest) then "verified" else "failed" end)
    }
  ' "$source" > "$result"
  write_envelope "$output_directory/signature.json" cosign "$result"
}

collect_provenance() {
  local source="$temporary_directory/provenance.json" result="$temporary_directory/provenance-result.json"
  require_json provenance "$source"
  jq -e 'type == "object" and (.subject | type == "array") and (.predicate | type == "object")' "$source" >/dev/null || {
    printf 'SLSA provenance is incomplete\n' >&2
    exit 1
  }
  jq -c '
    def subject_digests:
      [.subject[]?.digest.sha256? | select(type == "string" and test("^[0-9a-f]{64}$")) | "sha256:" + .] | unique;
    def builder_id: (.predicate.runDetails.builder.id // .predicate.builder.id // "");
    def build_type: (.predicate.buildDefinition.buildType // .predicate.buildType // "");
    def source_commit:
      ([.predicate.buildDefinition.resolvedDependencies[]?.digest.gitCommit?, .predicate.invocation.configSource.digest.sha1?]
       | map(select(type == "string" and test("^[0-9a-f]{40}$"))) | .[0] // null);
    subject_digests as $digests |
    builder_id as $builder |
    build_type as $build_type |
    source_commit as $source_commit |
    {
      subject_digests:$digests,
      builder_id:$builder,
      build_type:$build_type,
      source_commit:$source_commit,
      status:(if ($digests | length) > 0 and ($builder | type == "string" and length > 0 and length <= 512) and ($build_type | type == "string" and length > 0 and length <= 512) and $source_commit != null then "verified" else "failed" end)
    }
  ' "$source" > "$result"
  write_envelope "$output_directory/provenance.json" slsa "$result"
}

collect_scan() {
  local result="$temporary_directory/scan-result.json"
  if [ -z "$scan_source" ]; then
    printf '%s\n' '{"status":"not_run","complete":false,"scanned_at":null,"age_seconds":null,"findings":{"critical":0,"high":0,"medium":0,"low":0,"unknown":0}}' > "$result"
    write_envelope "$output_directory/scan.json" grype "$result"
    return
  fi

  local source="$temporary_directory/scan.json"
  require_json grype "$source"
  jq -e '(.descriptor.timestamp | type == "string" and test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")) and (.matches | type == "array")' "$source" >/dev/null || {
    printf 'Grype report is incomplete\n' >&2
    exit 1
  }
  jq -c '
    def count_severity($severity):
      [.matches[]?.vulnerability.severity? | select(type == "string") | ascii_downcase | select(. == $severity)] | length;
    .descriptor.timestamp as $scanned_at |
    ($scanned_at | fromdateiso8601) as $scanned_epoch |
    (now | floor) as $current_epoch |
    {
      status:"completed",
      complete:true,
      scanned_at:$scanned_at,
      age_seconds:(if $current_epoch > $scanned_epoch then $current_epoch - $scanned_epoch else 0 end),
      findings:{critical:count_severity("critical"), high:count_severity("high"), medium:count_severity("medium"), low:count_severity("low"), unknown:([.matches[]?.vulnerability.severity? | select(type != "string" or (ascii_downcase != "critical" and ascii_downcase != "high" and ascii_downcase != "medium" and ascii_downcase != "low"))] | length)}
    }
  ' "$source" > "$result"
  write_envelope "$output_directory/scan.json" grype "$result"
}

collect_posture
collect_sbom
collect_signature
collect_provenance
collect_scan
