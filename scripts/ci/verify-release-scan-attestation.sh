#!/usr/bin/env bash
# Check objective: Verify caller-authenticated release scan evidence is bound to the requested artifact digest.
# Content validation for Cosign DSSE output that a caller has already verified.
set -euo pipefail

usage() {
  printf 'Usage: %s VERIFIED_COSIGN_JSON SHA256_DIGEST [EXPECTED_SUMMARY_JSON]\n' "${0##*/}" >&2
  exit 64
}

[ "$#" -eq 2 ] || [ "$#" -eq 3 ] || usage
verified="$1"
digest="$2"
expected_file="${3:-}"
command -v jq >/dev/null 2>&1 || { printf '%s\n' 'missing command: jq' >&2; exit 69; }
test -s "$verified" || { printf '%s\n' 'verified Cosign output is missing or empty' >&2; exit 65; }
[[ "$digest" =~ ^sha256:[a-f0-9]{64}$ ]] || { printf '%s\n' 'expected digest must be sha256:<64 lowercase hex>' >&2; exit 64; }

expected_json='null'
if [ -n "$expected_file" ]; then
  test -s "$expected_file" || { printf '%s\n' 'expected scan summary is missing or empty' >&2; exit 65; }
  expected_json="$(jq -s -c -e 'if length == 1 and (.[0] | type) == "object" then .[0] else error("expected summary must be one object") end' "$expected_file")" || {
    printf '%s\n' 'expected scan summary must be exactly one JSON object' >&2
    exit 65
  }
fi

jq -s -e --arg digest "${digest#sha256:}" --argjson expected "$expected_json" '
  def nonempty: type == "string" and length > 0;
  def count: type == "number" and floor == . and . >= 0;
  def timestamp:
    type == "string" and
    test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$") and
    (try fromdateiso8601 catch empty | type == "number");
  def statements:
    if length == 1 and (.[0] | type) == "array" then .[0] else . end |
    map(.payload | @base64d | fromjson);
  def valid_summary:
    .schema_version == "v1" and .tool == "grype" and
    (.scanner | type == "object" and (.version | nonempty) and
      (.database_built | nonempty) and (.database_schema_version | nonempty)) and
    .artifact_digest == ("sha256:" + $digest) and
    (.sbom_sha256 | type == "string" and test("^[a-f0-9]{64}$")) and
    (.scanned_at | timestamp) and .status == "passed" and
    (.findings | type == "object" and
      (.critical | count) and (.high | count) and (.medium | count) and
      (.low | count) and (.unknown | count) and
      .critical == 0 and .high == 0 and .unknown == 0);
  statements | any(.[];
    (._type == "https://in-toto.io/Statement/v0.1" or ._type == "https://in-toto.io/Statement/v1") and
    (.subject | type == "array" and any(.[]; .digest.sha256? == $digest)) and
    .predicateType == "https://github.com/s1ns3nz0/node-operator/attestations/scan-summary/v1" and
    (.predicate | valid_summary) and
    (if $expected == null then true else .predicate == $expected end)
  )
' "$verified" >/dev/null || { printf '%s\n' 'verified scan attestation content is missing, malformed, or violates the release scan contract' >&2; exit 65; }
printf '%s\n' 'PASS: cryptographically pre-verified scan attestation has the required digest-bound summary content.'
