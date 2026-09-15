#!/usr/bin/env bash
# Check objective: Verify release scan attestations bind the reviewed artifact and scanner summary.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
verifier="$root/scripts/ci/verify-release-scan-attestation.sh"
scratch="$(mktemp -d)"
trap 'rm -rf -- "$scratch"' EXIT
digest='sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'

statement="$(jq -cn --arg digest "$digest" '{_type:"https://in-toto.io/Statement/v1",subject:[{name:"fixture",digest:{sha256:($digest|sub("^sha256:";""))}}],predicateType:"https://github.com/s1ns3nz0/node-operator/attestations/scan-summary/v1",predicate:{schema_version:"v1",tool:"grype",scanner:{version:"0.118.0",database_built:"2026-09-09T00:00:00Z",database_schema_version:"v6"},artifact_digest:$digest,sbom_sha256:"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",scanned_at:"2026-09-09T00:00:00Z",findings:{critical:0,high:0,medium:0,low:0,unknown:0},status:"passed"}}')"
envelope() { jq -cn --arg payload "$(printf '%s' "$1" | base64 | tr -d '\n')" '{payload:$payload,payloadType:"application/vnd.in-toto+json",signatures:[{sig:"already-verified"}]}'; }
write() { envelope "$1" > "$2"; }
write "$statement" "$scratch/valid.json"
printf '%s\n' "$statement" | while IFS= read -r line; do envelope "$line"; done > "$scratch/valid.jsonl"
jq -n --argjson summary "$(jq -c '.predicate' <<<"$statement")" '$summary' > "$scratch/expected.json"
"$verifier" "$scratch/valid.json" "$digest" "$scratch/expected.json" >/dev/null
"$verifier" "$scratch/valid.jsonl" "$digest" >/dev/null
printf '[%s]\n' "$(cat "$scratch/valid.json")" > "$scratch/valid-array.json"
"$verifier" "$scratch/valid-array.json" "$digest" >/dev/null

expect_fail() { if "$verifier" "$1" "$digest" >/dev/null 2>&1; then printf 'invalid fixture accepted: %s\n' "$1" >&2; exit 1; fi; }
write "$(jq '._type="https://example.invalid/Statement/v1"' <<<"$statement")" "$scratch/wrongtype.json"; expect_fail "$scratch/wrongtype.json"
write "$(jq 'del(.predicate.scanner.database_built)' <<<"$statement")" "$scratch/missingfields.json"; expect_fail "$scratch/missingfields.json"
write "$(jq '.subject[0].digest.sha256="cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"' <<<"$statement")" "$scratch/wrongdigest.json"; expect_fail "$scratch/wrongdigest.json"
write "$(jq '.predicate.findings.medium="0"' <<<"$statement")" "$scratch/typecounts.json"; expect_fail "$scratch/typecounts.json"
write "$(jq '.predicateType="https://cosign.sigstore.dev/attestation/vuln/v1" | .predicate={scanner:{version:"0.118.0"}}' <<<"$statement")" "$scratch/legacyvuln.json"; expect_fail "$scratch/legacyvuln.json"
test ! -s "$scratch/empty.json"; expect_fail "$scratch/empty.json"
printf '{not json}\n' > "$scratch/malformed.json"; expect_fail "$scratch/malformed.json"
jq '.predicate.status="blocked"' "$scratch/expected.json" > "$scratch/wrong-expected.json"
if "$verifier" "$scratch/valid.json" "$digest" "$scratch/wrong-expected.json" >/dev/null 2>&1; then printf '%s\n' 'different expected summary accepted' >&2; exit 1; fi
printf 'null\n' > "$scratch/null-expected.json"
if "$verifier" "$scratch/valid.json" "$digest" "$scratch/null-expected.json" >/dev/null 2>&1; then printf '%s\n' 'null expected summary disabled comparison' >&2; exit 1; fi
printf '%s\n%s\n' "$(jq -c '.predicate' <<<"$statement")" "$(jq -c '.predicate' <<<"$statement")" > "$scratch/multiple-expected.json"
if "$verifier" "$scratch/valid.json" "$digest" "$scratch/multiple-expected.json" >/dev/null 2>&1; then printf '%s\n' 'multiple expected summaries accepted' >&2; exit 1; fi
printf '%s\n' 'PASS: scan-attestation verifier accepts JSON/JSONL and rejects malformed, legacy, digest, schema, and count drift.'
