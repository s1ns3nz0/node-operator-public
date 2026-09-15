#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
builder="$root/scripts/ops/build-validator-audit-manifest.sh"
tmp="$(mktemp -d /private/tmp/node-operator-manifest-test.XXXXXX)"
key='0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
jq -n --arg key "$key" '{schema_version:1,event_type:"uc-3",collected_at_utc:"2026-09-07T00:00:00Z",correlation_id:"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",network:"hoodi",validator_set:"hoodi-test-001",validator_public_key:$key,source:"private-beacon",payload:{}}' > "$tmp/record.json"
"$builder" --evidence-dir "$tmp" --output "$tmp/manifest.json" >/dev/null
jq -e '.event_type == "archive-manifest" and (.records | length == 1) and (.records[0].sha256 | test("^[a-f0-9]{64}$"))' "$tmp/manifest.json" >/dev/null
jq -n --arg key "$key" '{schema_version:1,event_type:"uc-3",collected_at_utc:"2026-09-07T00:00:00Z",correlation_id:"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",network:"hoodi",validator_set:"hoodi-test-001",validator_public_key:$key,source:"private-beacon",payload:{password:"forbidden"}}' > "$tmp/forbidden.json"
if "$builder" --evidence-dir "$tmp" --output "$tmp/rejected.json" >/dev/null 2>&1; then printf '%s\n' 'manifest accepted forbidden evidence' >&2; exit 1; fi
printf '%s\n' 'PASS: audit manifest accepts only validated non-secret evidence.'
