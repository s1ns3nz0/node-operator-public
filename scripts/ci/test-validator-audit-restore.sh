#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
builder="$root/scripts/ops/build-validator-audit-manifest.sh"
verifier="$root/scripts/ops/verify-validator-audit-restore.sh"
tmp="$(mktemp -d /private/tmp/node-operator-restore-test.XXXXXX)"
key='0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
jq -n --arg key "$key" '{schema_version:1,event_type:"uc-4",collected_at_utc:"2026-09-07T00:00:00Z",correlation_id:"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",network:"hoodi",validator_set:"hoodi-test-001",validator_public_key:$key,source:"private-beacon",payload:{}}' > "$tmp/record.json"
"$builder" --evidence-dir "$tmp" --output "$tmp/manifest.json" >/dev/null
"$verifier" --manifest "$tmp/manifest.json" --evidence-dir "$tmp" >/dev/null
printf '%s\n' 'corrupt' >> "$tmp/record.json"
if "$verifier" --manifest "$tmp/manifest.json" --evidence-dir "$tmp" >/dev/null 2>&1; then printf '%s\n' 'restore verifier accepted a corrupted record' >&2; exit 1; fi
printf '%s\n' 'PASS: archive restore verifier rejects corrupted evidence.'
