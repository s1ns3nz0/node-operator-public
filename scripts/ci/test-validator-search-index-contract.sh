#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
script="$root/scripts/ops/build-validator-search-index.sh"
tmp="$(mktemp -d)"
key="0x$(printf 'ab%.0s' {1..48})"
jq -n --arg key "$key" '{schema_version:1,event_type:"uc-3",collected_at_utc:"2026-09-07T00:00:00Z",correlation_id:"12345678-1234-1234-1234-1234567890ab",network:"hoodi",validator_set:"hoodi-example",validator_public_key:$key,source:"private-beacon",payload:{validator_index:"123",token:"prohibited"}}' > "$tmp/forbidden.json"
if "$script" --evidence-dir "$tmp" --output "$tmp/index.ndjson" >/dev/null 2>&1; then
  printf 'search index accepted forbidden evidence\n' >&2; exit 1
fi
mkdir "$tmp/valid"
jq 'del(.payload.token)' "$tmp/forbidden.json" > "$tmp/valid/evidence.json"
"$script" --evidence-dir "$tmp/valid" --output "$tmp/valid/index.ndjson" >/dev/null
[ "$(wc -l < "$tmp/valid/index.ndjson" | tr -d ' ')" = 2 ]
grep -Fq 'hoodi-validator-evidence-v1' "$tmp/valid/index.ndjson"
printf 'PASS validator search index is derived only from schema-valid public evidence.\n'
