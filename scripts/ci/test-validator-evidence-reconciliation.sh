#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
script="$root/scripts/ops/reconcile-hoodi-validator-evidence.sh"
tmp="$(mktemp -d /private/tmp/node-operator-reconcile-test.XXXXXX)"
key='0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
correlation='aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
jq -n --arg key "$key" --arg correlation "$correlation" '{schema_version:1,event_type:"uc-3",collected_at_utc:"2026-09-07T00:00:00Z",correlation_id:$correlation,network:"hoodi",validator_set:"hoodi-test-001",validator_public_key:$key,source:"private-beacon",payload:{}}' > "$tmp/private.json"
jq -n --arg key "$key" --arg correlation "$correlation" '{schema_version:1,event_type:"uc-3",collected_at_utc:"2026-09-07T00:00:01Z",correlation_id:$correlation,network:"hoodi",validator_set:"hoodi-test-001",validator_public_key:$key,source:"beaconcha-in",payload:{verification_status:"not-configured"}}' > "$tmp/external.json"
"$script" --private "$tmp/private.json" --external "$tmp/external.json" --output-dir "$tmp/output" >/dev/null
jq -e '.event_type == "source-disagreement" and .payload.reconciliation_status == "external-not-configured" and (.payload.operator_action | test("do not alter validator runtime"))' "$tmp/output"/*.json >/dev/null
printf 'PASS: reconciliation treats missing external evidence as observability-only.\n'
