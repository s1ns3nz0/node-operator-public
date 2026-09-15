#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
for observer in observe-private-hoodi-validator.sh observe-private-hoodi-validator-duties.sh; do
  file="$root/scripts/ops/$observer"
  grep -Fq "beacon_target='service/prysm-beacon'" "$file"
  grep -Fq 'get service prysm-beacon' "$file"
  grep -Fq 'app.kubernetes.io/name=prysm-beacon' "$file"
  grep -Fq 'expected exactly one Ready private Prysm Beacon Pod' "$file"
  grep -Fq "port-forward \"\$beacon_target\"" "$file"
done

duties="$root/scripts/ops/observe-private-hoodi-validator-duties.sh"
state_observer="$root/scripts/ops/observe-private-hoodi-validator.sh"
grep -Fq '/eth/v1/beacon/states/head/pending_deposits' "$state_observer"
grep -Fq 'deposit_state:' "$state_observer"
grep -Fq 'pending-deposit' "$state_observer"
grep -Fq 'unresolved-not-found' "$state_observer"
grep -Fq 'collection alone does not establish UC-3 completion' "$state_observer"
if grep -Fq 'PASS: private Beacon API evidence' "$state_observer"; then
  printf '%s\n' 'FAIL: evidence collection must not claim UC-3 PASS.' >&2
  exit 1
fi
grep -Fq 'fetch_success_json()' "$duties"
grep -Fq 'curl --fail --silent --show-error' "$duties"
grep -Fq "[ \"\$http_status\" = 200 ]" "$duties"
grep -Fq 'validate_attester_response()' "$duties"
grep -Fq 'validate_proposer_response()' "$duties"
grep -Fq 'validate_sync_response()' "$duties"
grep -Fq "duty_request_body=\"\$(jq -cn --arg index \"\$validator_index\" '[\$index]')\"" "$duties"
grep -Fq "attester/\${duty_epoch}" "$duties"
grep -Fq "sync/\${duty_epoch}" "$duties"
grep -Fq -- '--request POST' "$duties"
grep -Fq -- "--data \"\$duty_request_body\"" "$duties"
grep -Fq "proposer/\${duty_epoch}" "$duties"
grep -Fq "query_duty_epoch \"\$current_epoch\"" "$duties"
grep -Fq "query_duty_epoch \"\$next_epoch\"" "$duties"
grep -Fq 'signed_outcomes_observed:false' "$duties"
if grep -Fq "duties/attester/\${current_epoch}?index=" "$duties"; then
  printf '%s\n' 'FAIL: attester duties must use the POST JSON body, not a query-string index.' >&2
  exit 1
fi
printf '%s\n' 'PASS: private Beacon observers select a private target safely; the duty observer uses fail-closed, standards-shaped assignment requests for current and next epochs.'
