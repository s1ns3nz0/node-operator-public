#!/usr/bin/env bash
set -euo pipefail

# Read-only UC-4 assignment observer. It asks the private Beacon API for duty
# assignments only; actual signed outcomes remain correlated later from the
# validator and signer audit streams. It never reads Vault or key material.
usage() { printf 'Usage: %s --validator-set <hoodi-id> --validator-public-key <0x-key> --correlation-id <id> --output-dir <absolute-dir>\n' "${0##*/}" >&2; exit 64; }
validator_set=''; public_key=''; correlation_id=''; output_dir=''
while [ "$#" -gt 0 ]; do
  case "$1" in
    --validator-set) validator_set="${2:-}"; shift 2 ;;
    --validator-public-key) public_key="${2:-}"; shift 2 ;;
    --correlation-id) correlation_id="${2:-}"; shift 2 ;;
    --output-dir) output_dir="${2:-}"; shift 2 ;;
    *) usage ;;
  esac
done
case "$validator_set" in hoodi-[a-z0-9][a-z0-9-]*) ;; *) usage ;; esac
case "$public_key" in 0x????????????????????????????????????????????????????????????????????????????????????????????????) ;; *) usage ;; esac
case "$correlation_id" in [a-f0-9-][a-f0-9-][a-f0-9-][a-f0-9-][a-f0-9-][a-f0-9-][a-f0-9-][a-f0-9-]*) ;; *) usage ;; esac
case "$output_dir" in /*) ;; *) usage ;; esac
for command in kubectl curl jq nc mktemp date unlink mkdir chmod; do command -v "$command" >/dev/null 2>&1 || { printf 'missing command: %s\n' "$command" >&2; exit 69; }; done

mkdir -p "$output_dir"; chmod 700 "$output_dir"; output_dir="$(cd "$output_dir" && pwd -P)"
port="${PRIVATE_BEACON_LOCAL_PORT:-19500}"
nc -z 127.0.0.1 "$port" >/dev/null 2>&1 && { printf 'local beacon port %s is already in use\n' "$port" >&2; exit 75; }
port_log="$(mktemp /private/tmp/node-operator-duty-port.XXXXXX)"; port_pid=''
validator_file="$(mktemp /private/tmp/node-operator-duty-validator.XXXXXX)"
node_sync_file="$(mktemp /private/tmp/node-operator-duty-node-sync.XXXXXX)"
attester_current_file="$(mktemp /private/tmp/node-operator-duty-attester-current.XXXXXX)"
proposer_current_file="$(mktemp /private/tmp/node-operator-duty-proposer-current.XXXXXX)"
sync_current_file="$(mktemp /private/tmp/node-operator-duty-sync-current.XXXXXX)"
attester_next_file="$(mktemp /private/tmp/node-operator-duty-attester-next.XXXXXX)"
proposer_next_file="$(mktemp /private/tmp/node-operator-duty-proposer-next.XXXXXX)"
sync_next_file="$(mktemp /private/tmp/node-operator-duty-sync-next.XXXXXX)"
cleanup() { set +e; [ -z "$port_pid" ] || kill -TERM "$port_pid" 2>/dev/null || true; [ -z "$port_pid" ] || wait "$port_pid" 2>/dev/null || true; unlink "$port_log" "$validator_file" "$node_sync_file" "$attester_current_file" "$proposer_current_file" "$sync_current_file" "$attester_next_file" "$proposer_next_file" "$sync_next_file" 2>/dev/null || true; }
trap cleanup EXIT INT TERM
# A release may expose the Beacon API through its Service or directly from the
# singleton StatefulSet Pod. Both are private. Refuse ambiguity rather than
# selecting an arbitrary Pod when the Service is intentionally absent.
beacon_target='service/prysm-beacon'
if ! kubectl -n node-operator get service prysm-beacon >/dev/null 2>&1; then
  beacon_pod="$(kubectl -n node-operator get pods -l app.kubernetes.io/name=prysm-beacon -o json | jq -r '[.items[] | select(any(.status.conditions[]?; .type == "Ready" and .status == "True")) | .metadata.name] | if length == 1 then .[0] else empty end')"
  [ -n "$beacon_pod" ] || { printf 'expected exactly one Ready private Prysm Beacon Pod when its Service is absent\n' >&2; exit 75; }
  beacon_target="pod/${beacon_pod}"
fi
kubectl -n node-operator port-forward "$beacon_target" "${port}:3500" >"$port_log" 2>&1 & port_pid=$!
for ((attempt = 1; attempt <= 20; attempt++)); do nc -z 127.0.0.1 "$port" >/dev/null 2>&1 && break; sleep 1; done
nc -z 127.0.0.1 "$port" >/dev/null || { printf 'private beacon port-forward did not become ready\n' >&2; exit 75; }

base_url="http://127.0.0.1:${port}"

# Do not turn a failed or unexpected response into empty duty evidence. The
# assignment endpoints are useful only when every queried response is a valid
# success response for this validator and epoch.
fetch_success_json() {
  response_name="$1"; response_file="$2"; shift 2
  http_status="$(curl --fail --silent --show-error --output "$response_file" --write-out '%{http_code}' "$@")" || {
    printf 'private Beacon %s request failed; refusing to record assignments\n' "$response_name" >&2
    exit 65
  }
  [ "$http_status" = 200 ] || {
    printf 'private Beacon %s returned HTTP %s; refusing to record assignments\n' "$response_name" "$http_status" >&2
    exit 65
  }
}

fetch_success_json 'node sync state' "$node_sync_file" --header 'Accept: application/json' "${base_url}/eth/v1/node/syncing"
jq -e '
  type == "object"
  and (.data | type == "object")
  and (.data.head_slot | type == "string" and test("^[0-9]+$"))
  and (.data.is_syncing | type == "boolean")
  and (.data.is_optimistic | type == "boolean")
  and (.data.el_offline | type == "boolean")
' "$node_sync_file" >/dev/null || {
  printf 'private Beacon node-sync response is malformed\n' >&2
  exit 65
}
head_slot="$(jq -r '.data.head_slot' "$node_sync_file")"

validate_validator_response() {
  jq -e --arg key "$public_key" '
    type == "object"
    and (.data | type == "object")
    and (.data.index | type == "string" and test("^[0-9]+$"))
    and (.data.validator | type == "object")
    and (.data.validator.pubkey == $key)
  ' "$validator_file" >/dev/null || {
    printf 'private Beacon validator response is malformed or identifies another validator\n' >&2
    exit 65
  }
}

validate_attester_response() {
  response_file="$1"
  jq -e --arg key "$public_key" --arg index "$validator_index" '
    type == "object"
    and (.dependent_root | type == "string")
    and (.execution_optimistic | type == "boolean")
    and (.data | type == "array")
    and all(.data[]; type == "object"
      and .pubkey == $key
      and .validator_index == $index
      and (.committee_index | type == "string")
      and (.committee_length | type == "string")
      and (.committees_at_slot | type == "string")
      and (.validator_committee_index | type == "string")
      and (.slot | type == "string"))
  ' "$response_file" >/dev/null || {
    printf 'private Beacon attester-duty response is malformed\n' >&2
    exit 65
  }
}

validate_proposer_response() {
  response_file="$1"
  jq -e '
    type == "object"
    and (.dependent_root | type == "string")
    and (.execution_optimistic | type == "boolean")
    and (.data | type == "array")
    and all(.data[]; type == "object"
      and (.pubkey | type == "string")
      and (.validator_index | type == "string")
      and (.slot | type == "string"))
  ' "$response_file" >/dev/null || {
    printf 'private Beacon proposer-duty response is malformed\n' >&2
    exit 65
  }
}

validate_sync_response() {
  response_file="$1"
  jq -e --arg key "$public_key" --arg index "$validator_index" '
    type == "object"
    and (.execution_optimistic | type == "boolean")
    and (.data | type == "array")
    and all(.data[]; type == "object"
      and .pubkey == $key
      and .validator_index == $index
      and (.validator_sync_committee_indices | type == "array")
      and all(.validator_sync_committee_indices[]; type == "string"))
  ' "$response_file" >/dev/null || {
    printf 'private Beacon sync-duty response is malformed\n' >&2
    exit 65
  }
}

fetch_success_json 'validator' "$validator_file" --header 'Accept: application/json' "${base_url}/eth/v1/beacon/states/head/validators/${public_key}"
validate_validator_response

validator_index="$(jq -r '.data.index // empty' "$validator_file")"
case "$validator_index" in ''|*[!0-9]*) printf 'active validator response lacks a numeric index\n' >&2; exit 65 ;; esac
current_epoch=$((head_slot / 32)); next_epoch=$((current_epoch + 1))
duty_request_body="$(jq -cn --arg index "$validator_index" '[$index]')"
query_duty_epoch() {
  duty_epoch="$1"; attester_response_file="$2"; proposer_response_file="$3"; sync_response_file="$4"
  fetch_success_json "attester duties for epoch ${duty_epoch}" "$attester_response_file" --request POST --header 'Accept: application/json' --header 'Content-Type: application/json' --data "$duty_request_body" "${base_url}/eth/v1/validator/duties/attester/${duty_epoch}"
  validate_attester_response "$attester_response_file"
  fetch_success_json "proposer duties for epoch ${duty_epoch}" "$proposer_response_file" --header 'Accept: application/json' "${base_url}/eth/v1/validator/duties/proposer/${duty_epoch}"
  validate_proposer_response "$proposer_response_file"
  fetch_success_json "sync duties for epoch ${duty_epoch}" "$sync_response_file" --request POST --header 'Accept: application/json' --header 'Content-Type: application/json' --data "$duty_request_body" "${base_url}/eth/v1/validator/duties/sync/${duty_epoch}"
  validate_sync_response "$sync_response_file"
}

query_duty_epoch "$current_epoch" "$attester_current_file" "$proposer_current_file" "$sync_current_file"
query_duty_epoch "$next_epoch" "$attester_next_file" "$proposer_next_file" "$sync_next_file"

timestamp="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
record="$output_dir/uc-4-private-duties-$(date -u +%Y%m%dT%H%M%SZ).json"
jq -n --arg collected "$timestamp" --arg correlation "$correlation_id" --arg set "$validator_set" --arg key "$public_key" --arg index "$validator_index" --argjson current "$current_epoch" --argjson next "$next_epoch" \
  --slurpfile attester_current "$attester_current_file" --slurpfile proposer_current "$proposer_current_file" --slurpfile sync_current "$sync_current_file" \
  --slurpfile attester_next "$attester_next_file" --slurpfile proposer_next "$proposer_next_file" --slurpfile sync_next "$sync_next_file" '
  {schema_version:1,event_type:"uc-4",collected_at_utc:$collected,correlation_id:$correlation,network:"hoodi",validator_set:$set,validator_public_key:$key,source:"private-beacon",payload:{observation_status:"assignments-observed",signed_outcomes_observed:false,signed_outcomes_note:"not observed by assignment queries; correlate separately with validator and signer audit evidence",validator_index:$index,queried_epochs:[$current,$next],assignments:{current_epoch:{epoch:$current,attester:([$attester_current[0].data[] | {pubkey,validator_index,committee_index,committee_length,committees_at_slot,validator_committee_index,slot}]),proposer:([$proposer_current[0].data[] | select(.validator_index == $index) | {pubkey,validator_index,slot}]),sync:([$sync_current[0].data[] | {pubkey,validator_index,validator_sync_committee_indices}])},next_epoch:{epoch:$next,attester:([$attester_next[0].data[] | {pubkey,validator_index,committee_index,committee_length,committees_at_slot,validator_committee_index,slot}]),proposer:([$proposer_next[0].data[] | select(.validator_index == $index) | {pubkey,validator_index,slot}]),sync:([$sync_next[0].data[] | {pubkey,validator_index,validator_sync_committee_indices}])}}}}' > "$record"
printf 'PASS: private Beacon duty-assignment evidence written to %s\n' "$record"
