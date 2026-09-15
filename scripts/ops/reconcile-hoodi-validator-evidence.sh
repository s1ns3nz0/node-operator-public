#!/usr/bin/env bash
set -euo pipefail

# This produces an alertable record, never a control signal. In particular, an
# asynchronous public explorer must not start, stop, or retry validator duties.
usage() { printf 'Usage: %s --private <evidence-json> --external <evidence-json> --output-dir <absolute-dir>\n' "${0##*/}" >&2; exit 64; }
private_file=''; external_file=''; output_dir=''
while [ "$#" -gt 0 ]; do
  case "$1" in
    --private) private_file="${2:-}"; shift 2 ;;
    --external) external_file="${2:-}"; shift 2 ;;
    --output-dir) output_dir="${2:-}"; shift 2 ;;
    *) usage ;;
  esac
done
case "$private_file" in /*) ;; *) usage ;; esac
case "$external_file" in /*) ;; *) usage ;; esac
case "$output_dir" in /*) ;; *) usage ;; esac
for command in jq mkdir chmod date; do command -v "$command" >/dev/null 2>&1 || { printf 'missing command: %s\n' "$command" >&2; exit 69; }; done
[ -r "$private_file" ] && [ -r "$external_file" ] || { printf 'evidence input is not readable\n' >&2; exit 66; }

for evidence in "$private_file" "$external_file"; do
  jq -e '
    .schema_version == 1 and .network == "hoodi" and
    (.correlation_id | test("^[a-f0-9-]{16,64}$")) and
    (.validator_public_key | test("^0x[0-9a-fA-F]{96}$"))
  ' "$evidence" >/dev/null || { printf 'input is not a valid public evidence envelope\n' >&2; exit 65; }
  if jq -e '[.. | objects | keys[]? | ascii_downcase | test("mnemonic|keystore|password|token|recovery|kubeconfig|secret_access_key")] | any' "$evidence" >/dev/null; then
    printf 'input contains a forbidden field name\n' >&2; exit 65
  fi
done

mkdir -p "$output_dir"; chmod 700 "$output_dir"; output_dir="$(cd "$output_dir" && pwd -P)"
timestamp="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
record="$output_dir/source-disagreement-$(date -u +%Y%m%dT%H%M%SZ).json"
jq -n --arg collected "$timestamp" --slurpfile private "$private_file" --slurpfile external "$external_file" '
  $private[0] as $p | $external[0] as $e |
  (if $p.correlation_id != $e.correlation_id or $p.validator_public_key != $e.validator_public_key or $p.validator_set != $e.validator_set then
     "identity-mismatch"
   elif ($e.payload.verification_status // "unavailable") == "observed" then
     "corroborated"
   elif ($e.payload.verification_status // "unavailable") == "not-configured" then
     "external-not-configured"
   else "external-unavailable-or-indexing-delay"
   end) as $status |
  {schema_version:1,event_type:"source-disagreement",collected_at_utc:$collected,correlation_id:$p.correlation_id,network:"hoodi",validator_set:$p.validator_set,validator_public_key:$p.validator_public_key,source:"private-beacon",payload:{reconciliation_status:$status,private_event_type:$p.event_type,external_source:$e.source,external_event_type:$e.event_type,private_collected_at_utc:$p.collected_at_utc,external_collected_at_utc:$e.collected_at_utc,operator_action:(if $status == "identity-mismatch" then "stop and investigate evidence identity; do not alter validator runtime" elif $status == "corroborated" then "none" else "record an observability alert; do not alter validator runtime" end)}}
  ' > "$record"
printf 'PASS: reconciliation evidence written to %s; it is not a runtime control signal.\n' "$record"
