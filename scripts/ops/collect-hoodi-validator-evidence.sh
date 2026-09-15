#!/usr/bin/env bash
set -euo pipefail

# Collects non-secret lifecycle evidence. It deliberately saves selected,
# redacted client/signing state rather than raw pod logs or any Vault response.

usage() {
  printf 'Usage: %s --phase <uc-1|uc-2|uc-3|uc-4|uc-5> --validator-set <id> --validator-public-key <0x-BLS-pubkey> --output-dir <absolute-dir>\n' "${0##*/}" >&2
  exit 64
}

phase=''; validator_set=''; public_key=''; output_dir=''
while [ "$#" -gt 0 ]; do
  case "$1" in
    --phase) phase="${2:-}"; shift 2 ;;
    --validator-set) validator_set="${2:-}"; shift 2 ;;
    --validator-public-key) public_key="${2:-}"; shift 2 ;;
    --output-dir) output_dir="${2:-}"; shift 2 ;;
    *) usage ;;
  esac
done
case "$phase" in uc-1|uc-2|uc-3|uc-4|uc-5) ;; *) usage ;; esac
case "$validator_set" in hoodi-[a-z0-9][a-z0-9-]*) ;; *) usage ;; esac
case "$public_key" in 0x????????????????????????????????????????????????????????????????????????????????????????????????) ;; *) usage ;; esac
case "$output_dir" in /*) ;; *) usage ;; esac
for command in kubectl jq date mkdir sed tr; do command -v "$command" >/dev/null 2>&1 || { printf 'missing command: %s\n' "$command" >&2; exit 69; }; done

mkdir -p "$output_dir"
chmod 700 "$output_dir"
output_dir="$(cd "$output_dir" && pwd -P)"
timestamp="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
record="$output_dir/${phase}-${validator_set}-$(date -u +%Y%m%dT%H%M%SZ).json"
node_json="$(kubectl -n node-operator get pods -l 'app.kubernetes.io/part-of=hoodi-node' -o json)"
validator_json="$(kubectl -n validator-operations get pods -l "node-operator.io/validator-set=${validator_set}" -o json 2>/dev/null || printf '{"items":[]}')"
lease_json="$(kubectl -n validator-operations get lease "validator-${validator_set}-primary" -o json 2>/dev/null || printf '{}')"
events_json="$(kubectl -n validator-operations get events --field-selector involvedObject.namespace=validator-operations -o json 2>/dev/null || printf '{"items":[]}')"

# Event messages can include operator-provided strings. Retain only standard
# Kubernetes reason/timestamp/object metadata and no message body.
jq -n --arg timestamp "$timestamp" --arg phase "$phase" --arg validator_set "$validator_set" --arg public_key "$public_key" \
  --argjson node "$node_json" --argjson validator "$validator_json" --argjson lease "$lease_json" --argjson events "$events_json" '
  {schema_version:1,collected_at_utc:$timestamp,use_case:$phase,network:"hoodi",validator_set:$validator_set,validator_public_key:$public_key,
   node_pods:[$node.items[] | {name:.metadata.name,phase:.status.phase,ready:([.status.containerStatuses[]?.ready] | all),created_at:.metadata.creationTimestamp}],
   validator_pods:[$validator.items[] | {name:.metadata.name,phase:.status.phase,ready:([.status.containerStatuses[]?.ready] | all),created_at:.metadata.creationTimestamp}],
   fence:($lease | if .metadata then {name:.metadata.name,holder_identity:(.spec.holderIdentity // null),renew_time:(.spec.renewTime // null),lease_duration_seconds:(.spec.leaseDurationSeconds // null)} else null end),
   recent_kubernetes_events:[$events.items[] | {reason:.reason,type:.type,object:(.involvedObject.kind + "/" + .involvedObject.name),last_timestamp:(.eventTime // .lastTimestamp // .metadata.creationTimestamp)}] | sort_by(.last_timestamp) | reverse | .[:50],
   redaction:"No Vault response, credential, raw pod log, keystore, mnemonic, password, recovery material, or wallet material is collected."}' > "$record"
chmod 600 "$record"
phase_label="$(printf '%s' "$phase" | tr '[:lower:]' '[:upper:]')"
printf 'COLLECTED %s: non-secret lifecycle evidence written to %s; collection alone does not establish use-case success.\n' "$phase_label" "$record"
