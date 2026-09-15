#!/usr/bin/env bash
set -euo pipefail

# UC-5 recovery never deletes or recreates slashing history. It restores only
# the signer, leaves the client at zero, and delegates a new duty start to the
# independent activation gate after evidence review.
usage() { printf '%s\n' "Usage: ${0##*/} --validator-set <hoodi-id> --validator-public-key <0x-key> --correlation-id <id> --recovery-approval-id <id> --output-dir <absolute-dir> [--dry-run]" >&2; exit 64; }
validator_set=''; public_key=''; correlation_id=''; approval_id=''; output_dir=''; dry_run=false
while [ "$#" -gt 0 ]; do
  case "$1" in
    --validator-set) validator_set="${2:-}"; shift 2 ;;
    --validator-public-key) public_key="${2:-}"; shift 2 ;;
    --correlation-id) correlation_id="${2:-}"; shift 2 ;;
    --recovery-approval-id) approval_id="${2:-}"; shift 2 ;;
    --output-dir) output_dir="${2:-}"; shift 2 ;;
    --dry-run) dry_run=true; shift ;;
    *) usage ;;
  esac
done
case "$validator_set" in hoodi-[a-z0-9][a-z0-9-]*) ;; *) usage ;; esac
case "$public_key" in 0x????????????????????????????????????????????????????????????????????????????????????????????????) ;; *) usage ;; esac
case "$correlation_id" in [a-f0-9-][a-f0-9-][a-f0-9-][a-f0-9-][a-f0-9-][a-f0-9-][a-f0-9-][a-f0-9-]*) ;; *) usage ;; esac
case "$approval_id" in [a-zA-Z0-9][a-zA-Z0-9._:-]*) ;; *) usage ;; esac
case "$output_dir" in /*) ;; *) usage ;; esac
for command in kubectl jq mkdir chmod date; do command -v "$command" >/dev/null 2>&1 || { printf 'missing command: %s\n' "$command" >&2; exit 69; }; done

namespace=validator-operations
client_replicas="$(kubectl -n "$namespace" get deployment "validator-${validator_set}-client" --ignore-not-found -o jsonpath='{.spec.replicas}')"
stateful_replicas="$(kubectl -n "$namespace" get statefulset "validator-${validator_set}-client" --ignore-not-found -o jsonpath='{.spec.replicas}')"
fence_replicas="$(kubectl -n "$namespace" get deployment "validator-${validator_set}-signing-fence" --ignore-not-found -o jsonpath='{.spec.replicas}')"
signer_replicas="$(kubectl -n "$namespace" get deployment "validator-${validator_set}-remote-signer" -o jsonpath='{.spec.replicas}')"
[ -z "$client_replicas" ] || [ "$client_replicas" = 0 ] || { printf '%s\n' 'validator client is not fenced at zero replicas' >&2; exit 65; }
[ -z "$stateful_replicas" ] || [ "$stateful_replicas" = 0 ] || { printf '%s\n' 'validator StatefulSet client is not fenced at zero replicas' >&2; exit 65; }
client_controller_count=0
[ -z "$client_replicas" ] || client_controller_count=$((client_controller_count + 1))
[ -z "$stateful_replicas" ] || client_controller_count=$((client_controller_count + 1))
[ "$client_controller_count" -eq 1 ] || { printf '%s\n' 'expected exactly one staged zero-replica validator client controller' >&2; exit 65; }
[ -z "$fence_replicas" ] || [ "$fence_replicas" = 0 ] || { printf '%s\n' 'signing fence is not at zero replicas' >&2; exit 65; }
[ "$signer_replicas" = 0 ] || { printf '%s\n' 'remote signer is not fenced at zero replicas' >&2; exit 65; }
remaining_pods="$(kubectl -n "$namespace" get pods -l "app.kubernetes.io/component in (validator-client,validator-remote-signer,validator-signing-fence),node-operator.io/validator-set=${validator_set}" -o json)"
jq -e '.items | type == "array" and length == 0' <<<"$remaining_pods" >/dev/null || { printf '%s\n' 'client, signer or fence Pods remain; recovery refused' >&2; exit 65; }
lease_holder="$(kubectl -n "$namespace" get lease "validator-${validator_set}-primary" -o jsonpath='{.spec.holderIdentity}')"
[ -z "$lease_holder" ] || { printf '%s\n' 'active fence lease holder remains; recovery refused' >&2; exit 65; }
pvc="data-validator-${validator_set}-slashing-db-0"
pvc_phase="$(kubectl -n "$namespace" get pvc "$pvc" -o jsonpath='{.status.phase}')"
[ "$pvc_phase" = Bound ] || { printf '%s\n' 'retained slashing DB PVC is not Bound; recovery refused' >&2; exit 65; }
pvc_set="$(kubectl -n "$namespace" get pvc "$pvc" -o jsonpath='{.metadata.labels.node-operator\.io/validator-set}')"
[ "$pvc_set" = "$validator_set" ] || { printf '%s\n' 'slashing DB PVC validator-set does not match requested recovery' >&2; exit 65; }

mkdir -p "$output_dir"; chmod 700 "$output_dir"; output_dir="$(cd "$output_dir" && pwd -P)"
record="$output_dir/uc-5-recovery-$(date -u +%Y%m%dT%H%M%SZ).json"
jq -n --arg collected "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --arg correlation "$correlation_id" --arg set "$validator_set" --arg key "$public_key" --arg approval "$approval_id" --arg pvc "$pvc" --arg mode "$dry_run" \
  '{schema_version:1,event_type:"uc-5",collected_at_utc:$collected,correlation_id:$correlation,network:"hoodi",validator_set:$set,validator_public_key:$key,source:"kubernetes",payload:{recovery_approval_id:$approval,fence_holder_absent:true,slashing_db_pvc:$pvc,slashing_db_pvc_bound:true,client_remains_fenced:true,client_signer_fence_pods_absent_at_preflight:true,uc5_complete:false,mode:(if $mode == "true" then "dry-run" else "restore-signer-only" end)}}' > "$record"
if [ "$dry_run" = true ]; then printf 'PASS: recovery gate passed; no workload was scaled. Evidence: %s\n' "$record"; exit 0; fi
kubectl -n "$namespace" scale deployment "validator-${validator_set}-remote-signer" --replicas=1
printf 'PASS: signer recovery submitted; validator client remains fenced at zero. Evidence: %s\n' "$record"
