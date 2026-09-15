#!/usr/bin/env bash
set -euo pipefail

# Upgrade the Web3Signer slashing database without recreating its PVC. A
# failed migration deliberately leaves both signer and client fenced at zero.
dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
if [ "${PRIVATE_EKS_SESSION:-}" != 1 ]; then
  exec "$dir/with-private-eks.sh" -- env PRIVATE_EKS_SESSION=1 "$0" "$@"
fi

usage() { printf '%s\n' "Usage: ${0##*/} --validator-set <hoodi-id> --web3signer-image <private-ecr@sha256> --migration-approval-id <id> --output-dir <absolute-dir> [--dry-run]" >&2; exit 64; }
validator_set=''; image=''; approval_id=''; output_dir=''; dry_run=false
while [ "$#" -gt 0 ]; do
  case "$1" in
    --validator-set) validator_set="${2:-}"; shift 2 ;;
    --web3signer-image) image="${2:-}"; shift 2 ;;
    --migration-approval-id) approval_id="${2:-}"; shift 2 ;;
    --output-dir) output_dir="${2:-}"; shift 2 ;;
    --dry-run) dry_run=true; shift ;;
    *) usage ;;
  esac
done
case "$validator_set" in hoodi-[a-z0-9][a-z0-9-]*) ;; *) usage ;; esac
case "$image" in *.dkr.ecr.ap-northeast-2.amazonaws.com/node-operator-baseline-validator-runtime-web3signer@sha256:????????????????????????????????????????????????????????????????) ;; *) usage ;; esac
case "$approval_id" in [a-zA-Z0-9][a-zA-Z0-9._:-]*) ;; *) usage ;; esac
case "$output_dir" in /*) ;; *) usage ;; esac
for command in kubectl jq mkdir chmod date sleep; do command -v "$command" >/dev/null 2>&1 || { printf 'missing command: %s\n' "$command" >&2; exit 69; }; done

namespace=validator-operations
signer="validator-${validator_set}-remote-signer"
client="validator-${validator_set}-client"
database="validator-${validator_set}-slashing-db"
lease="validator-${validator_set}-primary"
pvc="data-${database}-0"

client_replicas="$(kubectl -n "$namespace" get deployment "$client" --ignore-not-found -o jsonpath='{.spec.replicas}')"
[ -z "$client_replicas" ] || [ "$client_replicas" = 0 ] || { printf '%s\n' 'validator client is not fenced at zero replicas' >&2; exit 65; }
pvc_phase="$(kubectl -n "$namespace" get pvc "$pvc" -o jsonpath='{.status.phase}')"
[ "$pvc_phase" = Bound ] || { printf '%s\n' 'retained slashing DB PVC is not Bound' >&2; exit 65; }
pvc_set="$(kubectl -n "$namespace" get pvc "$pvc" -o jsonpath='{.metadata.labels.node-operator\.io/validator-set}')"
[ "$pvc_set" = "$validator_set" ] || { printf '%s\n' 'slashing DB PVC validator-set does not match requested migration' >&2; exit 65; }

if [ "$dry_run" = true ]; then
  printf '%s\n' 'PASS: slashing DB migration gate passed; signer/client remain unchanged.'
  exit 0
fi

# Quiesce signing before touching durable slashing state. No delete is issued.
kubectl -n "$namespace" scale deployment "$signer" --replicas=0 >/dev/null
for attempt in $(seq 1 60); do
  [ -z "$(kubectl -n "$namespace" get pods -l "app.kubernetes.io/component=validator-remote-signer,node-operator.io/validator-set=${validator_set}" -o name)" ] && break
  sleep 1
done
[ -z "$(kubectl -n "$namespace" get pods -l "app.kubernetes.io/component=validator-remote-signer,node-operator.io/validator-set=${validator_set}" -o name)" ] || { printf '%s\n' 'remote signer did not quiesce; migration refused' >&2; exit 65; }

# The target, reviewed image supplies the exact PostgreSQL migration files.
# Updating only this init container restarts the DB with its retained PVC.
kubectl -n "$namespace" set image statefulset/"$database" stage-web3signer-postgres-migrations="$image" >/dev/null
kubectl -n "$namespace" rollout status statefulset/"$database" --timeout=180s >/dev/null
pod="$(kubectl -n "$namespace" get pod "${database}-0" -o jsonpath='{.metadata.name}')"
version="$(kubectl -n "$namespace" exec "$pod" -c postgres -- sh -ec 'export PGPASSWORD="$(cat /vault/secrets/postgres-password)"; exec psql -Atq -U web3signer -d web3signer -c "SELECT version FROM database_version WHERE id = 1"')"
case "$version" in
  10)
    kubectl -n "$namespace" exec "$pod" -c postgres -- sh -ec 'export PGPASSWORD="$(cat /vault/secrets/postgres-password)"; exec psql -v ON_ERROR_STOP=1 -U web3signer -d web3signer -f /docker-entrypoint-initdb.d/V00011__bigint_indexes.sql -f /docker-entrypoint-initdb.d/V00012__add_highwatermark_metadata.sql' >/dev/null
    ;;
  12) ;;
  *) printf 'unsupported slashing DB version: %s\n' "$version" >&2; exit 65 ;;
esac
version_after="$(kubectl -n "$namespace" exec "$pod" -c postgres -- sh -ec 'export PGPASSWORD="$(cat /vault/secrets/postgres-password)"; exec psql -Atq -U web3signer -d web3signer -c "SELECT version FROM database_version WHERE id = 1"')"
[ "$version_after" = 12 ] || { printf '%s\n' 'slashing DB migration did not reach version 12' >&2; exit 65; }

# Release the stale start lease only after the durable migration is verified.
holder="$(kubectl -n "$namespace" get lease "$lease" -o jsonpath='{.spec.holderIdentity}')"
if [ -n "$holder" ]; then
  now="$(date -u +%Y-%m-%dT%H:%M:%S.000000Z)"
  patch="$(jq -cn --arg holder "$holder" --arg now "$now" '[{op:"test",path:"/spec/holderIdentity",value:$holder},{op:"replace",path:"/spec/holderIdentity",value:""},{op:"replace",path:"/spec/renewTime",value:$now}]')"
  kubectl -n "$namespace" patch lease "$lease" --type=json -p "$patch" >/dev/null
fi

mkdir -p "$output_dir"; chmod 700 "$output_dir"; output_dir="$(cd "$output_dir" && pwd -P)"
record="$output_dir/slashing-db-migration-$(date -u +%Y%m%dT%H%M%SZ).json"
jq -n --arg collected "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --arg approval "$approval_id" --arg set "$validator_set" --arg image "$image" --arg pvc "$pvc" --arg before "$version" --arg after "$version_after" \
  '{schema_version:1,event_type:"slashing-db-migration",collected_at_utc:$collected,network:"hoodi",validator_set:$set,source:"kubernetes",payload:{migration_approval_id:$approval,web3signer_image:$image,slashing_db_pvc:$pvc,slashing_db_version_before:($before|tonumber),slashing_db_version_after:($after|tonumber),signer_fenced:true,client_fenced:true}}' > "$record"
printf 'PASS: slashing DB migrated to version 12; signer/client remain fenced. Evidence: %s\n' "$record"
