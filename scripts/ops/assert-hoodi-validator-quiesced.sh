#!/usr/bin/env bash
# Read-only live gate. Historical fence evidence alone is not a stop guarantee.
set -euo pipefail
usage() { printf 'Usage: %s --validator-set <hoodi-id>\n' "${0##*/}" >&2; exit 64; }
[ "$#" -eq 2 ] && [ "$1" = --validator-set ] || usage
validator_set="$2"
[[ "$validator_set" =~ ^hoodi-[a-z0-9][a-z0-9-]{0,35}$ ]] || usage
namespace=validator-operations
client="validator-$validator_set-client"
fence="validator-$validator_set-signing-fence"
kubectl -n "$namespace" get statefulset "$client" -o json | jq -e '
  .spec.replicas == 0 and (.status.replicas // 0) == 0 and
  (.status.readyReplicas // 0) == 0 and
  (.status.observedGeneration // 0) >= .metadata.generation' >/dev/null
kubectl -n "$namespace" get deployment "$fence" -o json | jq -e '
  .spec.replicas == 0 and (.status.replicas // 0) == 0 and
  (.status.readyReplicas // 0) == 0 and
  (.status.observedGeneration // 0) >= .metadata.generation' >/dev/null
# Include terminating Pods: a deletion timestamp does not prove signing stopped.
kubectl -n "$namespace" get pods -o json | jq -e --arg set "$validator_set" --arg client "$client" --arg fence "$fence" '
  [.items[] | select(
    (.metadata.name | startswith($client + "-")) or
    (.metadata.name | startswith($fence + "-")) or
    (.metadata.labels["node-operator.io/validator-set"] == $set and
      (.metadata.labels["app.kubernetes.io/component"] == "validator-client" or
       .metadata.labels["app.kubernetes.io/component"] == "validator-signing-fence")))] | length == 0' >/dev/null
printf '%s\n' 'PASS: live validator client and signing fence are quiesced; no remaining Pods.'
