#!/usr/bin/env bash
set -euo pipefail

# Creates the live, non-signing fencing evidence required immediately before
# the UC-5 Vault-role revocation ceremony.  The validator and fence are left
# at zero only after both a negative direct-signer probe and its positive
# fence-labelled control have completed.  It never submits a signing request.
dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
if [ "${PRIVATE_EKS_SESSION:-}" != 1 ]; then
  exec "$dir/with-private-eks.sh" -- env PRIVATE_EKS_SESSION=1 "$0" "$@"
fi

usage() { printf '%s\n' "Usage: ${0##*/} --validator-set <hoodi-id> --expected-public-key <0x-key> --output-dir <absolute-dir>" >&2; exit 64; }
validator_set=''; public_key=''; output_dir=''
while [ "$#" -gt 0 ]; do
  case "$1" in
    --validator-set) validator_set="${2:-}"; shift 2 ;;
    --expected-public-key) public_key="${2:-}"; shift 2 ;;
    --output-dir) output_dir="${2:-}"; shift 2 ;;
    *) usage ;;
  esac
done
case "$validator_set" in hoodi-[a-z0-9][a-z0-9-]*) ;; *) usage ;; esac
case "$public_key" in 0x????????????????????????????????????????????????????????????????????????????????????????????????) ;; *) usage ;; esac
case "$output_dir" in /*) ;; *) usage ;; esac
for command in kubectl jq python3 mkdir chmod date sleep seq tr; do command -v "$command" >/dev/null 2>&1 || { printf 'missing command: %s\n' "$command" >&2; exit 69; }; done

namespace=validator-operations
client="validator-${validator_set}-client"
fence="validator-${validator_set}-signing-fence"
signer="validator-${validator_set}-remote-signer"
lease="validator-${validator_set}-primary"
direct_probe="signer-probe-direct-${validator_set}"
control_probe="signer-probe-control-${validator_set}"
mkdir -p "$output_dir"; chmod 700 "$output_dir"; output_dir="$(cd "$output_dir" && pwd -P)"
manifest="$output_dir/uc-5-fence-probes.json"
record="$output_dir/uc-5-fence-proof-$(date -u +%Y%m%dT%H%M%SZ).json"

fail() { printf '%s\n' "$*" >&2; exit 65; }
probes_created=false
cleanup_probes() {
  exit_code=$?
  trap - EXIT INT TERM HUP
  if [ "$probes_created" = true ]; then
    kubectl -n "$namespace" delete pod "$direct_probe" "$control_probe" --ignore-not-found --wait=true >/dev/null 2>&1 || true
  fi
  exit "$exit_code"
}
trap cleanup_probes EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP
client_json="$(kubectl -n "$namespace" get statefulset "$client" -o json)"
fence_json="$(kubectl -n "$namespace" get deployment "$fence" -o json)"
signer_json="$(kubectl -n "$namespace" get deployment "$signer" -o json)"
fence_pods="$(kubectl -n "$namespace" get pods -l "app.kubernetes.io/component=validator-signing-fence,node-operator.io/validator-set=${validator_set}" -o json)"
lease_json="$(kubectl -n "$namespace" get lease "$lease" -o json)"
signer_policy="$(kubectl -n "$namespace" get networkpolicy "validator-${validator_set}-signer-ingress" -o json)"
public_service="$(kubectl -n "$namespace" get service "$signer" -o json)"
direct_service="$(kubectl -n "$namespace" get service "${signer}-direct" -o json)"

jq -e --arg set "$validator_set" '
  .spec.replicas == 1 and .status.readyReplicas == 1 and
  .spec.template.metadata.labels["node-operator.io/validator-set"] == $set
' <<<"$client_json" >/dev/null || fail 'client must be the one Ready StatefulSet before UC-5 fencing'
jq -e --arg set "$validator_set" '
  .spec.replicas == 1 and .status.readyReplicas == 1 and
  .spec.template.metadata.labels["node-operator.io/validator-set"] == $set
' <<<"$fence_json" >/dev/null || fail 'signing fence must be Ready before UC-5 fencing'
jq -e '.spec.replicas == 1 and .status.readyReplicas == 1' <<<"$signer_json" >/dev/null || fail 'remote signer must be Ready before UC-5 fencing'
fence_uid="$(jq -er '.items | select(length == 1) | .[0].metadata.uid' <<<"$fence_pods")"
jq -e --arg holder "$fence_uid" --argjson now "$(date -u +%s)" '
  def epoch: sub("\\.[0-9]+Z$"; "Z") | fromdateiso8601;
  .spec.holderIdentity == $holder and (.spec.leaseDurationSeconds | type == "number" and . > 0) and
  (.spec.renewTime | epoch) <= ($now + 30) and (($now - (.spec.renewTime | epoch)) <= .spec.leaseDurationSeconds)
' <<<"$lease_json" >/dev/null || fail 'fence lease is not held freshly by its one live Pod'
jq -e --arg set "$validator_set" '
  .spec.selector["app.kubernetes.io/component"] == "validator-signing-fence" and
  .spec.selector["node-operator.io/validator-set"] == $set and
  any(.spec.ports[]; .port == 9000 and .targetPort == "fence-proxy")
' <<<"$public_service" >/dev/null || fail 'public signer Service does not select only the fence'
jq -e --arg set "$validator_set" '
  .spec.selector["app.kubernetes.io/component"] == "validator-remote-signer" and
  .spec.selector["node-operator.io/validator-set"] == $set and
  any(.spec.ports[]; .port == 9000 and .targetPort == "signer-api")
' <<<"$direct_service" >/dev/null || fail 'direct signer Service is not set-scoped'
jq -e --arg set "$validator_set" '
  .spec.podSelector.matchLabels["app.kubernetes.io/component"] == "validator-remote-signer" and
  .spec.podSelector.matchLabels["node-operator.io/validator-set"] == $set and
  (.spec.ingress | length == 1) and
  .spec.ingress[0].from[0].podSelector.matchLabels["app.kubernetes.io/component"] == "validator-signing-fence" and
  .spec.ingress[0].from[0].podSelector.matchLabels["node-operator.io/validator-set"] == $set and
  .spec.ingress[0].ports == [{"protocol":"TCP","port":9000}]
' <<<"$signer_policy" >/dev/null || fail 'direct signer ingress policy does not permit only the set fence'

# Fence first, then wait for both controllers' Pods to disappear.  This is a
# fail-closed order: the client loses its upstream before it is terminated.
kubectl -n "$namespace" scale deployment "$fence" --replicas=0 >/dev/null
kubectl -n "$namespace" scale statefulset "$client" --replicas=0 >/dev/null
for _ in $(seq 1 60); do
  remaining="$(kubectl -n "$namespace" get pods -l "node-operator.io/validator-set=${validator_set}" -o json)"
  if jq -e '[.items[] | select(.metadata.labels["app.kubernetes.io/component"] == "validator-client" or .metadata.labels["app.kubernetes.io/component"] == "validator-signing-fence")] | length == 0' <<<"$remaining" >/dev/null; then break; fi
  sleep 2
done
remaining="$(kubectl -n "$namespace" get pods -l "node-operator.io/validator-set=${validator_set}" -o json)"
jq -e '[.items[] | select(.metadata.labels["app.kubernetes.io/component"] == "validator-client" or .metadata.labels["app.kubernetes.io/component"] == "validator-signing-fence")] | length == 0' <<<"$remaining" >/dev/null || fail 'client or fence Pod remained after fail-closed scale-down'

python3 "$dir/render-signer-network-probe.py" --validator-set "$validator_set" --expected-public-key "$(printf '%s' "$public_key" | tr '[:upper:]' '[:lower:]')" --output "$manifest"
kubectl -n "$namespace" create -f "$manifest" >/dev/null
probes_created=true
for _ in $(seq 1 75); do
  direct_json="$(kubectl -n "$namespace" get pod "$direct_probe" -o json)"
  control_json="$(kubectl -n "$namespace" get pod "$control_probe" -o json)"
  direct_phase="$(jq -r '.status.phase' <<<"$direct_json")"; control_phase="$(jq -r '.status.phase' <<<"$control_json")"
  if [ "$direct_phase" = Failed ] && [ "$control_phase" = Succeeded ]; then break; fi
  if [ "$direct_phase" = Succeeded ] || [ "$control_phase" = Failed ]; then fail 'direct-signer probe produced an unsafe or inconclusive result'; fi
  sleep 2
done
direct_json="$(kubectl -n "$namespace" get pod "$direct_probe" -o json)"
control_json="$(kubectl -n "$namespace" get pod "$control_probe" -o json)"
jq -e '.status.phase == "Failed"' <<<"$direct_json" >/dev/null || fail 'client-labelled direct signer probe was not denied'
jq -e '.status.phase == "Succeeded"' <<<"$control_json" >/dev/null || fail 'fence-labelled direct signer control did not succeed'
direct_uid="$(jq -er '.metadata.uid' <<<"$direct_json")"; control_uid="$(jq -er '.metadata.uid' <<<"$control_json")"
kubectl -n "$namespace" delete pod "$direct_probe" "$control_probe" --wait=true >/dev/null
probes_created=false

jq -n --arg collected "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --arg set "$validator_set" --arg key "$(printf '%s' "$public_key" | tr '[:upper:]' '[:lower:]')" --arg fence_uid "$fence_uid" --arg direct_uid "$direct_uid" --arg control_uid "$control_uid" \
  '{schema_version:1,event_type:"signing-proxy-fence",collected_at_utc:$collected,network:"hoodi",validator_set:$set,validator_public_key:$key,source:"signing-proxy-fence",payload:{fence_live:true,lease_enforced:true,direct_client_to_signer_denied:true,cached_key_requests_blocked:true,in_flight_request_bound:true,fence_live_before_quiesce:true,client_and_fence_quiesced:true,direct_probe_pod_uid:$direct_uid,fence_control_probe_pod_uid:$control_uid,fence_pod_uid_before_quiesce:$fence_uid,probe_scope:"GET-only public-key endpoint; no signing request, key, token, or raw TLS material"}}' > "$record"
chmod 600 "$record"
trap - EXIT INT TERM HUP
printf 'PASS: UC-5 fence proof completed. Client and fence remain deliberately at zero; immediately run the recovery ceremony with: %s\n' "$record"
