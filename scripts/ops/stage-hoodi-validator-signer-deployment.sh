#!/usr/bin/env bash
# Stages only a reviewed signer Deployment template.  It never starts workloads.
set -euo pipefail
dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
self="$dir/${BASH_SOURCE[0]##*/}"
usage() { printf '%s\n' "Usage: ${0##*/} --validator-set hoodi-X --desired-deployment /absolute/file.json --expected-deployment-uid UID --expected-pvc-uid UID --maintenance-approval-id ID [--dry-run]" >&2; exit 64; }
set_name=''; desired=''; expected_uid=''; expected_pvc_uid=''; approval=''; dry=false
original_args=("$@")
while [ "$#" -gt 0 ]; do case "$1" in
  --validator-set) set_name="${2:-}"; shift 2;; --desired-deployment) desired="${2:-}"; shift 2;;
  --expected-deployment-uid) expected_uid="${2:-}"; shift 2;; --expected-pvc-uid) expected_pvc_uid="${2:-}"; shift 2;;
  --maintenance-approval-id) approval="${2:-}"; shift 2;; --dry-run) dry=true; shift;; *) usage;; esac; done
case "$set_name" in hoodi-[a-z0-9-]*) ;; *) usage;; esac
case "$desired" in /*) [ -f "$desired" ] || usage;; *) usage;; esac
for value in "$expected_uid" "$expected_pvc_uid" "$approval"; do case "$value" in [A-Za-z0-9][A-Za-z0-9._:-]*) ;; *) usage;; esac; done
command -v jq >/dev/null 2>&1 || { printf '%s\n' 'missing jq' >&2; exit 69; }
desired_json="$(jq -ce . "$desired")" || { printf '%s\n' 'desired deployment JSON is invalid' >&2; exit 65; }
if [ "${PRIVATE_EKS_SESSION:-}" != 1 ]; then exec "$dir/with-private-eks.sh" -- env PRIVATE_EKS_SESSION=1 "$self" "${original_args[@]}"; fi
command -v kubectl >/dev/null 2>&1 || { printf '%s\n' 'missing kubectl' >&2; exit 69; }
namespace=validator-operations; signer="validator-${set_name}-remote-signer"; lease="validator-${set_name}-primary"; pvc="data-validator-${set_name}-slashing-db-0"
fail() { printf '%s\n' "$1" >&2; exit "${2:-65}"; }
# Prerequisite: exclusive maintenance and a paused GitOps reconciler.  This
# operation cannot make cross-object reads and a later patch atomic.
jq -e --arg name "$signer" --arg ns "$namespace" --arg set "$set_name" '
  .apiVersion == "apps/v1" and .kind == "Deployment" and (.metadata.name == $name) and
  (.metadata.namespace == $ns) and (.spec.selector.matchLabels["node-operator.io/validator-set"] == $set) and
  (.spec.replicas == 0) and (.spec.template.metadata.labels["node-operator.io/validator-set"] == $set) and
  (.spec.template.spec.containers | type) == "array" and (.spec.template.spec.containers | length == 1) and
  (.spec.template.spec.containers[0].name == "web3signer") and
  (.spec.template.spec.containers[0].image | test("^123456789012\\.dkr\\.ecr\\.ap-northeast-2\\.amazonaws\\.com/node-operator-baseline-validator-runtime-web3signer@sha256:[a-f0-9]{64}$")) and
  ((.spec.template.spec.initContainers // []) | type == "array" and length == 0)' <<<"$desired_json" >/dev/null || fail 'desired is not the exact zero-replica reviewed Web3Signer ECR Deployment'
current="$(kubectl -n "$namespace" get deployment "$signer" -o json)" || fail 'cannot read target Deployment' 69
jq -e --arg uid "$expected_uid" --arg set "$set_name" '.metadata.uid == $uid and .spec.replicas == 0 and .spec.selector.matchLabels["node-operator.io/validator-set"] == $set and .spec.template.metadata.labels["node-operator.io/validator-set"] == $set' <<<"$current" >/dev/null || fail 'target Deployment UID, set, selector, template labels, or replicas precondition failed'
jq -e --argjson want "$desired_json" '(.spec.selector == $want.spec.selector) and (.metadata.name == $want.metadata.name) and (.metadata.namespace == $want.metadata.namespace)' <<<"$current" >/dev/null || fail 'desired changes immutable Deployment identity or selector'
controllers="$(kubectl -n "$namespace" get deployments,statefulsets -o json)" || fail 'cannot prove controllers are stopped' 69
jq -e --arg set "$set_name" '(.items | type) == "array" and ([.items[] | select((.metadata.labels["node-operator.io/validator-set"] == $set or .spec.selector.matchLabels["node-operator.io/validator-set"] == $set or .spec.template.metadata.labels["node-operator.io/validator-set"] == $set) and (.metadata.labels["app.kubernetes.io/component"] == "validator-client" or .metadata.labels["app.kubernetes.io/component"] == "validator-remote-signer" or .metadata.labels["app.kubernetes.io/component"] == "validator-signing-fence" or .spec.template.metadata.labels["app.kubernetes.io/component"] == "validator-client" or .spec.template.metadata.labels["app.kubernetes.io/component"] == "validator-remote-signer" or .spec.template.metadata.labels["app.kubernetes.io/component"] == "validator-signing-fence")) | select((.spec.replicas // 1) != 0)] | length == 0)' <<<"$controllers" >/dev/null || fail 'a set client, signer, or fence controller is not scaled to zero'
pods="$(kubectl -n "$namespace" get pods -o json)" || fail 'cannot prove Pods are absent' 69
jq -e --arg set "$set_name" '(.items | type) == "array" and ([.items[] | select(.metadata.labels["node-operator.io/validator-set"] == $set and (.metadata.labels["app.kubernetes.io/component"] == "validator-client" or .metadata.labels["app.kubernetes.io/component"] == "validator-remote-signer" or .metadata.labels["app.kubernetes.io/component"] == "validator-signing-fence"))] | length == 0)' <<<"$pods" >/dev/null || fail 'set client, signer, or fence Pod remains'
holder="$(kubectl -n "$namespace" get lease "$lease" -o json)" || fail 'cannot read signer Lease' 69
jq -e '(.spec.holderIdentity // "") == ""' <<<"$holder" >/dev/null || fail 'Lease holder is nonempty; use the guarded handover procedure first'
pvc_json="$(kubectl -n "$namespace" get pvc "$pvc" -o json)" || fail 'cannot read retained slashing PVC' 69
jq -e --arg uid "$expected_pvc_uid" '.metadata.uid == $uid and .metadata.deletionTimestamp == null and .status.phase == "Bound" and (.spec.volumeName | type == "string" and length > 0)' <<<"$pvc_json" >/dev/null || fail 'retained slashing PVC UID or binding precondition failed'
pv_name="$(jq -r '.spec.volumeName' <<<"$pvc_json")"
pv_json="$(kubectl get pv "$pv_name" -o json)" || fail 'cannot read retained slashing PV' 69
jq -e --arg name "$pvc" --arg ns "$namespace" --arg uid "$expected_pvc_uid" '.status.phase == "Bound" and .spec.claimRef.namespace == $ns and .spec.claimRef.name == $name and .spec.claimRef.uid == $uid' <<<"$pv_json" >/dev/null || fail 'retained slashing PV does not bind the expected PVC identity'
old_rv="$(jq -r '.metadata.resourceVersion' <<<"$current")"; [ -n "$old_rv" ] && [ "$old_rv" != null ] || fail 'target Deployment resourceVersion is empty'; template="$(jq -c '.spec.template' <<<"$desired_json")"
patch="$(jq -cn --arg uid "$expected_uid" --arg rv "$old_rv" --argjson template "$template" '[{op:"test",path:"/metadata/uid",value:$uid},{op:"test",path:"/metadata/resourceVersion",value:$rv},{op:"test",path:"/spec/replicas",value:0},{op:"replace",path:"/spec/template",value:$template}]')"
preview="$(kubectl -n "$namespace" patch deployment "$signer" --type=json -p "$patch" --dry-run=server -o json)" || fail 'server-side Deployment template preview CAS failed; no mutation was attempted' 70
canonical_template="$(jq -ce --arg uid "$expected_uid" 'if .metadata.uid == $uid and .spec.replicas == 0 and (.spec.template | type) == "object" then .spec.template else empty end' <<<"$preview")" || fail 'CRITICAL: server-side preview did not preserve UID and zero replicas' 70
if "$dry"; then printf 'dry-run: Deployment template preconditions passed; no mutation made (approval=%s)\n' "$approval"; exit 0; fi
kubectl -n "$namespace" patch deployment "$signer" --type=json -p "$patch" >/dev/null || fail 'CRITICAL: Deployment template CAS failed; no retry or rollback was attempted' 70
readback="$(kubectl -n "$namespace" get deployment "$signer" -o json)" || fail 'CRITICAL: Deployment changed but readback failed' 70
jq -e --arg uid "$expected_uid" --arg old "$old_rv" --argjson template "$canonical_template" '.metadata.uid == $uid and .metadata.resourceVersion != $old and .spec.replicas == 0 and .spec.template == $template' <<<"$readback" >/dev/null || fail 'CRITICAL: Deployment readback does not match staged template with replicas zero' 70
printf 'staged signer Deployment template only (approval=%s); replicas remain zero\n' "$approval"
