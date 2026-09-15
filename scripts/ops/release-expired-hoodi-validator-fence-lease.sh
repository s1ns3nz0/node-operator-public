#!/usr/bin/env bash
set -euo pipefail

dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
if [ "${PRIVATE_EKS_SESSION:-}" != 1 ]; then
  exec "$dir/with-private-eks.sh" -- env PRIVATE_EKS_SESSION=1 "$0" "$@"
fi

usage() { printf '%s\n' "Usage: ${0##*/} --validator-set <hoodi-id> --expected-lease-uid <uid> --expected-resource-version <rv> --expected-holder <holder> --expected-pvc-uid <uid> --maintenance-approval-id <id> --output-dir <absolute-dir> [--dry-run]" >&2; exit 64; }
validator_set=''; expected_lease_uid=''; expected_resource_version=''; expected_holder=''; expected_pvc_uid=''; approval_id=''; output_dir=''; dry_run=false
while [ "$#" -gt 0 ]; do case "$1" in
  --validator-set) validator_set="${2:-}"; shift 2 ;; --expected-lease-uid) expected_lease_uid="${2:-}"; shift 2 ;;
  --expected-resource-version) expected_resource_version="${2:-}"; shift 2 ;; --expected-holder) expected_holder="${2:-}"; shift 2 ;;
  --expected-pvc-uid) expected_pvc_uid="${2:-}"; shift 2 ;; --maintenance-approval-id) approval_id="${2:-}"; shift 2 ;;
  --output-dir) output_dir="${2:-}"; shift 2 ;; --dry-run) dry_run=true; shift ;; *) usage ;; esac; done
case "$validator_set" in hoodi-[a-z0-9][a-z0-9-]*) ;; *) usage ;; esac
for value in "$expected_lease_uid" "$expected_resource_version" "$expected_holder" "$expected_pvc_uid" "$approval_id"; do case "$value" in [a-zA-Z0-9][a-zA-Z0-9._:-]*) ;; *) usage ;; esac; done
case "$output_dir" in /*) ;; *) usage ;; esac
for command in kubectl jq date mkdir chmod mktemp mv unlink; do command -v "$command" >/dev/null 2>&1 || { printf 'missing command: %s\n' "$command" >&2; exit 69; }; done

namespace=validator-operations; client="validator-${validator_set}-client"; fence="validator-${validator_set}-signing-fence"; signer="validator-${validator_set}-remote-signer"
lease="validator-${validator_set}-primary"; pvc="data-validator-${validator_set}-slashing-db-0"
quiescence_snapshot() {
  # --ignore-not-found yields empty output only for an explicit NotFound; API/RBAC
  # errors still return nonzero and must never be treated as absence.
  stateful_json="$(kubectl -n "$namespace" get statefulset "$client" --ignore-not-found -o json)" || return 69
  fence_json="$(kubectl -n "$namespace" get deployment "$fence" --ignore-not-found -o json)" || return 69
  signer_json="$(kubectl -n "$namespace" get deployment "$signer" -o json)" || return 69
  pods_json="$(kubectl -n "$namespace" get pods -l "app.kubernetes.io/component in (validator-client,validator-remote-signer,validator-signing-fence),node-operator.io/validator-set=${validator_set}" -o json)" || return 69
  pvc_json="$(kubectl -n "$namespace" get pvc "$pvc" -o json)" || return 69
  for controller in "$stateful_json" "$fence_json"; do
    [ -z "$controller" ] || jq -e --arg set "$validator_set" '.metadata.deletionTimestamp == null and .spec.replicas == 0 and .spec.selector.matchLabels["node-operator.io/validator-set"] == $set and .spec.template.metadata.labels["node-operator.io/validator-set"] == $set' <<<"$controller" >/dev/null || return 65
  done
  jq -e --arg name "$signer" --arg set "$validator_set" '.metadata.name == $name and .metadata.deletionTimestamp == null and .spec.replicas == 0 and .spec.selector.matchLabels["node-operator.io/validator-set"] == $set and .spec.template.metadata.labels["node-operator.io/validator-set"] == $set' <<<"$signer_json" >/dev/null || return 65
  jq -e '.items | type == "array" and length == 0' <<<"$pods_json" >/dev/null || return 65
  jq -e --arg name "$pvc" --arg uid "$expected_pvc_uid" '.metadata.name == $name and .metadata.uid == $uid and .metadata.deletionTimestamp == null and .status.phase == "Bound" and .spec.resources.requests.storage == "50Gi"' <<<"$pvc_json" >/dev/null || return 65
}

quiescence_snapshot || { status=$?; printf '%s\n' 'cannot prove exact zero-controller, zero-Pod, retained-PVC state' >&2; exit "$status"; }
lease_json="$(kubectl -n "$namespace" get lease "$lease" -o json)" || { printf '%s\n' 'cannot read signing-fence Lease' >&2; exit 69; }
now_epoch="$(date -u +%s)"
jq -e --arg name "$lease" --arg uid "$expected_lease_uid" --arg rv "$expected_resource_version" --arg holder "$expected_holder" --argjson now "$now_epoch" '
  def epoch:
    if type != "string" or (test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\\.[0-9]{1,9})?Z$") | not) then error("invalid MicroTime") else
      . as $raw | (sub("\\.[0-9]+Z$"; "Z")) as $whole | ($whole | fromdateiso8601) as $parsed |
      if ($parsed | strftime("%Y-%m-%dT%H:%M:%SZ")) == $whole then $parsed else error("non-roundtrip MicroTime") end
    end;
  (.spec.renewTime | epoch) as $renewed | .spec.leaseDurationSeconds as $duration |
  .metadata.name == $name and
  .metadata.uid == $uid and .metadata.resourceVersion == $rv and .spec.holderIdentity == $holder and ($holder | length) > 0 and
  ($duration | type == "number" and . >= 1 and . <= 300 and floor == .) and $renewed <= $now and $now >= ($renewed + $duration + 5)
' <<<"$lease_json" >/dev/null || { printf '%s\n' 'Lease identity is mismatched, live, future-dated, malformed, or not safely expired' >&2; exit 65; }
renew_time="$(jq -er '.spec.renewTime' <<<"$lease_json")"; duration="$(jq -er '.spec.leaseDurationSeconds' <<<"$lease_json")"
if [ "$dry_run" = true ]; then printf '%s\n' 'PASS: expired Lease handover preflight passed; no Lease or workload changed.'; exit 0; fi

# Reserve a unique, writable evidence destination before the one mutation.
mkdir -p "$output_dir" || { printf '%s\n' 'cannot create evidence directory' >&2; exit 69; }
[ ! -L "$output_dir" ] || { printf '%s\n' 'evidence directory must not be a symlink' >&2; exit 69; }
chmod 700 "$output_dir" || { printf '%s\n' 'cannot protect evidence directory' >&2; exit 69; }
output_dir="$(cd "$output_dir" && pwd -P)" || { printf '%s\n' 'cannot resolve evidence directory' >&2; exit 69; }
temporary="$(mktemp "$output_dir/.uc-5-lease-handover.XXXXXX")" || { printf '%s\n' 'cannot reserve evidence destination' >&2; exit 69; }
suffix="${temporary##*.}"; record="$output_dir/uc-5-lease-handover-$(date -u +%Y%m%dT%H%M%SZ)-${suffix}.json"
[ ! -e "$record" ] && [ ! -L "$record" ] || { unlink "$temporary" 2>/dev/null || true; printf '%s\n' 'unique evidence destination already exists' >&2; exit 69; }
cleanup() { set +e; [ -z "${temporary:-}" ] || [ ! -e "$temporary" ] || unlink "$temporary" 2>/dev/null || true; }
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# Re-read cross-object prerequisites immediately before CAS. This narrows but
# cannot eliminate races; callers must hold an exclusive reviewed GitOps pause.
quiescence_snapshot || { status=$?; printf '%s\n' 'quiescence changed before Lease release' >&2; exit "$status"; }
patch="$(jq -cn --arg uid "$expected_lease_uid" --arg rv "$expected_resource_version" --arg holder "$expected_holder" --arg renewed "$renew_time" --argjson duration "$duration" '[{op:"test",path:"/metadata/uid",value:$uid},{op:"test",path:"/metadata/resourceVersion",value:$rv},{op:"test",path:"/spec/holderIdentity",value:$holder},{op:"test",path:"/spec/renewTime",value:$renewed},{op:"test",path:"/spec/leaseDurationSeconds",value:$duration},{op:"replace",path:"/spec/holderIdentity",value:""}]')"
kubectl -n "$namespace" patch lease "$lease" --type=json -p "$patch" >/dev/null || { printf '%s\n' 'Lease release CAS failed; no retry or forced reclaim was attempted' >&2; exit 75; }
readback="$(kubectl -n "$namespace" get lease "$lease" -o json)" || { printf '%s\n' 'CRITICAL: Lease changed but readback failed' >&2; exit 70; }
jq -e --arg name "$lease" --arg uid "$expected_lease_uid" --arg old_rv "$expected_resource_version" --arg renewed "$renew_time" --argjson duration "$duration" '.metadata.name == $name and .metadata.uid == $uid and .metadata.resourceVersion != $old_rv and (.metadata.resourceVersion | length) > 0 and .spec.holderIdentity == "" and .spec.renewTime == $renewed and .spec.leaseDurationSeconds == $duration' <<<"$readback" >/dev/null || { printf '%s\n' 'CRITICAL: Lease release readback did not match the exact CAS result' >&2; exit 70; }

new_resource_version="$(jq -er '.metadata.resourceVersion' <<<"$readback")" || { printf '%s\n' 'CRITICAL: cannot extract post-CAS resourceVersion' >&2; exit 70; }
jq -n --arg collected "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --arg set "$validator_set" --arg approval "$approval_id" --arg lease_uid "$expected_lease_uid" --arg old_rv "$expected_resource_version" --arg new_rv "$new_resource_version" --arg old_holder "$expected_holder" --arg pvc_uid "$expected_pvc_uid" '{schema_version:1,event_type:"uc-5-lease-handover",collected_at_utc:$collected,network:"hoodi",validator_set:$set,source:"kubernetes-cas",payload:{maintenance_approval_id:$approval,exclusive_gitops_pause_attested:true,lease_uid:$lease_uid,old_resource_version:$old_rv,new_resource_version:$new_rv,old_holder:$old_holder,new_holder:"",retained_pvc_uid:$pvc_uid,controllers_desired_zero:true,pods_absent:true,uc5_complete:false}}' > "$temporary" || { printf '%s\n' 'CRITICAL: Lease released but evidence serialization failed' >&2; exit 70; }
mv "$temporary" "$record" || { printf '%s\n' 'CRITICAL: Lease released but evidence publication failed' >&2; exit 70; }
temporary=''; printf 'PASS: expired signing-fence Lease released by exact CAS. Evidence: %s\n' "$record"
