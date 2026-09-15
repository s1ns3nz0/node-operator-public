#!/usr/bin/env bash
set -euo pipefail

# This is the only client scale-up path. It is intentionally interactive in
# the sense that the caller must repeat public key and withdrawal address; it
# neither reaches a wallet nor accepts any secret value.
usage() { printf '%s\n' "Usage: ${0##*/} --validator-set <hoodi-id> --deposit-attestation <absolute-json> --public-deposit-verification <absolute-json> --private-evidence <absolute-json> --signer-evidence <absolute-json> --confirm-public-key <0x-key> --confirm-withdrawal-address <0x-address> [--activation-receipt <absolute-new-json> --deployment-name <name> --release-revision <40-hex> --operation-id <32-hex>] [--dry-run]" >&2; exit 64; }
validator_set=''; deposit_attestation=''; public_deposit_verification=''; private_evidence=''; signer_evidence=''; public_key=''; withdrawal_address=''; dry_run=false
activation_receipt=''; deployment_name=''; release_revision=''; operation_id=''
while [ "$#" -gt 0 ]; do
  case "$1" in
    --validator-set) validator_set="${2:-}"; shift 2 ;;
    --deposit-attestation) deposit_attestation="${2:-}"; shift 2 ;;
    --public-deposit-verification) public_deposit_verification="${2:-}"; shift 2 ;;
    --private-evidence) private_evidence="${2:-}"; shift 2 ;;
    --signer-evidence) signer_evidence="${2:-}"; shift 2 ;;
    --confirm-public-key) public_key="${2:-}"; shift 2 ;;
    --confirm-withdrawal-address) withdrawal_address="${2:-}"; shift 2 ;;
    --activation-receipt) activation_receipt="${2:-}"; shift 2 ;;
    --deployment-name) deployment_name="${2:-}"; shift 2 ;;
    --release-revision) release_revision="${2:-}"; shift 2 ;;
    --operation-id) operation_id="${2:-}"; shift 2 ;;
    --dry-run) dry_run=true; shift ;;
    *) usage ;;
  esac
done
case "$validator_set" in hoodi-[a-z0-9][a-z0-9-]*) ;; *) usage ;; esac
[[ "$public_key" =~ ^0x[0-9a-fA-F]{96}$ ]] || usage
case "$withdrawal_address" in 0x????????????????????????????????????????) ;; *) usage ;; esac
case "$deposit_attestation" in /*) ;; *) usage ;; esac
case "$public_deposit_verification" in /*) ;; *) usage ;; esac
case "$private_evidence" in /*) ;; *) usage ;; esac
case "$signer_evidence" in /*) ;; *) usage ;; esac
receipt_arg_count=0
for value in "$activation_receipt" "$deployment_name" "$release_revision" "$operation_id"; do [ -z "$value" ] || receipt_arg_count=$((receipt_arg_count + 1)); done
if [ "$receipt_arg_count" -ne 0 ]; then
  [ "$receipt_arg_count" -eq 4 ] && [ "$dry_run" = false ] || usage
  case "$activation_receipt" in /*) ;; *) usage ;; esac
  [[ "$deployment_name" =~ ^[a-z][a-z0-9-]{1,38}[a-z0-9]$ ]] || usage
  [[ "$release_revision" =~ ^[a-f0-9]{40}$ ]] || usage
  [[ "$operation_id" =~ ^[a-f0-9]{32}$ ]] || usage
fi
for command in jq kubectl date tr; do command -v "$command" >/dev/null 2>&1 || { printf 'missing command: %s\n' "$command" >&2; exit 69; }; done
[ -r "$deposit_attestation" ] && [ -r "$public_deposit_verification" ] && [ -r "$private_evidence" ] && [ -r "$signer_evidence" ] || { printf '%s\n' 'activation evidence is not readable' >&2; exit 66; }

public_key="$(printf '%s' "$public_key" | tr '[:upper:]' '[:lower:]')"
expected_key="$(jq -r '.validator_public_key // empty' "$deposit_attestation" | tr '[:upper:]' '[:lower:]')"
expected_withdrawal="$(jq -r '.withdrawal_address // empty' "$deposit_attestation" | tr '[:upper:]' '[:lower:]')"
[ "$expected_key" = "$public_key" ] || { printf '%s\n' 'public-key confirmation does not match the deposit attestation' >&2; exit 65; }
[ "$expected_withdrawal" = "$(printf '%s' "$withdrawal_address" | tr '[:upper:]' '[:lower:]')" ] || { printf '%s\n' 'withdrawal-address confirmation does not match the deposit attestation' >&2; exit 65; }
confirmed_withdrawal="$(printf '%s' "$withdrawal_address" | tr '[:upper:]' '[:lower:]')"
jq -e --arg key "$public_key" --arg set "$validator_set" --arg withdrawal "0x010000000000000000000000${confirmed_withdrawal#0x}" '
  .network == "hoodi" and .chain_id == 560048 and .validator_set == $set and .validator_public_key == $key and
  .withdrawal_credentials == $withdrawal and .deposit_amount_gwei == 32000000000 and
  .receipt_status == "0x1" and .ssz_roots_match == true and .bls_signature_valid == true and
  .event_matches_public_file == true and .secret_material_accessed == false
' "$public_deposit_verification" >/dev/null || { printf '%s\n' 'public deposit proof is incomplete or identifies another validator' >&2; exit 65; }
now_epoch="$(date -u +%s)"
jq -e --arg key "$public_key" --arg set "$validator_set" --argjson now "$now_epoch" '
  def rfc3339_epoch:
    if type == "string" and test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\\.[0-9]+)?Z$")
    then sub("\\.[0-9]+Z$"; "Z") | fromdateiso8601
    else error("invalid UTC RFC3339 timestamp")
    end;
  (.collected_at_utc | rfc3339_epoch) as $observed |
  (.schema_version == 1 and .event_type == "uc-3" and .network == "hoodi" and
   .validator_set == $set and .source == "private-beacon" and .validator_public_key == $key and
   ($observed <= ($now + 30)) and (($now - $observed) <= 300) and
   (.payload.syncing.is_syncing == false) and
   (.payload.syncing.is_optimistic == false) and
   (.payload.syncing.el_offline == false) and
   (.payload.validator_http_status == "200") and
   (.payload.validator.status == "active_ongoing") and
   (.payload.validator.validator.pubkey == $key) and
   (.payload.validator.index | tostring | test("^[0-9]+$")))
' "$private_evidence" >/dev/null || { printf '%s\n' 'private Beacon evidence does not prove an active, synced validator' >&2; exit 65; }
jq -e --arg key "$public_key" --arg set "$validator_set" --argjson now "$now_epoch" '
  def rfc3339_epoch:
    if type == "string" and test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\\.[0-9]+)?Z$")
    then sub("\\.[0-9]+Z$"; "Z") | fromdateiso8601
    else error("invalid UTC RFC3339 timestamp")
    end;
  (.collected_at_utc | rfc3339_epoch) as $observed |
  (.schema_version == 1 and .event_type == "signer-public-key" and .network == "hoodi" and
   .validator_set == $set and
   .validator_public_key == $key and
   (.source == "web3signer-tls" or
    (.source == "vault-injected-mtls-get-only-probe" and .vault_agent_init_succeeded == true)) and
   .tls_verified == true and .public_key_count == 1 and .public_key_match == true and
   ($observed <= ($now + 30)) and (($now - $observed) <= 300))
' "$signer_evidence" >/dev/null || { printf '%s\n' 'fresh TLS-verified signer identity evidence is missing or mismatched' >&2; exit 65; }

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
receipt_enabled=false; receipt_parent=''
if [ "$receipt_arg_count" -eq 4 ]; then
  receipt_parent="$(dirname "$activation_receipt")"
  [ -d "$receipt_parent" ] && [ ! -L "$receipt_parent" ] || { printf '%s\n' 'activation receipt parent must be a real directory' >&2; exit 65; }
  [ "$(stat -f '%Lp' "$receipt_parent" 2>/dev/null || stat -c '%a' "$receipt_parent")" = 700 ] || { printf '%s\n' 'activation receipt parent must have mode 0700' >&2; exit 65; }
  receipt_parent="$(cd "$receipt_parent" && pwd -P)"
  activation_receipt="$receipt_parent/$(basename "$activation_receipt")"
  [ ! -e "$activation_receipt" ] && [ ! -L "$activation_receipt" ] || { printf '%s\n' 'activation receipt target already exists' >&2; exit 65; }
  [ -f "$root/scripts/ops/lib/uc5-beacon-reader.py" ] && [ ! -L "$root/scripts/ops/lib/uc5-beacon-reader.py" ] || { printf '%s\n' 'private Beacon readiness reader is unavailable' >&2; exit 65; }
  command -v python3 >/dev/null 2>&1 || { printf '%s\n' 'missing command: python3' >&2; exit 69; }
  receipt_enabled=true
fi
allowlist="$root/.ci/validator/approved-client-images.json"
client="validator-${validator_set}-client"
client_pod="${client}-0"
fence="validator-${validator_set}-signing-fence"
signer="validator-${validator_set}-remote-signer"
lease="validator-${validator_set}-primary"
client_selector='app.kubernetes.io/component=validator-client'
client_deployments="$(kubectl get deployments --all-namespaces -l "$client_selector" -o json)"
client_pods="$(kubectl get pods --all-namespaces -l "$client_selector" -o json)"
client_statefulsets="$(kubectl get statefulsets --all-namespaces -l "$client_selector" -o json)"
fences="$(kubectl get deployments --all-namespaces -l "app.kubernetes.io/component=validator-signing-fence" -o json)"
[ "$(jq -r '.items | length' <<<"$client_deployments")" -eq 0 ] || { printf '%s\n' 'validator client Deployments exist cluster-wide; stable StatefulSet identity is required' >&2; exit 65; }
jq -e --arg namespace validator-operations --arg client "$client" --arg set "$validator_set" '
  (.items | type == "array" and length == 1) and
  (.items[0].metadata.namespace == $namespace) and
  (.items[0].metadata.name == $client) and
  (.items[0].metadata.labels["node-operator.io/validator-set"] == $set) and
  (.items[0].spec.template.metadata.labels["node-operator.io/validator-set"] == $set) and
  (.items[0].spec.serviceName == ("validator-" + $set + "-client-headless")) and
  (.items[0].spec.replicas == 0) and
  (.items[0].spec.template.spec.containers | type == "array" and length == 1) and
  (.items[0].spec.template.spec.containers[0].name == "validator") and
  (.items[0].spec.template.spec.containers[0].image | type == "string")
' <<<"$client_statefulsets" >/dev/null || { printf '%s\n' 'expected exactly one exact, zero-replica staged validator client StatefulSet cluster-wide' >&2; exit 65; }
client_image="$(jq -er '.items[0].spec.template.spec.containers[0].image' <<<"$client_statefulsets")"
client_uid="$(jq -er '.items[0].metadata.uid | strings | select(length>0)' <<<"$client_statefulsets")"
jq -e --arg image "$client_image" --argjson now "$now_epoch" '.schema_version == 2 and any(.images[]; .private_image == $image and .activation_approved == true and (.release_channel == "upstream-mirror" or .release_channel == "manual-native-mtls") and (.activation_expires_at? == null or (.activation_expires_at | type == "string" and test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$") and fromdateiso8601 > $now)))' "$allowlist" >/dev/null || { printf '%s\n' 'staged validator client image is not an exact activation-approved reviewed artifact' >&2; exit 65; }
[ "$(jq -r '.items | if type == "array" then length else -1 end' <<<"$client_pods")" -eq 0 ] || { printf '%s\n' 'validator client Pods exist cluster-wide; refuse activation' >&2; exit 65; }
fence_image="$(jq -er '.items[0].spec.template.spec.containers[0].image' <<<"$fences")"
approved_fence_image="$(jq -r --arg image "$client_image" '[.images[] | select(.private_image == $image and .activation_approved == true) | .approval_basis.fence_image? | select(type == "string")] | first // empty' "$allowlist")"
jq -e --arg namespace validator-operations --arg fence "$fence" --arg set "$validator_set" --arg image "$fence_image" --arg approved_fence_image "$approved_fence_image" '
  (.items | type == "array" and length == 1) and .items[0].metadata.namespace == $namespace and
  .items[0].metadata.name == $fence and .items[0].metadata.labels["node-operator.io/validator-set"] == $set and
  .items[0].spec.template.metadata.labels["node-operator.io/validator-set"] == $set and .items[0].spec.replicas == 0 and
  (.items[0].spec.template.spec.containers[0].image == $image) and
  ($image == $approved_fence_image or ($approved_fence_image == "" and ($image | test("^123456789012\\.dkr\\.ecr\\.ap-northeast-2\\.amazonaws\\.com/node-operator-baseline-validator-fence@sha256:[a-f0-9]{64}$"))))
' <<<"$fences" >/dev/null || { printf '%s\n' 'expected exactly one exact, zero-replica digest-pinned signing fence' >&2; exit 65; }
fence_controller_uid="$(jq -er '.items[0].metadata.uid | strings | select(length>0)' <<<"$fences")"
public_service="$(kubectl -n validator-operations get service "$signer" -o json)"
direct_service="$(kubectl -n validator-operations get service "${signer}-direct" -o json)"
jq -e --arg set "$validator_set" '.spec.selector["app.kubernetes.io/component"] == "validator-signing-fence" and .spec.selector["node-operator.io/validator-set"] == $set and any(.spec.ports[]; .port == 9000 and .targetPort == "fence-proxy")' <<<"$public_service" >/dev/null || { printf '%s\n' 'public signer Service does not enforce the signing fence' >&2; exit 65; }
jq -e --arg set "$validator_set" '.spec.selector["app.kubernetes.io/component"] == "validator-remote-signer" and .spec.selector["node-operator.io/validator-set"] == $set and any(.spec.ports[]; .port == 9000 and .targetPort == "signer-api")' <<<"$direct_service" >/dev/null || { printf '%s\n' 'direct signer Service is missing or mis-scoped' >&2; exit 65; }
signer_replicas="$(kubectl -n validator-operations get deployment "$signer" -o jsonpath='{.spec.replicas}')"
[ "$signer_replicas" = 1 ] || { printf '%s\n' 'signer is not fenced and running at exactly one replica' >&2; exit 65; }
marker="$(kubectl -n validator-operations get configmap uc5-hoodi-example-maintenance --ignore-not-found -o json)"
[ -z "$marker" ] || { printf '%s\n' 'UC5 maintenance marker remains; activation refused' >&2; exit 65; }
if [ "$dry_run" = true ]; then printf '%s\n' 'PASS: activation preflight passed; client and signing fence remain at zero because --dry-run was set.'; exit 0; fi

# The evidence and controller checks above are intentionally read-only.  A
# separate, literal confirmation on the controlling terminal is required
# before this process can issue its first scale patch.  Do not read stdin:
# wrappers may pipe it, but they must never be able to auto-accept activation.
if ! exec 9<>/dev/tty; then
  printf '%s\n' 'interactive controlling terminal is required to activate' >&2
  exit 65
fi
printf 'Activation request: validator set=%s public key=%s withdrawal address=%s\n' "$validator_set" "$public_key" "$confirmed_withdrawal" >&9
printf '%s' 'Type exactly ACTIVATE to scale the validator client and signing fence: ' >&9
if ! IFS= read -r activation_confirmation <&9; then
  exec 9>&-
  printf '%s\n' 'activation confirmation was not provided' >&2
  exit 65
fi
exec 9>&-
[ "$activation_confirmation" = ACTIVATE ] || { printf '%s\n' 'activation confirmation did not match ACTIVATE' >&2; exit 65; }

cas_scale() {
  local kind="$1" name="$2" expected_uid="$3" replicas="$4" current uid rv old patch
  marker="$(kubectl -n validator-operations get configmap uc5-hoodi-example-maintenance --ignore-not-found -o json)" || return 1
  [ -z "$marker" ] || return 1
  current="$(kubectl -n validator-operations get "$kind" "$name" -o json)" || return 1
  uid="$(jq -er --arg name "$name" --arg expected "$expected_uid" '.metadata.uid | select(. == $expected) | strings | select(length>0)' <<<"$current")" || return 1
  jq -e --arg name "$name" '.metadata.name == $name and .metadata.namespace == "validator-operations" and (.metadata.deletionTimestamp | not)' <<<"$current" >/dev/null || return 1
  rv="$(jq -er '.metadata.resourceVersion | strings | select(length>0)' <<<"$current")" || return 1
  old="$(jq -er '.spec.replicas | select(type=="number" and (.==0 or .==1))' <<<"$current")" || return 1
  [ "$replicas" = 0 ] || [ "$old" = 0 ] || return 1
  patch="$(jq -cn --arg uid "$uid" --arg rv "$rv" --argjson old "$old" --argjson new "$replicas" '[{op:"test",path:"/metadata/uid",value:$uid},{op:"test",path:"/metadata/resourceVersion",value:$rv},{op:"test",path:"/spec/replicas",value:$old},{op:"replace",path:"/spec/replicas",value:$new}]')" || return 1
  kubectl -n validator-operations patch "$kind" "$name" --type=json -p "$patch" -o json >/dev/null
}

activation_complete=false
rollback() {
  status=$?; trap - EXIT INT TERM HUP
  if [ "$activation_complete" != true ]; then
    cleanup_failed=false
    cas_scale deployment "$fence" "$fence_controller_uid" 0 >/dev/null 2>&1 || cleanup_failed=true
    cas_scale statefulset "$client" "$client_uid" 0 >/dev/null 2>&1 || cleanup_failed=true
    fence_after="$(kubectl -n validator-operations get deployment "$fence" -o jsonpath='{.spec.replicas}' 2>/dev/null)" || cleanup_failed=true
    client_after="$(kubectl -n validator-operations get statefulset "$client" -o jsonpath='{.spec.replicas}' 2>/dev/null)" || cleanup_failed=true
    [ "${fence_after:-}" = 0 ] && [ "${client_after:-}" = 0 ] || cleanup_failed=true
    if [ "$cleanup_failed" = true ]; then
      printf '%s\n' 'CRITICAL: activation failed and zero-replica rollback could not be verified' >&2
      exit 70
    fi
  fi
  exit "$status"
}
trap rollback EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

read_private_beacon_bound() {
  python3 -I -B - "$root/scripts/ops/lib/uc5-beacon-reader.py" "$public_key" <<'PY'
import importlib.util
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
spec = importlib.util.spec_from_file_location("node_operator_uc5_beacon_reader", path)
if spec is None or spec.loader is None:
    raise SystemExit("private Beacon readiness reader is unavailable")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
print(json.dumps(module.read_ready(sys.argv[2]), sort_keys=True, separators=(",", ":")))
PY
}

publish_activation_receipt() {
  local beacon_json="$1" client_after fence_after client_pod_after fence_pod_after lease_after client_pod_uid_after fence_pod_uid_after lease_uid_after holder_after temporary
  client_after="$(kubectl -n validator-operations get statefulset "$client" -o json)" || return 1
  fence_after="$(kubectl -n validator-operations get deployment "$fence" -o json)" || return 1
  client_pod_after="$(kubectl -n validator-operations get pod "$client_pod" -o json)" || return 1
  fence_pod_after="$(kubectl -n validator-operations get pods -l "app.kubernetes.io/component=validator-signing-fence,node-operator.io/validator-set=${validator_set}" -o json)" || return 1
  lease_after="$(kubectl -n validator-operations get lease "$lease" -o json)" || return 1
  client_pod_uid_after="$(jq -er --arg set "$validator_set" --arg name "$client_pod" --arg deployment "$deployment_name" --arg revision "$release_revision" '
    . as $pod | ($pod.metadata.name == $name and ($pod.metadata.uid | type == "string" and length > 0) and
    $pod.metadata.labels["node-operator.io/validator-set"] == $set and $pod.metadata.labels["app.kubernetes.io/component"] == "validator-client" and
    $pod.metadata.labels["node-operator.io/deployment-name"] == $deployment and $pod.metadata.labels["node-operator.io/release-revision"] == $revision and
    $pod.status.phase == "Running" and any($pod.status.conditions[]?; .type == "Ready" and .status == "True")) |
    if . then $pod.metadata.uid else error end
  ' <<<"$client_pod_after")" || return 1
  fence_pod_uid_after="$(jq -er --arg set "$validator_set" --arg deployment "$deployment_name" --arg revision "$release_revision" '
    .items | if type == "array" and length == 1 then .[0] else error end | . as $pod |
    (($pod.metadata.uid | type == "string" and length > 0) and $pod.metadata.labels["node-operator.io/validator-set"] == $set and
    $pod.metadata.labels["app.kubernetes.io/component"] == "validator-signing-fence" and $pod.metadata.labels["node-operator.io/deployment-name"] == $deployment and
    $pod.metadata.labels["node-operator.io/release-revision"] == $revision and $pod.status.phase == "Running" and
    any($pod.status.conditions[]?; .type == "Ready" and .status == "True")) |
    if . then $pod.metadata.uid else error end
  ' <<<"$fence_pod_after")" || return 1
  jq -e --arg client_uid "$client_uid" --arg fence_uid "$fence_controller_uid" '
    .metadata.uid == $client_uid and .spec.replicas == 1
  ' <<<"$client_after" >/dev/null || return 1
  jq -e --arg fence_uid "$fence_controller_uid" '
    .metadata.uid == $fence_uid and .spec.replicas == 1
  ' <<<"$fence_after" >/dev/null || return 1
  lease_uid_after="$(jq -er --arg holder "$fence_pod_uid_after" --argjson now "$(date -u +%s)" '
    def rfc3339_epoch:
      if type == "string" and test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\\.[0-9]+)?Z$")
      then sub("\\.[0-9]+Z$"; "Z") | fromdateiso8601 else error end;
    . as $lease | ($lease.metadata.uid | strings | select(length > 0)) as $uid |
    ($lease.spec.renewTime | rfc3339_epoch) as $renewed |
    ($lease.spec.holderIdentity == $holder and ($lease.spec.leaseDurationSeconds | type == "number" and . > 0) and
    $renewed <= ($now + 30) and (($now - $renewed) <= $lease.spec.leaseDurationSeconds)) |
    if . then $uid else error end
  ' <<<"$lease_after")" || return 1
  holder_after="$(jq -er '.spec.holderIdentity' <<<"$lease_after")" || return 1
  jq -e --arg key "$public_key" '
    .result == "PASS_PRIVATE_BEACON_READY" and .scope == "private Beacon readiness only; not duty evidence" and
    .validator_public_key == $key and (.validator_index | tostring | test("^[0-9]+$")) and
    (.pod_uid | type == "string" and length > 0) and (.head_slot | type == "number" and . >= 0 and floor == .)
  ' <<<"$beacon_json" >/dev/null || return 1
  temporary="$(mktemp "$receipt_parent/.activation-receipt.XXXXXX")" || return 1
  chmod 600 "$temporary" || { rm -f "$temporary"; return 1; }
  if ! jq -n --arg set "$validator_set" --arg key "$public_key" --arg deployment "$deployment_name" --arg revision "$release_revision" --arg operation "$operation_id" --arg client_controller "$client_uid" --arg fence_controller "$fence_controller_uid" --arg client_pod "$client_pod_uid_after" --arg fence_pod "$fence_pod_uid_after" --arg lease_uid "$lease_uid_after" --arg holder "$holder_after" --argjson beacon "$beacon_json" \
    '{schema_version:1,result:"activation-post-ready-head-bound",scope:"post-Ready private Beacon head lower bound only; not duty, finalization, signature, or end-to-end proof",validator_set:$set,validator_public_key:$key,deployment_name:$deployment,release_revision:$revision,operation_id:$operation,controllers:{client_statefulset_uid:$client_controller,fence_deployment_uid:$fence_controller},pods:{client_uid:$client_pod,fence_uid:$fence_pod},lease:{uid:$lease_uid,holder_identity:$holder},private_beacon:{pod_uid:$beacon.pod_uid,validator_index:($beacon.validator_index|tostring),head_slot:$beacon.head_slot}}' > "$temporary"; then
    rm -f "$temporary"; return 1
  fi
  ln "$temporary" "$activation_receipt" && rm -f "$temporary" || { rm -f "$temporary"; return 1; }
}

# The public signer Service has no endpoints while the fence is zero, and
# direct signer ingress accepts only the fence. Starting the fixed-name client
# first therefore cannot sign; it only establishes the Pod UID/IP to bind.
cas_scale statefulset "$client" "$client_uid" 1 || { printf '%s\n' 'client identity-pinned scale-up failed' >&2; exit 65; }
kubectl -n validator-operations rollout status statefulset "$client" --timeout=120s
client_json="$(kubectl -n validator-operations get pod "$client_pod" -o json)"
jq -e --arg set "$validator_set" --arg name "$client_pod" '
  .metadata.name == $name and .metadata.labels["node-operator.io/validator-set"] == $set and
  .metadata.labels["app.kubernetes.io/component"] == "validator-client" and
  (.metadata.uid | type == "string" and length > 0) and (.status.podIP | type == "string" and length > 0) and
  .status.phase == "Running" and any(.status.conditions[]; .type == "Ready" and .status == "True")
' <<<"$client_json" >/dev/null || { printf '%s\n' 'fixed client Pod identity is not Ready for fence binding' >&2; exit 65; }
cas_scale deployment "$fence" "$fence_controller_uid" 1 || { printf '%s\n' 'fence identity-pinned scale-up failed' >&2; exit 65; }
kubectl -n validator-operations rollout status deployment "$fence" --timeout=120s
fence_pod="$(kubectl -n validator-operations get pods -l "app.kubernetes.io/component=validator-signing-fence,node-operator.io/validator-set=${validator_set}" -o json)"
fence_uid="$(jq -er 'select(.items | length == 1) | .items[0].metadata.uid' <<<"$fence_pod")"
lease_json="$(kubectl -n validator-operations get lease "$lease" -o json)"
jq -e --arg holder "$fence_uid" --argjson now "$(date -u +%s)" '
  def rfc3339_epoch:
    if type == "string" and test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\\.[0-9]+)?Z$")
    then sub("\\.[0-9]+Z$"; "Z") | fromdateiso8601
    else error("invalid UTC RFC3339 timestamp")
    end;
  (.spec.renewTime | rfc3339_epoch) as $renewed |
  ((.spec.holderIdentity == $holder) and
   (.spec.leaseDurationSeconds | type == "number" and . > 0) and
   ($renewed <= ($now + 30)) and (($now - $renewed) <= .spec.leaseDurationSeconds))
' <<<"$lease_json" >/dev/null || { printf '%s\n' 'signer fence lease is absent, malformed, or expired' >&2; exit 65; }
if [ "$receipt_enabled" = true ]; then
  beacon_bound="$(read_private_beacon_bound)" || { printf '%s\n' 'post-Ready private Beacon head could not be read; activation will be rolled back' >&2; exit 65; }
  publish_activation_receipt "$beacon_bound" || { printf '%s\n' 'activation receipt could not be bound to the post-Ready cluster state; activation will be rolled back' >&2; exit 65; }
fi
activation_complete=true
trap - EXIT INT TERM HUP
printf '%s\n' 'PASS: one fixed-identity client and its signing fence are Ready. Immediately collect private duty, signer audit, and Kubernetes evidence; never start a second client.'
