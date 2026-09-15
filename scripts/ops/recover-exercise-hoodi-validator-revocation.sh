#!/usr/bin/env bash
set -euo pipefail

# UC-5 runtime exercise. It uses a recovery-key ceremony to temporarily remove
# only this set's Vault Kubernetes role, proves the signer cannot start, then
# restores the reviewed role. It never reads or prints Vault values, recovery
# material, tokens, or keystores.
dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
if [ "${PRIVATE_VAULT_SESSION:-}" != 1 ]; then
  exec "$dir/with-private-vault.sh" -- env PRIVATE_VAULT_SESSION=1 "$0" "$@"
fi

usage() { printf '%s\n' "Usage: ${0##*/} --validator-set <hoodi-id> --exercise-approval-id <id> --signing-proxy-fence-proof <absolute-json> --output-dir <absolute-dir>" >&2; exit 64; }
validator_set=''; approval_id=''; signing_proxy_fence_proof=''; output_dir=''
while [ "$#" -gt 0 ]; do
  case "$1" in
    --validator-set) validator_set="${2:-}"; shift 2 ;;
    --exercise-approval-id) approval_id="${2:-}"; shift 2 ;;
    --signing-proxy-fence-proof) signing_proxy_fence_proof="${2:-}"; shift 2 ;;
    --output-dir) output_dir="${2:-}"; shift 2 ;;
    *) usage ;;
  esac
done
case "$validator_set" in hoodi-[a-z0-9][a-z0-9-]*) ;; *) usage ;; esac
case "$approval_id" in [a-zA-Z0-9][a-zA-Z0-9._:-]*) ;; *) usage ;; esac
case "$signing_proxy_fence_proof" in /*) ;; *) usage ;; esac
case "$output_dir" in /*) ;; *) usage ;; esac
for command in vault jq kubectl mkdir chmod date sleep; do command -v "$command" >/dev/null 2>&1 || { printf 'missing command: %s\n' "$command" >&2; exit 69; }; done

namespace=validator-operations
role="hoodi-${validator_set}-runtime"
deployment="validator-${validator_set}-remote-signer"
client="validator-${validator_set}-client"
[ -r "$signing_proxy_fence_proof" ] || { printf '%s\n' 'signing-proxy fence proof is not readable' >&2; exit 66; }
now_epoch="$(date -u +%s)"
jq -e --arg set "$validator_set" --argjson now "$now_epoch" '
  def rfc3339_epoch:
    if type == "string" and test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\\.[0-9]+)?Z$")
    then sub("\\.[0-9]+Z$"; "Z") | fromdateiso8601
    else error("invalid UTC RFC3339 timestamp")
    end;
  (.collected_at_utc | rfc3339_epoch) as $observed |
  (.schema_version == 1 and .event_type == "signing-proxy-fence" and
   .source == "signing-proxy-fence" and .network == "hoodi" and .validator_set == $set and
   ($observed <= ($now + 30)) and (($now - $observed) <= 300) and
   .payload.fence_live_before_quiesce == true and .payload.lease_enforced == true and
   .payload.client_and_fence_quiesced == true and
   .payload.direct_client_to_signer_denied == true)
' "$signing_proxy_fence_proof" >/dev/null || { printf '%s\n' 'fresh staged fence proof is required; role deletion alone cannot fence cached keys' >&2; exit 65; }
client_replicas="$(kubectl -n "$namespace" get deployment "$client" --ignore-not-found -o jsonpath='{.spec.replicas}')"
[ -z "$client_replicas" ] || [ "$client_replicas" = 0 ] || { printf '%s\n' 'validator client must be fenced at zero before UC-5' >&2; exit 65; }
stateful_replicas="$(kubectl -n "$namespace" get statefulset "$client" --ignore-not-found -o jsonpath='{.spec.replicas}')" || { printf '%s\n' 'cannot prove validator client StatefulSet state' >&2; exit 69; }
[ -z "$stateful_replicas" ] || [ "$stateful_replicas" = 0 ] || { printf '%s\n' 'validator client StatefulSet must be fenced at zero before UC-5' >&2; exit 65; }
[ -z "$(kubectl -n "$namespace" get pods -l "app.kubernetes.io/component=validator-client,node-operator.io/validator-set=${validator_set}" -o name)" ] || { printf '%s\n' 'validator client Pod remains; UC-5 role probe refused' >&2; exit 65; }
[ "$(kubectl -n "$namespace" get deployment "$deployment" -o jsonpath='{.spec.replicas}')" = 1 ] || { printf '%s\n' 'signer must be running at one replica before UC-5' >&2; exit 65; }

started=false; complete=false; root_token=''; cleanup_failed=false; role_revoked=false; role_restored=false
cleanup() {
  set +e
  # Once the ceremony has removed the workload role, failure must restore the
  # reviewed role before relinquishing the generated root token.  The client
  # remains fenced at zero, so this restoration cannot resume signing by
  # itself.
  if [ "$role_revoked" = true ] && [ "$role_restored" != true ] && [ -n "$root_token" ]; then
    if VAULT_TOKEN="$root_token" PRIVATE_VAULT_SESSION=1 "$dir/bootstrap-hoodi-validator-runtime-vault.sh" --validator-set "$validator_set" >/dev/null 2>&1; then
      role_restored=true
      kubectl -n "$namespace" rollout restart "deployment/${deployment}" >/dev/null 2>&1 || cleanup_failed=true
    else
      cleanup_failed=true
      printf '%s\n' 'CRITICAL: reviewed workload role restoration could not be confirmed' >&2
    fi
  fi
  if [ -n "$root_token" ] && ! VAULT_TOKEN="$root_token" vault token revoke -self >/dev/null 2>&1; then
    cleanup_failed=true
    printf '%s\n' 'CRITICAL: generated root token revocation could not be confirmed' >&2
  fi
  if [ "$started" = true ] && [ "$complete" != true ] && ! vault operator generate-root -cancel >/dev/null 2>&1; then
    cleanup_failed=true
    printf '%s\n' 'CRITICAL: incomplete root-token ceremony cancellation could not be confirmed' >&2
  fi
  unset VAULT_TOKEN root_token
}
on_exit() {
  local status=$?
  trap - EXIT
  cleanup
  if [ "$cleanup_failed" = true ] && [ "$status" -eq 0 ]; then exit 1; fi
  exit "$status"
}
trap on_exit EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP
# shellcheck source=scripts/ops/lib/vault-recovery-auth.sh
source "$dir/lib/vault-recovery-auth.sh"
vault_recovery_auth_preflight
status="$(vault operator generate-root -status -format=json)"
[ "$(jq -r '.started' <<<"$status")" = false ] || { printf '%s\n' 'root-token ceremony already in progress' >&2; exit 75; }
init="$(vault operator generate-root -init -format=json)"; started=true
nonce="$(jq -er .nonce <<<"$init")"; otp="$(jq -er .otp <<<"$init")"; required="$(jq -er .required <<<"$init")"
for share_number in $(seq 1 "$required"); do
  printf 'Recovery key share %s of %s: ' "$share_number" "$required" >&2
  IFS= read -r -s share; printf '\n' >&2
  submitted="$(printf %s "$share" | vault operator generate-root -nonce="$nonce" -format=json -)"; unset share
  if [ "$(jq -r .complete <<<"$submitted")" = true ]; then complete=true; encoded="$(jq -er .encoded_token <<<"$submitted")"; break; fi
done
[ "$complete" = true ] || { printf '%s\n' 'recovery quorum was not reached' >&2; exit 77; }
root_token="$(vault_recovery_decode_generated_root "$encoded" "$otp")"; unset encoded otp nonce init submitted status

VAULT_TOKEN="$root_token" vault delete "auth/kubernetes/role/${role}" >/dev/null
role_revoked=true
kubectl -n "$namespace" rollout restart "deployment/${deployment}" >/dev/null
denied=false
for _ in $(seq 1 60); do
  pod="$(kubectl -n "$namespace" get pods -l "app.kubernetes.io/component=validator-remote-signer,node-operator.io/validator-set=${validator_set}" -o json | jq -r '[.items[] | select(.metadata.creationTimestamp != null)] | sort_by(.metadata.creationTimestamp) | last | .metadata.name // empty')"
  if [ -n "$pod" ] && kubectl -n "$namespace" logs "$pod" -c vault-agent-init --tail=20 2>&1 | grep -Eq 'permission denied|invalid role|error authenticating'; then denied=true; break; fi
  sleep 5
done
[ "$denied" = true ] || { printf '%s\n' 'signer did not prove fail-closed; role remains revoked for investigation' >&2; exit 1; }

VAULT_TOKEN="$root_token" PRIVATE_VAULT_SESSION=1 "$dir/bootstrap-hoodi-validator-runtime-vault.sh" --validator-set "$validator_set" >/dev/null
role_restored=true
kubectl -n "$namespace" rollout restart "deployment/${deployment}" >/dev/null
kubectl -n "$namespace" rollout status "deployment/${deployment}" --timeout=360s >/dev/null

mkdir -p "$output_dir"; chmod 700 "$output_dir"; output_dir="$(cd "$output_dir" && pwd -P)"
record="$output_dir/uc-5-role-revocation-$(date -u +%Y%m%dT%H%M%SZ).json"
jq -n --arg collected "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --arg approval "$approval_id" --arg set "$validator_set" --arg role "$role" \
  '{schema_version:1,event_type:"uc-5",collected_at_utc:$collected,network:"hoodi",validator_set:$set,source:"role-revocation-probe",payload:{exercise_approval_id:$approval,revoked_kubernetes_auth_role:$role,bootstrap_auth_denied:true,cached_key_stop_proven:true,signing_proxy_fence_proof_verified:true,role_restored:true,signer_ready_after_restore:true,client_remained_fenced:true,client_pods_absent:true,remaining_requirement:"reactivate the same slashing PVC through the activation gate and verify a later canonical duty",uc5_complete:false}}' > "$record"
chmod 600 "$record"
printf 'PASS UC-5 role-revocation probe: fencing blocked the direct path, bootstrap authentication was denied, and access was restored. A later canonical duty remains required. Evidence: %s\n' "$record"
