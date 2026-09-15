#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"; script="$root/scripts/ops/release-expired-hoodi-validator-fence-lease.sh"
scratch="$(mktemp -d /private/tmp/node-operator-lease-handover.XXXXXX)"; trap 'rm -rf "$scratch"' EXIT; mkdir "$scratch/bin" "$scratch/out"
cat > "$scratch/bin/kubectl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "$MOCK_TRACE"
[ "${MOCK_API_FAIL:-false}" = false ] || exit 1
case "$*" in
  *'get statefulset validator-hoodi-example-client '*) [ "${MOCK_CLIENT_ABSENT:-false}" = true ] || jq -n --argjson r "${MOCK_CLIENT_REPLICAS:-0}" '{metadata:{name:"validator-hoodi-example-client"},spec:{replicas:$r,selector:{matchLabels:{"node-operator.io/validator-set":"hoodi-example"}},template:{metadata:{labels:{"node-operator.io/validator-set":"hoodi-example"}}}}}' ;;
  *'get deployment validator-hoodi-example-signing-fence '*) [ "${MOCK_FENCE_ABSENT:-false}" = true ] || jq -n --argjson r "${MOCK_FENCE_REPLICAS:-0}" '{metadata:{name:"validator-hoodi-example-signing-fence"},spec:{replicas:$r,selector:{matchLabels:{"node-operator.io/validator-set":"hoodi-example"}},template:{metadata:{labels:{"node-operator.io/validator-set":"hoodi-example"}}}}}' ;;
  *'get deployment validator-hoodi-example-remote-signer -o json') jq -n --argjson r "${MOCK_SIGNER_REPLICAS:-0}" '{metadata:{name:"validator-hoodi-example-remote-signer"},spec:{replicas:$r,selector:{matchLabels:{"node-operator.io/validator-set":"hoodi-example"}},template:{metadata:{labels:{"node-operator.io/validator-set":"hoodi-example"}}}}}' ;;
  *'get pods '*)
    count_file="$MOCK_STATE/pod-count"; count=0; [ ! -f "$count_file" ] || count="$(<"$count_file")"; count=$((count+1)); printf '%s' "$count" > "$count_file"
    pods="${MOCK_PODS:-0}"; [ "$count" -lt 2 ] || pods="${MOCK_SECOND_PODS:-$pods}"; jq -n --argjson n "$pods" '{items:[range($n)|{metadata:{name:"remaining"}}]}' ;;
  *'get pvc data-validator-hoodi-example-slashing-db-0 -o json') jq -n --arg uid "${MOCK_PVC_UID:-pvc-uid}" --arg phase "${MOCK_PVC_PHASE:-Bound}" '{metadata:{name:"data-validator-hoodi-example-slashing-db-0",uid:$uid},spec:{resources:{requests:{storage:"50Gi"}}},status:{phase:$phase}}' ;;
  *'get lease validator-hoodi-example-primary -o json')
    if [ -f "$MOCK_STATE/patched" ]; then
      [ "${MOCK_READBACK_FAIL:-false}" = false ] || exit 1
      jq -n --arg uid "${MOCK_LEASE_UID:-lease-uid}" --arg renewed "$MOCK_RENEWED" --argjson duration "${MOCK_DURATION:-60}" '{metadata:{name:"validator-hoodi-example-primary",uid:$uid,resourceVersion:"rv-new"},spec:{holderIdentity:"",renewTime:$renewed,leaseDurationSeconds:$duration}}'
    else
      jq -n --arg uid "${MOCK_LEASE_UID:-lease-uid}" --arg rv "${MOCK_RV:-rv-old}" --arg holder "${MOCK_HOLDER:-old-holder}" --arg renewed "$MOCK_RENEWED" --argjson duration "${MOCK_DURATION:-60}" '{metadata:{name:"validator-hoodi-example-primary",uid:$uid,resourceVersion:$rv},spec:{holderIdentity:$holder,renewTime:$renewed,leaseDurationSeconds:$duration}}'
    fi ;;
  *'patch lease validator-hoodi-example-primary --type=json -p '*)
    patch="${!#}"
    jq -e --arg renewed "$MOCK_RENEWED" '. == [{op:"test",path:"/metadata/uid",value:"lease-uid"},{op:"test",path:"/metadata/resourceVersion",value:"rv-old"},{op:"test",path:"/spec/holderIdentity",value:"old-holder"},{op:"test",path:"/spec/renewTime",value:$renewed},{op:"test",path:"/spec/leaseDurationSeconds",value:60},{op:"replace",path:"/spec/holderIdentity",value:""}]' <<<"$patch" >/dev/null || exit 64
    [ "${MOCK_CAS_FAIL:-false}" = false ] || exit 1; : > "$MOCK_STATE/patched" ;;
  *) printf 'unexpected kubectl: %s\n' "$*" >&2; exit 64 ;;
esac
EOF
chmod +x "$scratch/bin/kubectl"
cat > "$scratch/bin/aws" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' 'ERROR: real AWS access is forbidden in this offline test' >&2
exit 99
EOF
chmod +x "$scratch/bin/aws"
expired="$(jq -nr --argjson t "$(( $(date -u +%s) - 120 ))" '$t|strftime("%Y-%m-%dT%H:%M:%S.000000Z")')"
run_helper() {
  local out="$1"; shift; mkdir -p "$out" "$scratch/state"
  unlink "$scratch/state/patched" 2>/dev/null || true
  unlink "$scratch/state/pod-count" 2>/dev/null || true
  : > "$scratch/trace"
  local dry_arg=''
  if [ "${1:-}" = --dry-run ]; then dry_arg=--dry-run; shift; fi
  env PRIVATE_EKS_SESSION=1 PATH="$scratch/bin:$PATH" MOCK_TRACE="$scratch/trace" MOCK_STATE="$scratch/state" MOCK_RENEWED="$expired" "$@" "$script" --validator-set hoodi-example --expected-lease-uid lease-uid --expected-resource-version rv-old --expected-holder old-holder --expected-pvc-uid pvc-uid --maintenance-approval-id reviewed-change-1 --output-dir "$out" ${dry_arg:+"$dry_arg"}
}
expect_fail() { local name="$1"; shift; if run_helper "$scratch/out-$name" "$@" >/dev/null 2>&1; then printf 'accepted unsafe case: %s\n' "$name" >&2; exit 1; fi; if grep -q ' patch lease ' "$scratch/trace" && [ "$name" != cas-race ] && [ "$name" != readback-failure ]; then printf 'mutated rejected case: %s\n' "$name" >&2; exit 1; fi; }

run_helper "$scratch/dry" --dry-run env >/dev/null
if grep -q ' patch lease ' "$scratch/trace"; then printf '%s\n' 'dry-run mutated Lease' >&2; exit 1; fi
run_helper "$scratch/apply" env >/dev/null
test "$(grep -c ' patch lease ' "$scratch/trace")" -eq 1
jq -e '.event_type == "uc-5-lease-handover" and .payload.old_holder == "old-holder" and .payload.new_holder == "" and .payload.retained_pvc_uid == "pvc-uid" and .payload.uc5_complete == false' "$scratch/apply/"*.json >/dev/null

expect_fail live-lease env MOCK_RENEWED="$(jq -nr --argjson t "$(( $(date -u +%s) - 10 ))" '$t|strftime("%Y-%m-%dT%H:%M:%SZ")')"
expect_fail future-lease env MOCK_RENEWED="$(jq -nr --argjson t "$(( $(date -u +%s) + 60 ))" '$t|strftime("%Y-%m-%dT%H:%M:%SZ")')"
expect_fail malformed-time env MOCK_RENEWED=not-a-time
expect_fail normalized-invalid-date env MOCK_RENEWED=2026-02-30T00:00:00Z
expect_fail malformed-duration env MOCK_DURATION=0
expect_fail lease-uid-mismatch env MOCK_LEASE_UID=other-lease
expect_fail resource-version-mismatch env MOCK_RV=other-version
expect_fail holder-mismatch env MOCK_HOLDER=other-holder
expect_fail client-live env MOCK_CLIENT_REPLICAS=1
expect_fail fence-live env MOCK_FENCE_REPLICAS=1
expect_fail signer-live env MOCK_SIGNER_REPLICAS=1
run_helper "$scratch/absent" --dry-run env MOCK_CLIENT_ABSENT=true MOCK_FENCE_ABSENT=true >/dev/null
expect_fail pod-present env MOCK_PODS=1
expect_fail pod-race env MOCK_SECOND_PODS=1
expect_fail pvc-mismatch env MOCK_PVC_UID=other-pvc
expect_fail pvc-unbound env MOCK_PVC_PHASE=Pending
expect_fail api-error env MOCK_API_FAIL=true
expect_fail cas-race env MOCK_CAS_FAIL=true
status=0; run_helper "$scratch/out-readback" env MOCK_READBACK_FAIL=true >/dev/null 2>&1 || status=$?; test "$status" -eq 70
printf '%s\n' 'PASS expired Lease handover is exact-CAS, quiescence/PVC-bound, dry-run safe, and fails closed on races or malformed state.'
