#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
script="$root/scripts/ops/recover-hoodi-validator-signer.sh"
# shellcheck disable=SC2016 # Literal source-contract assertions.
grep -Fq '[ "$client_replicas" = 0 ]' "$script"
# shellcheck disable=SC2016 # Literal source-contract assertion.
grep -Fq '[ "$signer_replicas" = 0 ]' "$script"
# shellcheck disable=SC2016 # Literal source-contract assertion.
grep -Fq '[ -z "$lease_holder" ]' "$script"
# shellcheck disable=SC2016 # Literal source-contract assertions.
grep -Fq 'data-validator-${validator_set}-slashing-db-0' "$script"
# shellcheck disable=SC2016 # Literal source-contract assertion.
grep -Fq 'validator-${validator_set}-remote-signer' "$script"
if grep -Eq 'kubectl .*delete|scale deployment hoodi-validator-client --replicas=1' "$script"; then printf '%s\n' 'recovery may delete data or activate validator client' >&2; exit 1; fi
scratch="$(mktemp -d /private/tmp/node-operator-recovery-test.XXXXXX)"
trap 'rm -rf "$scratch"' EXIT
mkdir -p "$scratch/bin" "$scratch/output"
cat > "$scratch/bin/kubectl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "$MOCK_TRACE"
case "$*" in
  *'get statefulset validator-hoodi-example-client '*)
    [ "${MOCK_API_FAIL:-false}" = false ] || exit 69
    printf '%s' "${MOCK_STATEFUL-0}" ;;
  *'get deployment validator-hoodi-example-client '*) printf '%s' "${MOCK_LEGACY-}" ;;
  *'get deployment validator-hoodi-example-signing-fence '*) printf '%s' "${MOCK_FENCE-0}" ;;
  *'get deployment validator-hoodi-example-remote-signer '*) printf '%s' "${MOCK_SIGNER-0}" ;;
  *'get pods '*)
    if [ "${MOCK_MALFORMED:-false}" = true ]; then printf '%s\n' '{}'; else
      jq -n --argjson count "${MOCK_PODS:-0}" '{items:[range($count)|{metadata:{name:"remaining"}}]}'
    fi ;;
  *'get lease '*) printf '%s' "${MOCK_HOLDER-}" ;;
  *'get pvc '*'{.status.phase}') printf '%s' "${MOCK_PVC_PHASE-Bound}" ;;
  *'get pvc '*) printf '%s' "${MOCK_PVC_SET-hoodi-example}" ;;
  '-n validator-operations scale deployment validator-hoodi-example-remote-signer --replicas=1') ;;
  *) exit 64 ;;
esac
EOF
chmod +x "$scratch/bin/kubectl"
key="0x$(printf 'a%.0s' {1..96})"
run_recovery() {
  PATH="$scratch/bin:$PATH" MOCK_TRACE="$scratch/trace" bash "$script" \
    --validator-set hoodi-example --validator-public-key "$key" \
    --correlation-id 00000000-0000-4000-8000-000000000001 \
    --recovery-approval-id offline-test --output-dir "$scratch/output" "$@"
}
expect_rejected() {
  : > "$scratch/trace"
  if run_recovery --dry-run >"$scratch/stdout" 2>"$scratch/stderr"; then
    printf 'unsafe recovery preflight accepted: %s\n' "$1" >&2; exit 1
  fi
  if grep -q ' scale ' "$scratch/trace"; then
    printf 'rejected preflight mutated a workload: %s\n' "$1" >&2; exit 1
  fi
}
MOCK_STATEFUL=1 expect_rejected active-statefulset-without-pods
MOCK_LEGACY=1 expect_rejected active-legacy-deployment
MOCK_STATEFUL='' expect_rejected missing-staged-client
MOCK_STATEFUL=0 MOCK_LEGACY=0 expect_rejected duplicate-staged-client-controllers
MOCK_API_FAIL=true expect_rejected api-unavailable
MOCK_FENCE=1 expect_rejected active-proxy
MOCK_SIGNER=1 expect_rejected active-signer
MOCK_PODS=1 expect_rejected remaining-pods
MOCK_MALFORMED=true expect_rejected malformed-pod-response
MOCK_HOLDER=another-owner expect_rejected lease-owned
MOCK_PVC_PHASE=Pending expect_rejected unbound-history
MOCK_PVC_SET=hoodi-other expect_rejected mismatched-history

: > "$scratch/trace"
run_recovery --dry-run >/dev/null
if grep -q ' scale ' "$scratch/trace"; then printf '%s\n' 'dry-run scaled a workload' >&2; exit 1; fi
jq -e '.payload.uc5_complete == false and .payload.client_signer_fence_pods_absent_at_preflight == true and .payload.mode == "dry-run"' "$scratch/output/"*.json >/dev/null
: > "$scratch/trace"
run_recovery >/dev/null
test "$(grep -c ' scale ' "$scratch/trace")" -eq 1
grep -Fxq -- '-n validator-operations scale deployment validator-hoodi-example-remote-signer --replicas=1' "$scratch/trace"
printf '%s\n' 'PASS: recovery checks both client controller kinds and Pod absence, preserves slashing PVCs, and scales only the isolated signer.'
