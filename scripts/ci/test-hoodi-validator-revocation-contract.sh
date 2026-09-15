#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
script="$root/scripts/ops/recover-exercise-hoodi-validator-revocation.sh"
fail() { printf 'FAIL Hoodi role-revocation probe: %s\n' "$*" >&2; exit 1; }
test -x "$script" || fail 'missing executable role-revocation probe'
bash -n "$script"

for required in \
  '--signing-proxy-fence-proof' \
  'event_type == "signing-proxy-fence"' \
  'fence_live_before_quiesce == true' \
  'client_and_fence_quiesced == true' \
  'direct_client_to_signer_denied == true' \
  'source:"role-revocation-probe"' \
  'bootstrap_auth_denied:true' \
  'cached_key_stop_proven:true' \
  'reviewed workload role restoration could not be confirmed' \
  'uc5_complete:false' \
  'CRITICAL: generated root token revocation could not be confirmed' \
  "trap 'exit 130' INT" \
  "trap 'exit 143' TERM"; do
  grep -Fq -- "$required" "$script" || fail "missing safety contract: $required"
done
# shellcheck disable=SC2016 # Literal source-contract assertions.
grep -Fq 'get pods -l "app.kubernetes.io/component=validator-client,node-operator.io/validator-set=${validator_set}" -o name' "$script" || fail 'client-Pod zero gate missing'
if grep -Fq 'source:"vault-audit"' "$script"; then fail 'role-revocation probe mislabels itself as a Vault audit record'; fi

scratch="$(mktemp -d /private/tmp/node-operator-revocation-probe.XXXXXX)"
trap 'rm -rf "$scratch"' EXIT
mkdir -p "$scratch/bin" "$scratch/output"
now="$(jq -nr 'now | strftime("%Y-%m-%dT%H:%M:%S.123Z")')"
jq -n --arg collected "$now" '{schema_version:1,event_type:"signing-proxy-fence",source:"signing-proxy-fence",network:"hoodi",validator_set:"hoodi-example",collected_at_utc:$collected,payload:{fence_live_before_quiesce:true,lease_enforced:true,direct_client_to_signer_denied:true,client_and_fence_quiesced:true}}' > "$scratch/proof.json"
jq '.payload.client_and_fence_quiesced = false' "$scratch/proof.json" > "$scratch/bad-proof.json"

cat > "$scratch/bin/kubectl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
case "$*" in
  '-n validator-operations get statefulset validator-hoodi-example-client --ignore-not-found -o jsonpath={.spec.replicas}')
    [ "${MOCK_STATEFUL_FAIL:-false}" = false ] || exit 1
    printf '%s' "${MOCK_STATEFUL_REPLICAS:-0}" ;;
  '-n validator-operations get deployment validator-hoodi-example-client --ignore-not-found -o jsonpath={.spec.replicas}') printf '%s' 0 ;;
  '-n validator-operations get pods -l app.kubernetes.io/component=validator-client,node-operator.io/validator-set=hoodi-example -o name') printf '%s' "${MOCK_CLIENT_PODS:-}" ;;
  *) printf 'unexpected kubectl call: %s\n' "$*" >&2; exit 64 ;;
esac
EOF
cat > "$scratch/bin/vault" <<'EOF'
#!/usr/bin/env bash
printf 'vault must not run before preflight rejection\n' >&2
exit 70
EOF
chmod +x "$scratch/bin/kubectl" "$scratch/bin/vault"

run_probe() {
  PATH="$scratch/bin:$PATH" PRIVATE_VAULT_SESSION=1 \
    bash "$script" --validator-set hoodi-example --exercise-approval-id reviewed-uc5 \
      --signing-proxy-fence-proof "$1" --output-dir "$scratch/output"
}

if run_probe "$scratch/bad-proof.json" >/dev/null 2>&1; then
  fail 'invalid signing-proxy fence proof unexpectedly reached the ceremony'
else
  status=$?
fi
test "$status" -eq 65 || fail "invalid proof exited $status instead of 65"

if MOCK_CLIENT_PODS='pod/validator-hoodi-example-client' run_probe "$scratch/proof.json" >/dev/null 2>&1; then
  fail 'live validator client Pod unexpectedly reached the ceremony'
else
  status=$?
fi
test "$status" -eq 65 || fail "live client Pod exited $status instead of 65"

if MOCK_STATEFUL_REPLICAS=1 run_probe "$scratch/proof.json" >/dev/null 2>&1; then
  fail 'nonzero StatefulSet without Pods unexpectedly reached the ceremony'
else
  status=$?
fi
test "$status" -eq 65 || fail "nonzero StatefulSet exited $status instead of 65"
if MOCK_STATEFUL_FAIL=true run_probe "$scratch/proof.json" >/dev/null 2>&1; then
  fail 'StatefulSet API failure unexpectedly reached the ceremony'
else
  status=$?
fi
test "$status" -eq 69 || fail "StatefulSet API failure exited $status instead of 69"

printf '%s\n' 'PASS role-revocation probe requires a fresh staged fence proof and zero client Pods, restores the role on failure, and leaves post-recovery duty confirmation outstanding.'
