#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
script="$root/scripts/ops/activate-hoodi-validator-client.sh"
activation_script="$script"
fail() { printf 'FAIL validator activation gate: %s\n' "$*" >&2; exit 1; }
test -f "$script" || fail 'missing activation script'
# Inventory queries select Deployment metadata, not the Pod template labels.
sed -n '/^  name: validator-REPLACE_WITH_VALIDATOR_SET-signing-fence$/,/^spec:$/p' "$root/deploy/validator/client-lease-fence-template.yaml" |
  grep -Fq 'labels: {app.kubernetes.io/component: validator-signing-fence, node-operator.io/validator-set: REPLACE_WITH_VALIDATOR_SET}' || fail 'fence Deployment is invisible to activation inventory'
bash -n "$script"
command -v jq >/dev/null 2>&1 || fail 'jq is required for offline activation-gate tests'

scratch="$(mktemp -d /private/tmp/node-operator-validator-activation.XXXXXX)"
trap 'rm -rf "$scratch"' EXIT
mkdir -p "$scratch/bin"
public_key="0x$(printf 'a%.0s' {1..96})"
withdrawal_address="0x$(printf 'b%.0s' {1..40})"
validator_set='hoodi-example'
client="validator-${validator_set}-client"
fence="validator-${validator_set}-signing-fence"
canonical_client_image='123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/node-operator-baseline-validator-prysm@sha256:f35410bedf15c5a7b710769e1c67c5f77e74f75544fd51084f12d47082c457e3'
canonical_fence_image='123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/node-operator-baseline-validator-fence@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'
client_image="$canonical_client_image"
fence_image="$canonical_fence_image"
direct_client_image='123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/node-operator-example-baseline-validator-prysm@sha256:2789e2433b907019958b6d558c6e19b27dc9af7fe10e38684a1a64fccb48263d'
direct_fence_image='123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/node-operator-example-baseline-validator-fence@sha256:951312f79c693eae0a9b3e54961701944e0e1339d997f0f3315a25112dcb7fb8'
now_epoch="$(date -u +%s)"

timestamp() { jq -nr --argjson epoch "$1" '$epoch | strftime("%Y-%m-%dT%H:%M:%S.123Z")'; }

write_valid_evidence() {
  local observed="$1" withdrawal_credentials="0x010000000000000000000000${withdrawal_address#0x}"
  jq -n --arg key "$public_key" --arg withdrawal "$withdrawal_address" '{validator_public_key:$key,withdrawal_address:$withdrawal}' > "$scratch/deposit.json"
  jq -n --arg key "$public_key" --arg set "$validator_set" --arg withdrawal "$withdrawal_credentials" '{network:"hoodi",chain_id:560048,validator_set:$set,validator_public_key:$key,withdrawal_credentials:$withdrawal,deposit_amount_gwei:32000000000,receipt_status:"0x1",ssz_roots_match:true,bls_signature_valid:true,event_matches_public_file:true,secret_material_accessed:false}' > "$scratch/public.json"
  jq -n --arg key "$public_key" --arg set "$validator_set" --arg observed "$observed" '{schema_version:1,event_type:"uc-3",network:"hoodi",validator_set:$set,source:"private-beacon",validator_public_key:$key,collected_at_utc:$observed,payload:{syncing:{is_syncing:false,is_optimistic:false,el_offline:false},validator_http_status:"200",validator:{status:"active_ongoing",validator:{pubkey:$key},index:"123"}}}' > "$scratch/private.json"
  jq -n --arg key "$public_key" --arg set "$validator_set" --arg observed "$observed" '{schema_version:1,event_type:"signer-public-key",network:"hoodi",validator_set:$set,source:"web3signer-tls",validator_public_key:$key,collected_at_utc:$observed,tls_verified:true,public_key_count:1,public_key_match:true}' > "$scratch/signer.json"
  jq -n --arg observed "$observed" '{spec:{holderIdentity:"reviewed-signer-holder",leaseDurationSeconds:300,renewTime:$observed}}' > "$scratch/lease.json"
}

write_valid_inventory() {
  printf '%s\n' '{"items":[]}' > "$scratch/deployments.json"
  jq -n --arg client "$client" --arg set "$validator_set" --arg image "$client_image" '{items:[{metadata:{namespace:"validator-operations",name:$client,uid:"client-controller",resourceVersion:"1",labels:{"node-operator.io/validator-set":$set}},spec:{replicas:0,serviceName:("validator-"+$set+"-client-headless"),template:{metadata:{labels:{"node-operator.io/validator-set":$set}},spec:{containers:[{name:"validator",image:$image}]}}}}]}' > "$scratch/statefulsets.json"
  jq -n --arg fence "$fence" --arg set "$validator_set" --arg image "$fence_image" '{items:[{
    metadata:{namespace:"validator-operations",name:$fence,uid:"fence-controller",resourceVersion:"1",labels:{"node-operator.io/validator-set":$set}},
    spec:{replicas:0,template:{metadata:{labels:{"node-operator.io/validator-set":$set}},spec:{containers:[{image:$image}]}}}
  }]}' > "$scratch/fences.json"
  printf '%s\n' '{"items":[]}' > "$scratch/pods.json"
  jq -n --arg set "$validator_set" '{spec:{selector:{"app.kubernetes.io/component":"validator-signing-fence","node-operator.io/validator-set":$set},ports:[{port:9000,targetPort:"fence-proxy"}]}}' > "$scratch/public-service.json"
  jq -n --arg set "$validator_set" '{spec:{selector:{"app.kubernetes.io/component":"validator-remote-signer","node-operator.io/validator-set":$set},ports:[{port:9000,targetPort:"signer-api"}]}}' > "$scratch/direct-service.json"
}

cat > "$scratch/bin/kubectl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
case "$*" in
  '-n validator-operations get configmap uc5-hoodi-example-maintenance --ignore-not-found -o json')
    [ "${MOCK_MARKER_ERROR:-false}" = false ] || exit 1
    if [ "${MOCK_MARKER_PRESENT:-false}" = true ]; then printf '%s' '{"metadata":{"uid":"owned-by-other"}}'; fi ;;
  'get deployments --all-namespaces -l app.kubernetes.io/component=validator-client -o json') cat "$MOCK_DEPLOYMENTS" ;;
  'get pods --all-namespaces -l app.kubernetes.io/component=validator-client -o json') cat "$MOCK_PODS" ;;
  'get statefulsets --all-namespaces -l app.kubernetes.io/component=validator-client -o json') cat "$MOCK_STATEFULSETS" ;;
  'get deployments --all-namespaces -l app.kubernetes.io/component=validator-signing-fence -o json') cat "$MOCK_FENCES" ;;
  '-n validator-operations get service validator-hoodi-example-remote-signer -o json') cat "$MOCK_PUBLIC_SERVICE" ;;
  '-n validator-operations get service validator-hoodi-example-remote-signer-direct -o json') cat "$MOCK_DIRECT_SERVICE" ;;
  '-n validator-operations get deployment validator-hoodi-example-remote-signer -o jsonpath={.spec.replicas}') printf '%s' 1 ;;
  '-n validator-operations get statefulset validator-hoodi-example-client -o json')
    replacement="${MOCK_REPLACE_CLIENT:-client-controller}"
    if [ "${MOCK_REPLACE_ON_ROLLBACK:-false}" = true ] && [ -f "${MOCK_TRACE}.rollback" ]; then replacement=replaced; fi
    jq --arg uid "$replacement" --argjson replicas "$(grep -q 'patch statefulset validator-hoodi-example-client' "$MOCK_TRACE" && printf 1 || printf 0)" '.items[0].metadata.uid=$uid | .items[0].spec.replicas=$replicas | .items[0]' "$MOCK_STATEFULSETS" ;;
  '-n validator-operations get deployment validator-hoodi-example-signing-fence -o json') jq --argjson replicas "$(grep -q 'patch deployment validator-hoodi-example-signing-fence' "$MOCK_TRACE" && printf 1 || printf 0)" '.items[0].spec.replicas=$replicas | .items[0]' "$MOCK_FENCES" ;;
  *' patch statefulset validator-hoodi-example-client --type=json -p '*|*' patch deployment validator-hoodi-example-signing-fence --type=json -p '*) printf '%s\n' "scale $*" >> "$MOCK_TRACE" ;;
  '-n validator-operations scale statefulset validator-hoodi-example-client --replicas=1'|'-n validator-operations scale deployment validator-hoodi-example-signing-fence --replicas=1') printf '%s\n' "scale $*" >> "$MOCK_TRACE" ;;
  '-n validator-operations scale statefulset validator-hoodi-example-client --replicas=0'|'-n validator-operations scale deployment validator-hoodi-example-signing-fence --replicas=0') printf '%s\n' "rollback $*" >> "$MOCK_TRACE" ;;
  '-n validator-operations get deployment validator-hoodi-example-signing-fence -o jsonpath={.spec.replicas}'|'-n validator-operations get statefulset validator-hoodi-example-client -o jsonpath={.spec.replicas}') [ "${MOCK_ROLLBACK_VERIFY_FAIL:-false}" = false ] && printf '%s' 0 ;;
  '-n validator-operations rollout status statefulset validator-hoodi-example-client --timeout=120s') ;;
  '-n validator-operations rollout status deployment validator-hoodi-example-signing-fence --timeout=120s')
    if [ "${MOCK_FENCE_ROLLOUT_FAIL:-false}" = true ]; then touch "${MOCK_TRACE}.rollback"; exit 1; fi ;;
  '-n validator-operations get pod validator-hoodi-example-client-0 -o json') cat "$MOCK_CLIENT_POD" ;;
  '-n validator-operations get pods -l app.kubernetes.io/component=validator-signing-fence,node-operator.io/validator-set=hoodi-example -o json') cat "$MOCK_FENCE_PODS" ;;
  '-n validator-operations get lease validator-hoodi-example-primary -o json') cat "$MOCK_LEASE" ;;
  *) printf 'unexpected kubectl invocation: %s\n' "$*" >&2; exit 64 ;;
esac
EOF
chmod +x "$scratch/bin/kubectl"

run_gate() {
  PATH="$scratch/bin:$PATH" MOCK_DEPLOYMENTS="$scratch/deployments.json" MOCK_PODS="$scratch/pods.json" MOCK_STATEFULSETS="$scratch/statefulsets.json" MOCK_FENCES="$scratch/fences.json" MOCK_PUBLIC_SERVICE="$scratch/public-service.json" MOCK_DIRECT_SERVICE="$scratch/direct-service.json" MOCK_LEASE="$scratch/lease.json" MOCK_CLIENT_POD="$scratch/client-pod.json" MOCK_FENCE_PODS="$scratch/fence-pods.json" MOCK_TRACE="$scratch/trace" \
    bash "$activation_script" --validator-set "$validator_set" --deposit-attestation "$scratch/deposit.json" --public-deposit-verification "$scratch/public.json" --private-evidence "$scratch/private.json" --signer-evidence "$scratch/signer.json" --confirm-public-key "$public_key" --confirm-withdrawal-address "$withdrawal_address" --dry-run "$@"
}
run_gate_actual() {
  run_gate_actual_tty ACTIVATE
}
run_gate_actual_tty() {
  local response="$1"; shift
  PATH="$scratch/bin:$PATH" MOCK_DEPLOYMENTS="$scratch/deployments.json" MOCK_PODS="$scratch/pods.json" MOCK_STATEFULSETS="$scratch/statefulsets.json" MOCK_FENCES="$scratch/fences.json" MOCK_PUBLIC_SERVICE="$scratch/public-service.json" MOCK_DIRECT_SERVICE="$scratch/direct-service.json" MOCK_LEASE="$scratch/lease.json" MOCK_CLIENT_POD="$scratch/client-pod.json" MOCK_FENCE_PODS="$scratch/fence-pods.json" MOCK_TRACE="$scratch/trace" \
    ACTIVATION_SCRIPT="$activation_script" ACTIVATION_RESPONSE="$response" ACTIVATION_SET="$validator_set" ACTIVATION_DEPOSIT="$scratch/deposit.json" ACTIVATION_PUBLIC="$scratch/public.json" ACTIVATION_PRIVATE="$scratch/private.json" ACTIVATION_SIGNER="$scratch/signer.json" ACTIVATION_KEY="$public_key" ACTIVATION_WITHDRAWAL="$withdrawal_address" ACTIVATION_EXTRA="$*" MOCK_READER_LOG="$scratch/reader.log" \
    python3 - <<'PY'
import os
import pty
import select
import subprocess
import sys
import time
import fcntl
import termios

command = ["bash", os.environ["ACTIVATION_SCRIPT"], "--validator-set", os.environ["ACTIVATION_SET"],
           "--deposit-attestation", os.environ["ACTIVATION_DEPOSIT"],
           "--public-deposit-verification", os.environ["ACTIVATION_PUBLIC"],
           "--private-evidence", os.environ["ACTIVATION_PRIVATE"], "--signer-evidence", os.environ["ACTIVATION_SIGNER"],
           "--confirm-public-key", os.environ["ACTIVATION_KEY"], "--confirm-withdrawal-address", os.environ["ACTIVATION_WITHDRAWAL"]]
command += os.environ.get("ACTIVATION_EXTRA", "").split()
response = os.environ["ACTIVATION_RESPONSE"]
if response == "NONTTY":
    result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            start_new_session=True, check=False)
    sys.stdout.buffer.write(result.stdout)
    raise SystemExit(result.returncode)

master, slave = pty.openpty()
def make_controlling_terminal():
    os.setsid()
    fcntl.ioctl(0, termios.TIOCSCTTY, 0)
process = subprocess.Popen(command, stdin=slave, stdout=slave, stderr=slave, close_fds=True,
                           preexec_fn=make_controlling_terminal)
os.close(slave)
output = b""
deadline = time.monotonic() + 15
prompt = b"Type exactly ACTIVATE to scale the validator client and signing fence: "
while prompt not in output and process.poll() is None and time.monotonic() < deadline:
    ready, _, _ = select.select([master], [], [], 0.2)
    if ready:
        try:
            output += os.read(master, 65536)
        except OSError:
            break
if prompt not in output:
    process.terminate()
    process.wait(timeout=5)
    sys.stdout.buffer.write(output)
    raise SystemExit("activation confirmation prompt was not reached")
if response == "EOF":
    os.write(master, b"\x04")
else:
    os.write(master, response.encode("ascii") + b"\n")
while process.poll() is None:
    ready, _, _ = select.select([master], [], [], 0.2)
    if ready:
        try:
            output += os.read(master, 65536)
        except OSError:
            break
process.wait(timeout=5)
while True:
    ready, _, _ = select.select([master], [], [], 0)
    if not ready:
        break
    try:
        chunk = os.read(master, 65536)
    except OSError:
        break
    if not chunk:
        break
    output += chunk
os.close(master)
sys.stdout.buffer.write(output)
raise SystemExit(process.returncode)
PY
}
reset_fixture() {
  local observed; client_image="$canonical_client_image"; fence_image="$canonical_fence_image"; observed="$(timestamp "$now_epoch")"; write_valid_evidence "$observed"; write_valid_inventory
  jq -n --arg set "$validator_set" '{metadata:{name:"validator-hoodi-example-client-0",uid:"client-uid",labels:{"node-operator.io/validator-set":$set,"app.kubernetes.io/component":"validator-client"}},status:{podIP:"10.0.0.10",phase:"Running",conditions:[{type:"Ready",status:"True"}]}}' > "$scratch/client-pod.json"
  jq -n --arg set "$validator_set" '{items:[{metadata:{name:"validator-hoodi-example-signing-fence-pod",uid:"fence-uid",labels:{"node-operator.io/validator-set":$set,"app.kubernetes.io/component":"validator-signing-fence"}},status:{phase:"Running",conditions:[{type:"Ready",status:"True"}]}}]}' > "$scratch/fence-pods.json"
  jq -n --arg observed "$observed" '{metadata:{uid:"lease-uid"},spec:{holderIdentity:"fence-uid",leaseDurationSeconds:60,renewTime:$observed}}' > "$scratch/lease.json"
  jq '.metadata.labels["node-operator.io/deployment-name"] = "node-op-auth" | .metadata.labels["node-operator.io/release-revision"] = ("a" * 40)' "$scratch/client-pod.json" > "$scratch/client-pod.next"
  mv "$scratch/client-pod.next" "$scratch/client-pod.json"
  jq '.items[0].metadata.labels["node-operator.io/deployment-name"] = "node-op-auth" | .items[0].metadata.labels["node-operator.io/release-revision"] = ("a" * 40)' "$scratch/fence-pods.json" > "$scratch/fence-pods.next"
  mv "$scratch/fence-pods.next" "$scratch/fence-pods.json"
  : > "$scratch/trace"
  rm -f "$scratch/trace.rollback"
}
expect_rejected() {
  local name="$1" status
  if run_gate >/dev/null 2>&1; then fail "$name unexpectedly passed"; else status=$?; fi
  test "$status" -eq 65 || fail "$name exited $status instead of 65"
  test ! -s "$scratch/trace" || fail "$name reached a scale request"
}

reset_fixture
dry_run_output="$(run_gate)"
grep -Fq 'PASS: activation preflight passed; client and signing fence remain at zero because --dry-run was set.' <<<"$dry_run_output" || fail 'valid fractional-second evidence did not pass dry-run gate'
if grep -Fq 'Type exactly ACTIVATE' <<<"$dry_run_output"; then fail 'dry-run prompted for activation confirmation'; fi
test ! -s "$scratch/trace" || fail 'happy dry-run reached a scale request'

reset_fixture; client_image="$direct_client_image"; fence_image="$direct_fence_image"; write_valid_inventory
run_gate | grep -Fq 'PASS: activation preflight passed; client and signing fence remain at zero because --dry-run was set.' || fail 'exact task-approved direct client and release-bound fence did not pass dry-run gate'
test ! -s "$scratch/trace" || fail 'exact direct dry-run reached a scale request'

reset_fixture; client_image="${direct_client_image/node-operator-example/other-deployment}"; fence_image="$direct_fence_image"; write_valid_inventory; expect_rejected 'wrong direct client deployment repository'
reset_fixture; client_image="${direct_client_image/123456789012/123456789012}"; fence_image="$direct_fence_image"; write_valid_inventory; expect_rejected 'wrong direct client registry account'
reset_fixture; client_image="${direct_client_image%?}0"; fence_image="$direct_fence_image"; write_valid_inventory; expect_rejected 'wrong direct client digest'
reset_fixture; client_image="$direct_client_image"; fence_image="${direct_fence_image%?}0"; write_valid_inventory; expect_rejected 'wrong release-bound fence digest'

reset_fixture
if run_gate_actual_tty CANCEL >/dev/null 2>&1; then fail 'cancelled activation unexpectedly passed'; else status=$?; fi
test "$status" -eq 65 || fail "cancelled activation exited $status instead of 65"
test ! -s "$scratch/trace" || fail 'cancelled activation reached a scale request'

reset_fixture
if run_gate_actual_tty EOF >/dev/null 2>&1; then fail 'EOF activation confirmation unexpectedly passed'; else status=$?; fi
test "$status" -eq 65 || fail "EOF activation confirmation exited $status instead of 65"
test ! -s "$scratch/trace" || fail 'EOF activation confirmation reached a scale request'

reset_fixture
if run_gate_actual_tty NONTTY >/dev/null 2>&1; then fail 'non-interactive activation unexpectedly passed'; else status=$?; fi
test "$status" -eq 65 || fail "non-interactive activation exited $status instead of 65"
test ! -s "$scratch/trace" || fail 'non-interactive activation reached a scale request'

reset_fixture
run_gate_actual | grep -Fq "Activation request: validator set=$validator_set public key=$public_key withdrawal address=$withdrawal_address" || fail 'literal activation confirmation did not display normalized identity'
test "$(grep -c '^scale ' "$scratch/trace")" -eq 2 || fail 'actual activation did not perform exactly two identity-pinned patches'
grep -Fq 'patch statefulset validator-hoodi-example-client --type=json' "$scratch/trace" || fail 'client UID/resourceVersion patch was not used'
grep -Fq 'patch deployment validator-hoodi-example-signing-fence --type=json' "$scratch/trace" || fail 'fence UID/resourceVersion patch was not used'

receipt_root="$scratch/receipt-root"
mkdir -p "$receipt_root/scripts/ops/lib" "$receipt_root/.ci/validator"
cp "$script" "$receipt_root/scripts/ops/activate-hoodi-validator-client.sh"
cp "$root/.ci/validator/approved-client-images.json" "$receipt_root/.ci/validator/approved-client-images.json"
cat > "$receipt_root/scripts/ops/lib/uc5-beacon-reader.py" <<'PY'
import json, os
def read_ready(public_key):
    if os.environ.get("MOCK_READER_FAIL") == "true": raise RuntimeError("synthetic reader failure")
    with open(os.environ["MOCK_READER_LOG"], "a", encoding="utf-8") as log: log.write(public_key + "\n")
    return {"result":"PASS_PRIVATE_BEACON_READY","scope":"private Beacon readiness only; not duty evidence","pod_uid":"beacon-pod-uid","validator_public_key":public_key,"validator_index":"1559065","head_slot":json.loads(os.environ.get("MOCK_READER_HEAD", "123456"))}
PY
chmod +x "$receipt_root/scripts/ops/activate-hoodi-validator-client.sh"
activation_script="$receipt_root/scripts/ops/activate-hoodi-validator-client.sh"
receipt_dir="$scratch/activation-receipt"; mkdir -m 700 "$receipt_dir"
receipt="$receipt_dir/activation.json"
reset_fixture
run_gate_actual_tty ACTIVATE --activation-receipt "$receipt" --deployment-name node-op-auth --release-revision aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa --operation-id bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb >/dev/null || fail 'receipt-bound activation failed'
test "$(stat -f '%Lp' "$receipt" 2>/dev/null || stat -c '%a' "$receipt")" = 600 || fail 'activation receipt is not mode 0600'
jq -e --arg key "$public_key" '.schema_version == 1 and .result == "activation-post-ready-head-bound" and .validator_public_key == $key and .deployment_name == "node-op-auth" and .release_revision == "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" and .operation_id == "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" and .controllers == {client_statefulset_uid:"client-controller",fence_deployment_uid:"fence-controller"} and .pods == {client_uid:"client-uid",fence_uid:"fence-uid"} and .lease == {uid:"lease-uid",holder_identity:"fence-uid"} and .private_beacon == {pod_uid:"beacon-pod-uid",validator_index:"1559065",head_slot:123456} and (.scope | contains("lower bound only"))' "$receipt" >/dev/null || fail 'activation receipt is not exact post-Ready evidence'
test "$(cat "$scratch/reader.log")" = "$public_key" || fail 'activation did not invoke the fixed read_ready collector'

reset_fixture
if run_gate_actual_tty ACTIVATE --activation-receipt "$receipt" --deployment-name node-op-auth --release-revision aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa --operation-id bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb >/dev/null 2>&1; then fail 'existing activation receipt was overwritten'; fi
test ! -s "$scratch/trace" || fail 'existing activation receipt reached a scale request'

reset_fixture
if run_gate --activation-receipt "$receipt_dir/dry.json" >/dev/null 2>&1; then fail 'dry-run accepted activation receipt arguments'; fi
test ! -s "$scratch/trace" || fail 'invalid dry-run receipt group reached a scale request'
if run_gate_actual_tty ACTIVATE --activation-receipt "$receipt_dir/partial.json" --deployment-name node-op-auth >/dev/null 2>&1; then fail 'partial activation receipt group was accepted'; fi
test ! -s "$scratch/trace" || fail 'partial receipt group reached a scale request'

reset_fixture
failed_receipt="$receipt_dir/reader-failed.json"
if MOCK_READER_FAIL=true run_gate_actual_tty ACTIVATE --activation-receipt "$failed_receipt" --deployment-name node-op-auth --release-revision aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa --operation-id cccccccccccccccccccccccccccccccc >/dev/null 2>&1; then fail 'failed post-Ready reader reported activation success'; fi
test ! -e "$failed_receipt" || fail 'failed post-Ready reader wrote an activation receipt'
test "$(grep -c '^scale ' "$scratch/trace")" -eq 4 || fail 'failed post-Ready reader did not perform checked rollback'

reset_fixture
jq '.metadata.labels["node-operator.io/release-revision"] = ("f" * 40)' "$scratch/client-pod.json" > "$scratch/client-pod.next"; mv "$scratch/client-pod.next" "$scratch/client-pod.json"
label_failed_receipt="$receipt_dir/label-failed.json"
if run_gate_actual_tty ACTIVATE --activation-receipt "$label_failed_receipt" --deployment-name node-op-auth --release-revision aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa --operation-id dddddddddddddddddddddddddddddddd >/dev/null 2>&1; then fail 'mismatched post-Ready release label reported activation success'; fi
test ! -e "$label_failed_receipt" || fail 'mismatched post-Ready labels wrote an activation receipt'
test "$(grep -c '^scale ' "$scratch/trace")" -eq 4 || fail 'mismatched post-Ready labels did not perform checked rollback'

reset_fixture
fractional_receipt="$receipt_dir/fractional-head.json"
if MOCK_READER_HEAD=12.5 run_gate_actual_tty ACTIVATE --activation-receipt "$fractional_receipt" --deployment-name node-op-auth --release-revision aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa --operation-id eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee >/dev/null 2>&1; then fail 'fractional private Beacon head reported activation success'; fi
test ! -e "$fractional_receipt" || fail 'fractional private Beacon head wrote an activation receipt'
test "$(grep -c '^scale ' "$scratch/trace")" -eq 4 || fail 'fractional private Beacon head did not perform checked rollback'
activation_script="$script"

reset_fixture
if MOCK_REPLACE_CLIENT=replaced run_gate_actual >/dev/null 2>&1; then fail 'replacement client activated'; fi
if grep -Fq 'patch statefulset validator-hoodi-example-client' "$scratch/trace"; then fail 'replacement client was mutated'; fi

reset_fixture
if MOCK_FENCE_ROLLOUT_FAIL=true MOCK_REPLACE_ON_ROLLBACK=true run_gate_actual >/dev/null 2>&1; then fail 'replacement rollback reported success'; fi
test "$(grep -c 'patch statefulset validator-hoodi-example-client' "$scratch/trace")" -eq 1 || fail 'replacement client was mutated during rollback'

reset_fixture
if MOCK_MARKER_PRESENT=true run_gate_actual >/dev/null 2>&1; then fail 'maintenance marker did not block activation'; fi
test ! -s "$scratch/trace" || fail 'maintenance marker allowed a patch'

reset_fixture
if MOCK_MARKER_ERROR=true run_gate_actual >/dev/null 2>&1; then fail 'failed marker lookup allowed activation'; fi
test ! -s "$scratch/trace" || fail 'failed marker lookup allowed a patch'

reset_fixture
jq '.source = "vault-injected-mtls-get-only-probe" | .vault_agent_init_succeeded = true' "$scratch/signer.json" > "$scratch/signer.next"
mv "$scratch/signer.next" "$scratch/signer.json"
run_gate | grep -Fq 'PASS: activation preflight passed; client and signing fence remain at zero because --dry-run was set.' || fail 'Vault-injected GET-only signer evidence with successful init did not pass dry-run gate'
test ! -s "$scratch/trace" || fail 'Vault-injected GET-only dry-run reached a scale request'

reset_fixture
jq '.source = "vault-injected-mtls-get-only-probe" | .vault_agent_init_succeeded = false' "$scratch/signer.json" > "$scratch/signer.next"
mv "$scratch/signer.next" "$scratch/signer.json"
expect_rejected 'Vault-injected GET-only signer evidence without successful Vault init'

reset_fixture
jq '.source = "untrusted-signer-probe" | .vault_agent_init_succeeded = true' "$scratch/signer.json" > "$scratch/signer.next"
mv "$scratch/signer.next" "$scratch/signer.json"
expect_rejected 'unrecognized signer evidence source'

reset_fixture
if MOCK_FENCE_ROLLOUT_FAIL=true run_gate_actual >/dev/null 2>&1; then fail 'failed fence rollout unexpectedly activated'; fi
grep -Fq 'patch deployment validator-hoodi-example-signing-fence --type=json' "$scratch/trace" || fail 'failed fence rollout did not use identity-pinned rollback'
grep -Fq 'patch statefulset validator-hoodi-example-client --type=json' "$scratch/trace" || fail 'failed fence rollout did not use identity-pinned rollback'

reset_fixture
status=0
MOCK_FENCE_ROLLOUT_FAIL=true MOCK_ROLLBACK_VERIFY_FAIL=true run_gate_actual >/dev/null 2>&1 || status=$?
test "$status" -eq 70 || fail "unverified rollback exited $status instead of critical 70"

reset_fixture; write_valid_evidence "$(timestamp $((now_epoch - 301)))"; expect_rejected 'stale private and signer evidence'
reset_fixture; jq --arg observed "$(timestamp $((now_epoch + 61)))" '.collected_at_utc = $observed' "$scratch/private.json" > "$scratch/private.next"; mv "$scratch/private.next" "$scratch/private.json"; expect_rejected 'future private evidence'
reset_fixture; jq 'del(.payload.validator.validator) | .payload.validator.pubkey = .validator_public_key' "$scratch/private.json" > "$scratch/private.next"; mv "$scratch/private.next" "$scratch/private.json"; expect_rejected 'wrong nested validator key'
reset_fixture; jq '.payload.syncing.is_optimistic = true' "$scratch/private.json" > "$scratch/private.next"; mv "$scratch/private.next" "$scratch/private.json"; expect_rejected 'optimistic private evidence'
reset_fixture; jq '.payload.syncing.el_offline = true' "$scratch/private.json" > "$scratch/private.next"; mv "$scratch/private.next" "$scratch/private.json"; expect_rejected 'execution-layer-offline private evidence'
reset_fixture; jq '.event_matches_public_file = false' "$scratch/public.json" > "$scratch/public.next"; mv "$scratch/public.next" "$scratch/public.json"; expect_rejected 'public deposit proof mismatch'
reset_fixture; jq '.validator_set = "hoodi-002"' "$scratch/public.json" > "$scratch/public.next"; mv "$scratch/public.next" "$scratch/public.json"; expect_rejected 'public deposit validator-set mismatch'
reset_fixture; jq '.validator_public_key = ("0x" + ("c" * 96))' "$scratch/signer.json" > "$scratch/signer.next"; mv "$scratch/signer.next" "$scratch/signer.json"; expect_rejected 'signer identity mismatch'
reset_fixture; jq '.items += [.items[0] | .metadata.name = "validator-hoodi-002-client"]' "$scratch/statefulsets.json" > "$scratch/statefulsets.next"; mv "$scratch/statefulsets.next" "$scratch/statefulsets.json"; expect_rejected 'multiple cluster-wide client StatefulSets'
reset_fixture; jq '.items=[{metadata:{name:"legacy-client"}}]' "$scratch/deployments.json" > "$scratch/deployments.next"; mv "$scratch/deployments.next" "$scratch/deployments.json"; expect_rejected 'legacy client Deployment'
reset_fixture; jq '.spec.selector["app.kubernetes.io/component"]="validator-remote-signer"' "$scratch/public-service.json" > "$scratch/public-service.next"; mv "$scratch/public-service.next" "$scratch/public-service.json"; expect_rejected 'direct signer service bypass'
reset_fixture; jq -n '{items:[{metadata:{namespace:"validator-operations",name:"validator-client-pod"}}]}' > "$scratch/pods.json"; expect_rejected 'cluster-wide validator client Pod'
reset_fixture; jq '.items[0].spec.template.spec.containers[0].image |= sub("node-operator-baseline-validator-prysm"; "copied-validator-prysm")' "$scratch/statefulsets.json" > "$scratch/statefulsets.next"; mv "$scratch/statefulsets.next" "$scratch/statefulsets.json"; expect_rejected 'copied client digest in another repository'

contract_root="$scratch/contract-root"
mkdir -p "$contract_root/scripts/ops" "$contract_root/.ci/validator"
cp "$script" "$contract_root/scripts/ops/activate-hoodi-validator-client.sh"
chmod +x "$contract_root/scripts/ops/activate-hoodi-validator-client.sh"
activation_script="$contract_root/scripts/ops/activate-hoodi-validator-client.sh"
reset_fixture; jq '(.images[] | select(.release_channel == "manual-native-mtls")).activation_approved = false' "$root/.ci/validator/approved-client-images.json" > "$contract_root/.ci/validator/approved-client-images.json"; expect_rejected 'activation-unapproved native client image'
reset_fixture; jq 'del(.images[] | select(.release_channel == "manual-native-mtls").release_channel)' "$root/.ci/validator/approved-client-images.json" > "$contract_root/.ci/validator/approved-client-images.json"; expect_rejected 'native client image missing release channel'
activation_script="$script"

printf '%s\n' 'PASS validator activation gate enforces public proof, fresh private/signer evidence, fencing, and exact singleton client inventory offline.'
