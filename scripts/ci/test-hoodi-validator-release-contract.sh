#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
script="$root/scripts/release/hoodi-validator-release.sh"
scratch="$(mktemp -d /private/tmp/node-operator-validator-release.XXXXXX)"
bundle="$scratch/bundle"; inputs="$scratch/inputs"; trace="$scratch/trace"; fake_bin="$scratch/bin"
mkdir -p "$bundle/source/scripts/release" "$bundle/source/scripts/ops" "$inputs/zero-resource" "$inputs/validator-deployment" "$fake_bin"
printf '{"source_revision":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}\n' > "$bundle/bundle-manifest.json"
cat > "$bundle/source/scripts/release/node-operator-release.sh" <<'SCRIPT'
#!/usr/bin/env bash
printf 'release %s\n' "$*" >> "$TRACE"
action="${1:-}:${2:-}"
if [ "$action" = 'zero:prepare-artifacts' ] || [ "$action" = 'zero:apply' ]; then
  while [ "$#" -gt 0 ]; do
    case "$1" in --work-dir) work_dir="$2"; shift 2 ;; *) shift ;; esac
  done
  mkdir -p "$work_dir"
  chmod 700 "$work_dir"
fi
if [ "$action" = 'zero:apply' ]; then
  jq -n '{schema_version:"v1",aws_account_id:"123456789012"}' > "$work_dir/ops-access-handoff.json"
fi
SCRIPT
cat > "$bundle/source/scripts/release/custody_verifier_runtime.py" <<'SCRIPT'
#!/usr/bin/env python3
import os, sys
if os.environ.get("CUSTODY_RUNTIME_FAIL") == "1":
    raise SystemExit(65)
print('{"python":"/fixture/custody/venv/bin/python","upstream_root":"/fixture/custody/upstream"}')
SCRIPT
cat > "$bundle/source/scripts/release/installer_artifact_inventory.py" <<'SCRIPT'
#!/usr/bin/env python3
import os, sys
if any(os.environ.get(key) for key in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_SECURITY_TOKEN")):
    raise SystemExit(65)
with open(os.environ["TRACE"], "a", encoding="utf-8") as out:
    out.write("inventory " + " ".join(sys.argv[1:]) + " profile=" + os.environ.get("AWS_PROFILE", "") + "\n")
if os.environ.get("INVENTORY_MODE") == "fail":
    raise SystemExit(65)
print('{"schema_version":1,"complete":true,"release_revision":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","deployment":{"aws_account_id":"123456789012","aws_region":"ap-northeast-2","deployment_name":"node-op-001"},"artifacts":[{"component":"validator-signer-identity-probe","required":true,"status":"source-approved","authority":"signer-probe-release-authorization","source":"111111111111.dkr.ecr.ap-northeast-1.amazonaws.com/source-node-baseline-validator-signer-identity-probe@sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff","destination":"123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/node-op-001-baseline-validator-signer-identity-probe@sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"}]}')
SCRIPT
cat > "$bundle/source/scripts/release/mirror-installer-vault-artifacts.py" <<'SCRIPT'
#!/usr/bin/env python3
import os, sys
if any(os.environ.get(key) for key in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_SECURITY_TOKEN")):
    raise SystemExit(65)
with open(os.environ["TRACE"], "a", encoding="utf-8") as out:
    out.write("mirror " + " ".join(sys.argv[1:]) + " profile=" + os.environ.get("AWS_PROFILE", "") + "\n")
SCRIPT
cat > "$bundle/source/scripts/release/verify-platform-private-eks-session.py" <<'SCRIPT'
#!/usr/bin/env python3
import json
import os
import sys

arguments = sys.argv[1:]
values = {}
while arguments:
    key = arguments.pop(0)
    if key.startswith("--"):
        values[key] = arguments.pop(0)
expected = {
    "--work-dir": os.path.join(os.path.dirname(values["--session"]), "deployment-work"),
    "--baseline-config": os.path.join(os.path.dirname(values["--session"]), "inputs", "zero-resource", "baseline.tfvars.json"),
    "--account": "123456789012", "--region": "ap-northeast-2", "--profile": "chosen",
}
if any(values.get(key) != value for key, value in expected.items()):
    raise SystemExit(65)
if os.environ.get("AWS_PROFILE") != "chosen" or os.environ.get("AWS_REGION") != "ap-northeast-2":
    raise SystemExit(65)
with open(values["--session"], encoding="utf-8") as handle:
    session = json.load(handle)
if session.get("cluster_name") != "hoodi-release-001" or session.get("ssm_ops_instance_id") != "i-0123456789abcdef0":
    raise SystemExit(65)
print("hoodi-release-001\ti-0123456789abcdef0")
SCRIPT
cat > "$fake_bin/aws" <<'SCRIPT'
#!/usr/bin/env bash
set -euo pipefail
[ -z "${AWS_ACCESS_KEY_ID:-}${AWS_SECRET_ACCESS_KEY:-}${AWS_SESSION_TOKEN:-}${AWS_SECURITY_TOKEN:-}" ] || exit 65
printf 'aws %s profile=%s\n' "$*" "${AWS_PROFILE:-}" >> "$TRACE"
case "${1:-}:${2:-}" in
  sts:get-caller-identity) printf '123456789012\n' ;;
  eks:describe-cluster) printf 'https://localhost\n' ;;
  *) exit 64 ;;
esac
SCRIPT
cat > "$bundle/source/scripts/release/stage-hoodi-validator-deployment.sh" <<'SCRIPT'
#!/usr/bin/env bash
printf 'stage %s\n' "$*" >> "$TRACE"
if [ "${1:-}" = verify ] && [ ! -f "$TRACE.staged" ]; then exit 3; fi
if [ "${1:-}" = apply ]; then : > "$TRACE.staged"; fi
SCRIPT
cat > "$bundle/source/scripts/release/prepare-ops-access-inputs.sh" <<'SCRIPT'
#!/usr/bin/env bash
printf 'ops %s\n' "$*" >> "$TRACE"
while [ "$#" -gt 0 ]; do
  case "$1" in --handoff) handoff="$2"; shift 2 ;; --output-dir) output_dir="$2"; shift 2 ;; *) shift ;; esac
done
mkdir -p "$output_dir"
printf '{}' > "$output_dir/ops-access.tfvars.json"
printf '{}' > "$output_dir/ops-access.backend.hcl"
jq -n --arg handoff "$handoff" --arg config "$output_dir/ops-access.tfvars.json" --arg backend "$output_dir/ops-access.backend.hcl" '{schema_version:1,ops_access_handoff:$handoff,config:$config,backend_config:$backend}' > "$output_dir/ops-access-inputs.json"
SCRIPT
cat > "$bundle/source/scripts/release/node-operator-ops-access.sh" <<'SCRIPT'
#!/usr/bin/env bash
printf 'ops-access %s\n' "$*" >> "$TRACE"
operation="$1"; shift
while [ "$#" -gt 0 ]; do
  case "$1" in --plan-file) plan_file="$2"; shift 2 ;; --session-handoff) session_handoff="$2"; shift 2 ;; *) shift ;; esac
done
if [ "$operation" = plan ]; then : > "$plan_file"; fi
if [ "$operation" = apply ]; then jq -n '{schema_version:1,aws_region:"ap-northeast-2",cluster_name:"hoodi-release-001",ssm_ops_instance_id:"i-0123456789abcdef0"}' > "$session_handoff"; fi
SCRIPT
for command in with-private-eks.sh with-private-vault.sh recover-and-bootstrap-hoodi-validator-runtime-vault.sh recover-and-onboard-hoodi-validator-keystore.sh provision-hoodi-transport-tls.sh start-hoodi-validator-signer.sh collect-hoodi-signer-public-key-evidence.sh observe-private-hoodi-validator.sh activate-hoodi-validator-client.sh; do
  cat > "$bundle/source/scripts/ops/$command" <<'SCRIPT'
#!/usr/bin/env bash
set -euo pipefail
if [ "${CUSTODY_ASSERT:-0}" = 1 ] && [[ "$0" == *"with-private-eks.sh" || "$0" == *"with-private-vault.sh" ]]; then
  [ "${AWS_PROFILE:-}" = chosen ] || exit 71
  [ "${AWS_REGION:-}" = ap-northeast-2 ] || exit 72
  [ "${AWS_DEFAULT_REGION:-}" = ap-northeast-2 ] || exit 73
  [ "${EKS_CLUSTER_NAME:-}" = hoodi-release-001 ] || exit 74
  [ "${SSM_OPS_INSTANCE_ID:-}" = i-0123456789abcdef0 ] || exit 75
  [ "${AWS_EC2_METADATA_DISABLED:-}" = true ] || exit 76
  [ "${GITHUB_TOKEN:-}" = preserve-github-token ] || exit 77
  if [[ "$0" == *"with-private-vault.sh" ]]; then
    [ "${PRIVATE_VAULT_TARGET:-}" = pod/vault-0 ] || exit 79
  else
    [ -z "${PRIVATE_VAULT_TARGET:-}" ] || exit 79
  fi
  for key in AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AWS_SECURITY_TOKEN AWS_ACCESS_KEY AWS_SECRET_KEY AWS_DEFAULT_PROFILE AWS_WEB_IDENTITY_TOKEN_FILE AWS_ROLE_ARN AWS_ROLE_SESSION_NAME AWS_CONTAINER_CREDENTIALS_RELATIVE_URI AWS_CONTAINER_CREDENTIALS_FULL_URI AWS_CONTAINER_AUTHORIZATION_TOKEN AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE PRIVATE_EKS_SESSION PRIVATE_VAULT_SESSION KUBECONFIG BASH_ENV ENV VAULT_ADDR VAULT_CACERT VAULT_TLS_SERVER_NAME VAULT_SKIP_VERIFY VAULT_NAMESPACE VAULT_TOKEN; do
    [ -z "${!key:-}" ] || exit 78
  done
  printf 'custody-wrapper %s profile=%s region=%s default-region=%s cluster=%s instance=%s\n' "${0##*/}" "$AWS_PROFILE" "$AWS_REGION" "$AWS_DEFAULT_REGION" "$EKS_CLUSTER_NAME" "$SSM_OPS_INSTANCE_ID" >> "$TRACE"
fi
printf 'activation %s\n' "$*" >> "$TRACE"
SCRIPT
  chmod 700 "$bundle/source/scripts/ops/$command"
done
cp "$root/scripts/ops/verify-custody-validator-key.py" "$bundle/source/scripts/ops/verify-custody-validator-key.py"
chmod 700 "$bundle/source/scripts/ops/verify-custody-validator-key.py"
chmod 700 "$bundle/source/scripts/release/node-operator-release.sh" "$bundle/source/scripts/release/stage-hoodi-validator-deployment.sh" "$bundle/source/scripts/release/prepare-ops-access-inputs.sh" "$bundle/source/scripts/release/node-operator-ops-access.sh" "$bundle/source/scripts/release/installer_artifact_inventory.py" "$bundle/source/scripts/release/mirror-installer-vault-artifacts.py" "$bundle/source/scripts/release/verify-platform-private-eks-session.py" "$fake_bin/aws"
jq -n --arg zero "$inputs/zero-resource/zero-resource-inputs.json" --arg validator "$inputs/validator-deployment/validator-deployment-handoff.json" '{schema_version:1,network:"hoodi",aws_account_id:"123456789012",aws_region:"ap-northeast-2",validator_set:"hoodi-release-001",zero_resource_inputs:$zero,validator_deployment_handoff:$validator,required_checkpoints:[1,2,3,4,5,6]}' > "$inputs/hoodi-zero-release-inputs.json"
jq -n --arg baseline "$inputs/zero-resource/baseline.tfvars.json" '{schema_version:1,aws_account_id:"123456789012",aws_region:"ap-northeast-2",baseline_config:$baseline}' > "$inputs/zero-resource/zero-resource-inputs.json"
jq -n '{name:"node-op-001",aws_account_id:"123456789012",aws_region:"ap-northeast-2"}' > "$inputs/zero-resource/baseline.tfvars.json"
client_manifest="$scratch/validator-client.yaml"
printf '%s\n' 'cidr: 127.0.0.1/32' > "$client_manifest"
jq -n --arg client_manifest "$client_manifest" '{schema_version:1,network:"hoodi",aws_account_id:"123456789012",aws_region:"ap-northeast-2",validator_set:"hoodi-release-001",validator_public_key:("0x" + ("a" * 96)),client_manifest:$client_manifest,staged_client_replicas:0,staged_fence_replicas:0}' > "$inputs/validator-deployment/validator-deployment-handoff.json"
if "$script" interactive prepare --bundle-root "$bundle" --output-dir "$scratch/interactive" </dev/null >/dev/null 2>&1; then
  printf '%s\n' 'interactive preparation unexpectedly accepted a non-terminal input stream' >&2; exit 1
fi
TRACE="$trace" PATH="$fake_bin:$PATH" "$script" infrastructure apply --bundle-root "$bundle" --inputs "$inputs/hoodi-zero-release-inputs.json" --work-dir "$scratch/work" >/dev/null
rg -F "release verify --bundle-root $bundle" "$trace" >/dev/null
rg -F "inventory --bundle-root $bundle --release-sha aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa --aws-account-id 123456789012 --aws-region ap-northeast-2 --deployment-name node-op-001 --require-signer-probe profile=default" "$trace" >/dev/null
rg -F "release zero prepare-artifacts --bundle-root $bundle --inputs $inputs/zero-resource/zero-resource-inputs.json --work-dir $scratch/work --include-publishers" "$trace" >/dev/null
rg -F "mirror mirror --bundle-root $bundle --state-dir $scratch/work --work-dir $scratch/work --inputs-dir $inputs/zero-resource --account 123456789012 --region ap-northeast-2 --deployment-name node-op-001 --profile default --release-sha aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa profile=default" "$trace" >/dev/null
rg -F "mirror mirror --scope non-vault --bundle-root $bundle --state-dir $scratch/work --work-dir $scratch/work --inputs-dir $inputs/zero-resource --account 123456789012 --region ap-northeast-2 --deployment-name node-op-001 --profile default --release-sha aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa profile=default" "$trace" >/dev/null
rg -F "release zero apply --bundle-root $bundle --inputs $inputs/zero-resource/zero-resource-inputs.json --work-dir $scratch/work" "$trace" >/dev/null
inventory_line="$(rg -n '^inventory ' "$trace" | head -n1 | cut -d: -f1)"
prepare_line="$(rg -n '^release zero prepare-artifacts ' "$trace" | head -n1 | cut -d: -f1)"
vault_line="$(rg -n '^mirror mirror --bundle-root ' "$trace" | head -n1 | cut -d: -f1)"
non_vault_line="$(rg -n '^mirror mirror --scope non-vault ' "$trace" | head -n1 | cut -d: -f1)"
apply_line="$(rg -n '^release zero apply ' "$trace" | head -n1 | cut -d: -f1)"
[ "$prepare_line" -lt "$inventory_line" ] && [ "$inventory_line" -lt "$vault_line" ] && [ "$vault_line" -lt "$non_vault_line" ] && [ "$non_vault_line" -lt "$apply_line" ] || { printf '%s\n' 'artifact-first infrastructure order is invalid' >&2; exit 1; }
mkdir -p "$scratch/zero"; printf '{}' > "$scratch/zero/ops-access-handoff.json"
TRACE="$trace" "$script" ops-inputs prepare --bundle-root "$bundle" --inputs "$inputs/hoodi-zero-release-inputs.json" --zero-work-dir "$scratch/zero" --output-dir "$scratch/ops" >/dev/null
rg -F "ops --handoff $scratch/zero/ops-access-handoff.json --output-dir $scratch/ops" "$trace" >/dev/null
mkdir -p "$scratch/ops"
printf '{}' > "$scratch/ops/ops-access.tfvars.json"; printf '{}' > "$scratch/ops/ops-access.backend.hcl"
jq -n --arg handoff "$scratch/zero/ops-access-handoff.json" --arg config "$scratch/ops/ops-access.tfvars.json" --arg backend "$scratch/ops/ops-access.backend.hcl" '{schema_version:1,ops_access_handoff:$handoff,config:$config,backend_config:$backend}' > "$scratch/ops/ops-access-inputs.json"
jq -n '{schema_version:"v1",aws_account_id:"123456789012"}' > "$scratch/zero/ops-access-handoff.json"
mkdir -m 700 "$scratch/plans"
TRACE="$trace" "$script" ops-access plan --bundle-root "$bundle" --inputs "$inputs/hoodi-zero-release-inputs.json" --ops-inputs "$scratch/ops/ops-access-inputs.json" --plan-file "$scratch/plans/ops.tfplan" --allow-create >/dev/null
rg -F "ops-access plan --root $bundle/source --inputs $scratch/ops/ops-access-inputs.json --plan-file $scratch/plans/ops.tfplan --allow-create" "$trace" >/dev/null
rg -F 'deploy apply --bundle-root DIRECTORY --inputs /absolute/hoodi-zero-release-inputs.json' "$script" >/dev/null
rg -F '"entrypoint": "source/scripts/release/hoodi-validator-release.sh"' "$root/release/hoodi-release-contract.json" >/dev/null
rg -F '"deploy apply"' "$root/release/hoodi-release-contract.json" >/dev/null
rg -F '"interactive custody"' "$root/release/hoodi-release-contract.json" >/dev/null
rg -F '"custody apply"' "$root/release/hoodi-release-contract.json" >/dev/null
rg -F '"evidence signer"' "$root/release/hoodi-release-contract.json" >/dev/null
rg -F '"evidence beacon"' "$root/release/hoodi-release-contract.json" >/dev/null
rg -F '"activate apply"' "$root/release/hoodi-release-contract.json" >/dev/null
rg -F '"stage verify"' "$root/release/hoodi-release-contract.json" >/dev/null
rg -F 'activate apply --bundle-root DIRECTORY' "$script" >/dev/null
rg -F 'interactive custody --bundle-root DIRECTORY' "$script" >/dev/null
rg -F 'evidence signer --bundle-root DIRECTORY' "$script" >/dev/null
rg -F 'evidence beacon --bundle-root DIRECTORY' "$script" >/dev/null
rg -F 'NEXT: run %s interactive custody' "$script" >/dev/null
rg -F 'validator private key or keystore' "$root/release/hoodi-release-contract.json" >/dev/null
rg -F 'infrastructure, isolated private-EKS SSM access, and zero-replica validator staging are deployed' "$script" >/dev/null
rg -F 'deploy checkpoint contains an invalid ops-access plan digest' "$script" >/dev/null
deploy_work="$scratch/deploy-work"; deploy_session="$scratch/private-eks-session.json"
TRACE="$trace" PATH="$fake_bin:$PATH" "$script" deploy apply --bundle-root "$bundle" --inputs "$inputs/hoodi-zero-release-inputs.json" --work-dir "$deploy_work" --private-eks-session-handoff "$deploy_session" --allow-create >/dev/null
rg -F "release zero apply --bundle-root $bundle --inputs $inputs/zero-resource/zero-resource-inputs.json --work-dir $deploy_work" "$trace" >/dev/null
rg -F "ops --handoff $deploy_work/ops-access-handoff.json --output-dir $deploy_work/ops-access-inputs" "$trace" >/dev/null
rg -F "ops-access plan --root $bundle/source --inputs $deploy_work/ops-access-inputs/ops-access-inputs.json --plan-file $deploy_work/ops-access.tfplan --allow-create" "$trace" >/dev/null
rg -F "ops-access apply --root $bundle/source --inputs $deploy_work/ops-access-inputs/ops-access-inputs.json --plan-file $deploy_work/ops-access.tfplan" "$trace" >/dev/null
rg -F "stage verify --handoff $inputs/validator-deployment/validator-deployment-handoff.json --private-eks-session-handoff $deploy_session" "$trace" >/dev/null
rg -F "stage apply --handoff $inputs/validator-deployment/validator-deployment-handoff.json --private-eks-session-handoff $deploy_session" "$trace" >/dev/null
jq -e '.ssm_ops_instance_id == "i-0123456789abcdef0"' "$deploy_session" >/dev/null
keystore_dir="$scratch/keystore"; mkdir -m 700 "$keystore_dir"; jq -n '{version:4,pubkey:("a" * 96),path:"m/12381/3600/0/0/0",uuid:"00000000-0000-4000-8000-000000000000",crypto:{kdf:{function:"scrypt",params:{dklen:32,n:262144,r:8,p:1,salt:("a" * 64)},message:""},checksum:{function:"sha256",params:{},message:("b" * 64)},cipher:{function:"aes-128-ctr",params:{iv:("c" * 32)},message:("d" * 64)}}}' > "$keystore_dir/keystore-test.json"
ceremony_dir="$scratch/ceremony"
TRACE="$trace" PATH="$fake_bin:$PATH" CUSTODY_ASSERT=1 AWS_PROFILE=chosen \
  AWS_ACCESS_KEY_ID=ambient AWS_SECRET_ACCESS_KEY=ambient AWS_SESSION_TOKEN=ambient AWS_SECURITY_TOKEN=ambient \
  AWS_ACCESS_KEY=ambient AWS_SECRET_KEY=ambient AWS_DEFAULT_PROFILE=ambient \
  AWS_WEB_IDENTITY_TOKEN_FILE=ambient AWS_ROLE_ARN=ambient AWS_ROLE_SESSION_NAME=ambient \
  AWS_CONTAINER_CREDENTIALS_RELATIVE_URI=ambient AWS_CONTAINER_CREDENTIALS_FULL_URI=ambient \
  AWS_CONTAINER_AUTHORIZATION_TOKEN=ambient AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE=ambient \
  PRIVATE_EKS_SESSION=ambient PRIVATE_VAULT_SESSION=ambient PRIVATE_VAULT_TARGET=service/wrong-vault KUBECONFIG=ambient BASH_ENV=/dev/null ENV=ambient \
  VAULT_ADDR=ambient VAULT_CACERT=ambient VAULT_TLS_SERVER_NAME=ambient VAULT_SKIP_VERIFY=ambient VAULT_NAMESPACE=ambient VAULT_TOKEN=ambient \
  GITHUB_TOKEN=preserve-github-token \
  "$script" custody apply --bundle-root "$bundle" --inputs "$inputs/hoodi-zero-release-inputs.json" --private-eks-session-handoff "$deploy_session" --keystore-dir "$keystore_dir" --ceremony-dir "$ceremony_dir" >/dev/null
test -d "$ceremony_dir"
test "$(rg -c '^custody-wrapper with-private-vault.sh profile=chosen region=ap-northeast-2 default-region=ap-northeast-2 cluster=hoodi-release-001 instance=i-0123456789abcdef0$' "$trace")" -eq 2 || { printf '%s\n' 'custody Vault wrappers did not receive the selected outer session environment' >&2; exit 1; }
test "$(rg -c '^custody-wrapper with-private-eks.sh profile=chosen region=ap-northeast-2 default-region=ap-northeast-2 cluster=hoodi-release-001 instance=i-0123456789abcdef0$' "$trace")" -eq 2 || { printf '%s\n' 'custody EKS wrappers did not receive the selected outer session environment' >&2; exit 1; }
rg -F "activation -- env PRIVATE_VAULT_SESSION=1 $bundle/source/scripts/ops/recover-and-bootstrap-hoodi-validator-runtime-vault.sh --validator-set hoodi-release-001" "$trace" >/dev/null
rg -F "$bundle/source/scripts/ops/recover-and-onboard-hoodi-validator-keystore.sh --validator-set hoodi-release-001 --expected-public-key 0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa --keystore-dir $keystore_dir --signer-ca-output $ceremony_dir/signer-ca.crt --known-clients-output $ceremony_dir/known-clients.txt" "$trace" >/dev/null
rg -F "kubectl -n validator-operations create configmap validator-hoodi-release-001-known-clients --from-file=known-clients=$ceremony_dir/known-clients.txt" "$trace" >/dev/null
# Verify the real release CLI forwards the optional completion binding and
# rejects malformed/orphan arguments before any command reaches a cloud shim.
receipt_ceremony="$scratch/receipt-ceremony"
TRACE="$trace" PATH="$fake_bin:$PATH" AWS_PROFILE=chosen "$script" custody apply --bundle-root "$bundle" --inputs "$inputs/hoodi-zero-release-inputs.json" --private-eks-session-handoff "$deploy_session" --keystore-dir "$keystore_dir" --ceremony-dir "$receipt_ceremony" --custody-result-output "$scratch/custody-result.json" --custody-operation-id 0123456789abcdef0123456789abcdef >/dev/null
rg -F -- "--known-clients-output $receipt_ceremony/known-clients.txt --result-output $scratch/custody-result.json --operation-id 0123456789abcdef0123456789abcdef" "$trace" >/dev/null
trace_before_invalid="$(wc -c < "$trace")"
mkdir -m 755 "$scratch/public-receipt-parent"
touch "$scratch/existing-receipt.json"
for receipt_args in output-only id-only malformed-id relative-output public-parent existing-output; do
  case "$receipt_args" in
    output-only) set -- --custody-result-output "$scratch/orphan.json" ;;
    id-only) set -- --custody-operation-id 0123456789abcdef0123456789abcdef ;;
    malformed-id) set -- --custody-result-output "$scratch/orphan.json" --custody-operation-id invalid ;;
    relative-output) set -- --custody-result-output relative.json --custody-operation-id 0123456789abcdef0123456789abcdef ;;
    public-parent) set -- --custody-result-output "$scratch/public-receipt-parent/result.json" --custody-operation-id 0123456789abcdef0123456789abcdef ;;
    existing-output) set -- --custody-result-output "$scratch/existing-receipt.json" --custody-operation-id 0123456789abcdef0123456789abcdef ;;
  esac
  if TRACE="$trace" PATH="$fake_bin:$PATH" "$script" custody apply --bundle-root "$bundle" --inputs "$inputs/hoodi-zero-release-inputs.json" --private-eks-session-handoff "$deploy_session" --keystore-dir "$keystore_dir" --ceremony-dir "$scratch/invalid-receipt-ceremony" "$@" >/dev/null 2>&1; then
    printf '%s\n' 'custody accepted an invalid completion receipt binding' >&2; exit 1
  fi
  [ "$(wc -c < "$trace")" = "$trace_before_invalid" ] || exit 1
done
before_custody_wrappers="$(rg -c '^custody-wrapper ' "$trace")"
if TRACE="$trace" PATH="$fake_bin:$PATH" CUSTODY_RUNTIME_FAIL=1 "$script" custody apply --bundle-root "$bundle" --inputs "$inputs/hoodi-zero-release-inputs.json" --private-eks-session-handoff "$deploy_session" --keystore-dir "$keystore_dir" --ceremony-dir "$scratch/runtime-failed-ceremony" >/dev/null 2>&1; then
  printf '%s\n' 'custody accepted an unverified runtime' >&2; exit 1
fi
test ! -e "$scratch/runtime-failed-ceremony" || exit 1
[ "$(rg -c '^custody-wrapper ' "$trace")" = "$before_custody_wrappers" ] || exit 1
jq '.pubkey = ("b" * 96)' "$keystore_dir/keystore-test.json" > "$scratch/wrong-keystore.json"
mv "$scratch/wrong-keystore.json" "$keystore_dir/keystore-test.json"
if TRACE="$trace" PATH="$fake_bin:$PATH" CUSTODY_ASSERT=1 AWS_PROFILE=chosen "$script" custody apply --bundle-root "$bundle" --inputs "$inputs/hoodi-zero-release-inputs.json" --private-eks-session-handoff "$deploy_session" --keystore-dir "$keystore_dir" --ceremony-dir "$scratch/wrong-key-ceremony" >/dev/null 2>&1; then
  printf '%s\n' 'custody unexpectedly accepted a mismatched keystore identity guard' >&2; exit 1
fi
test ! -e "$scratch/wrong-key-ceremony" || { printf '%s\n' 'invalid custody key created ceremony state before private Vault access' >&2; exit 1; }
[ "$(rg -c '^custody-wrapper ' "$trace")" = "$before_custody_wrappers" ] || { printf '%s\n' 'invalid custody key reached a private session wrapper' >&2; exit 1; }
if TRACE="$trace" PATH="$fake_bin:$PATH" CUSTODY_ASSERT=1 AWS_PROFILE=chosen "$script" custody apply --bundle-root "$bundle" --inputs "$inputs/hoodi-zero-release-inputs.json" --private-eks-session-handoff "$scratch/missing-private-eks-session.json" --keystore-dir "$keystore_dir" --ceremony-dir "$scratch/missing-ceremony" >/dev/null 2>&1; then
  printf '%s\n' 'custody unexpectedly accepted a missing private EKS session handoff' >&2; exit 1
fi
original_custody_session="$scratch/original-custody-session.json"
cp "$deploy_session" "$original_custody_session"
jq '.cluster_name = "other-node"' "$original_custody_session" > "$deploy_session"
if TRACE="$trace" PATH="$fake_bin:$PATH" CUSTODY_ASSERT=1 AWS_PROFILE=chosen "$script" custody apply --bundle-root "$bundle" --inputs "$inputs/hoodi-zero-release-inputs.json" --private-eks-session-handoff "$deploy_session" --keystore-dir "$keystore_dir" --ceremony-dir "$scratch/wrong-cluster-ceremony" >/dev/null 2>&1; then
  printf '%s\n' 'custody unexpectedly accepted a verifier-rejected cluster target' >&2; exit 1
fi
test ! -e "$scratch/wrong-cluster-ceremony" || { printf '%s\n' 'mismatched custody cluster created ceremony state before verification' >&2; exit 1; }
cp "$original_custody_session" "$deploy_session"
jq '.ssm_ops_instance_id = "i-0123456789abcdef0"' "$original_custody_session" > "$deploy_session"
if TRACE="$trace" PATH="$fake_bin:$PATH" CUSTODY_ASSERT=1 AWS_PROFILE=chosen "$script" custody apply --bundle-root "$bundle" --inputs "$inputs/hoodi-zero-release-inputs.json" --private-eks-session-handoff "$deploy_session" --keystore-dir "$keystore_dir" --ceremony-dir "$scratch/wrong-instance-ceremony" >/dev/null 2>&1; then
  printf '%s\n' 'custody unexpectedly accepted a verifier-rejected SSM instance target' >&2; exit 1
fi
test ! -e "$scratch/wrong-instance-ceremony" || { printf '%s\n' 'mismatched custody instance created ceremony state before verification' >&2; exit 1; }
cp "$original_custody_session" "$deploy_session"
[ "$(rg -c '^custody-wrapper ' "$trace")" = "$before_custody_wrappers" ] || { printf '%s\n' 'invalid custody session reached a private session wrapper' >&2; exit 1; }
signer_evidence_dir="$scratch/signer-evidence"
TRACE="$trace" "$script" evidence signer --bundle-root "$bundle" --inputs "$inputs/hoodi-zero-release-inputs.json" --private-eks-session-handoff "$deploy_session" --output-dir "$signer_evidence_dir" >/dev/null
rg -F "activation -- env PRIVATE_EKS_SESSION=1 AWS_REGION=ap-northeast-2 EKS_CLUSTER_NAME=hoodi-release-001 SSM_OPS_INSTANCE_ID=i-0123456789abcdef0 $bundle/source/scripts/ops/start-hoodi-validator-signer.sh --validator-set hoodi-release-001" "$trace" >/dev/null
rg -F "$bundle/source/scripts/ops/collect-hoodi-signer-public-key-evidence.sh --validator-set hoodi-release-001 --validator-public-key 0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa --probe-image 123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/node-op-001-baseline-validator-signer-identity-probe@sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff --output-dir $signer_evidence_dir" "$trace" >/dev/null
evidence_inventory_line="$(rg -n '^inventory ' "$trace" | tail -n1 | cut -d: -f1)"
signer_start_line="$(rg -n 'start-hoodi-validator-signer.sh' "$trace" | tail -n1 | cut -d: -f1)"
[ "$evidence_inventory_line" -lt "$signer_start_line" ] || { printf '%s\n' 'signer artifact authority was not checked before the private-EKS signer operation' >&2; exit 1; }
before_failed_signer_start="$(rg -c 'start-hoodi-validator-signer.sh' "$trace")"
if TRACE="$trace" INVENTORY_MODE=fail "$script" evidence signer --bundle-root "$bundle" --inputs "$inputs/hoodi-zero-release-inputs.json" --private-eks-session-handoff "$deploy_session" --output-dir "$scratch/rejected-signer-evidence" >/dev/null 2>&1; then
  printf '%s\n' 'signer evidence unexpectedly accepted incomplete artifact authority' >&2; exit 1
fi
[ "$(rg -c 'start-hoodi-validator-signer.sh' "$trace")" = "$before_failed_signer_start" ] || { printf '%s\n' 'signer evidence opened a private-EKS signer operation after rejected artifact authority' >&2; exit 1; }
beacon_evidence_dir="$scratch/beacon-evidence"
TRACE="$trace" "$script" evidence beacon --bundle-root "$bundle" --inputs "$inputs/hoodi-zero-release-inputs.json" --private-eks-session-handoff "$deploy_session" --output-dir "$beacon_evidence_dir" >/dev/null
rg -F "$bundle/source/scripts/ops/observe-private-hoodi-validator.sh --validator-set hoodi-release-001 --validator-public-key 0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa --correlation-id" "$trace" >/dev/null
rg -F -- "--output-dir $beacon_evidence_dir" "$trace" >/dev/null
for evidence in deposit-attestation public-deposit private-evidence signer-evidence; do printf '{}' > "$scratch/$evidence.json"; done
TRACE="$trace" "$script" activate apply --bundle-root "$bundle" --inputs "$inputs/hoodi-zero-release-inputs.json" --private-eks-session-handoff "$deploy_session" --deposit-attestation "$scratch/deposit-attestation.json" --public-deposit-verification "$scratch/public-deposit.json" --private-evidence "$scratch/private-evidence.json" --signer-evidence "$scratch/signer-evidence.json" --confirm-public-key 0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa --confirm-withdrawal-address 0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa >/dev/null
rg -F "$bundle/source/scripts/ops/activate-hoodi-validator-client.sh --validator-set hoodi-release-001" "$trace" >/dev/null
activation_receipts="$scratch/activation-receipts"; mkdir -m 700 "$activation_receipts"
receipt="$activation_receipts/activation.json"
TRACE="$trace" "$script" activate apply --bundle-root "$bundle" --inputs "$inputs/hoodi-zero-release-inputs.json" --private-eks-session-handoff "$deploy_session" --deposit-attestation "$scratch/deposit-attestation.json" --public-deposit-verification "$scratch/public-deposit.json" --private-evidence "$scratch/private-evidence.json" --signer-evidence "$scratch/signer-evidence.json" --confirm-public-key 0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa --confirm-withdrawal-address 0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa --activation-receipt "$receipt" --deployment-name node-op-001 --release-revision aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa --operation-id bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb >/dev/null
rg -F "$bundle/source/scripts/ops/activate-hoodi-validator-client.sh --validator-set hoodi-release-001 --deposit-attestation $scratch/deposit-attestation.json --public-deposit-verification $scratch/public-deposit.json --private-evidence $scratch/private-evidence.json --signer-evidence $scratch/signer-evidence.json --confirm-public-key 0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa --confirm-withdrawal-address 0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa --activation-receipt $receipt --deployment-name node-op-001 --release-revision aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa --operation-id bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" "$trace" >/dev/null
before_receipt_activation="$(rg -c 'activate-hoodi-validator-client.sh' "$trace")"
if TRACE="$trace" "$script" activate apply --bundle-root "$bundle" --inputs "$inputs/hoodi-zero-release-inputs.json" --private-eks-session-handoff "$deploy_session" --deposit-attestation "$scratch/deposit-attestation.json" --public-deposit-verification "$scratch/public-deposit.json" --private-evidence "$scratch/private-evidence.json" --signer-evidence "$scratch/signer-evidence.json" --confirm-public-key 0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa --confirm-withdrawal-address 0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa --activation-receipt "$activation_receipts/partial.json" --deployment-name node-op-001 >/dev/null 2>&1; then
  printf '%s\n' 'activation unexpectedly accepted a partial receipt binding' >&2; exit 1
fi
if TRACE="$trace" "$script" activate apply --bundle-root "$bundle" --inputs "$inputs/hoodi-zero-release-inputs.json" --private-eks-session-handoff "$deploy_session" --deposit-attestation "$scratch/deposit-attestation.json" --public-deposit-verification "$scratch/public-deposit.json" --private-evidence "$scratch/private-evidence.json" --signer-evidence "$scratch/signer-evidence.json" --confirm-public-key 0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa --confirm-withdrawal-address 0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa --activation-receipt "$activation_receipts/wrong-revision.json" --deployment-name node-op-001 --release-revision cccccccccccccccccccccccccccccccccccccccc --operation-id bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb >/dev/null 2>&1; then
  printf '%s\n' 'activation unexpectedly accepted a mismatched receipt revision' >&2; exit 1
fi
if TRACE="$trace" "$script" activate apply --bundle-root "$bundle" --inputs "$inputs/hoodi-zero-release-inputs.json" --private-eks-session-handoff "$deploy_session" --deposit-attestation "$scratch/deposit-attestation.json" --public-deposit-verification "$scratch/public-deposit.json" --private-evidence "$scratch/private-evidence.json" --signer-evidence "$scratch/signer-evidence.json" --confirm-public-key 0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa --confirm-withdrawal-address 0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa --activation-receipt "$activation_receipts/wrong-deployment.json" --deployment-name other-op-001 --release-revision aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa --operation-id bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb >/dev/null 2>&1; then
  printf '%s\n' 'activation unexpectedly accepted a mismatched receipt deployment' >&2; exit 1
fi
[ "$(rg -c 'activate-hoodi-validator-client.sh' "$trace")" = "$before_receipt_activation" ] || { printf '%s\n' 'invalid activation receipt binding reached the private EKS activation helper' >&2; exit 1; }
bad_session="$scratch/bad-session.json"; jq '.cluster_name = "INVALID"' "$deploy_session" > "$bad_session"
if TRACE="$trace" "$script" activate apply --bundle-root "$bundle" --inputs "$inputs/hoodi-zero-release-inputs.json" --private-eks-session-handoff "$bad_session" --deposit-attestation "$scratch/deposit-attestation.json" --public-deposit-verification "$scratch/public-deposit.json" --private-evidence "$scratch/private-evidence.json" --signer-evidence "$scratch/signer-evidence.json" --confirm-public-key 0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa --confirm-withdrawal-address 0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa >/dev/null 2>&1; then
  printf '%s\n' 'activation unexpectedly accepted an invalid session handoff' >&2; exit 1
fi
before_apply_count="$(rg -c '^ops-access apply ' "$trace")"
TRACE="$trace" PATH="$fake_bin:$PATH" "$script" deploy apply --bundle-root "$bundle" --inputs "$inputs/hoodi-zero-release-inputs.json" --work-dir "$deploy_work" --private-eks-session-handoff "$deploy_session" --allow-create >/dev/null
[ "$(rg -c '^ops-access apply ' "$trace")" = "$before_apply_count" ] || { printf '%s\n' 'deploy resume unexpectedly re-applied ops access' >&2; exit 1; }
stage_apply_count="$(rg -c '^stage apply ' "$trace")"
[ "$stage_apply_count" = 1 ] || { printf '%s\n' 'deploy resume unexpectedly re-applied existing staged workloads' >&2; exit 1; }
session="$scratch/session.json"; jq -n '{schema_version:1,aws_region:"ap-northeast-2",cluster_name:"node-operator",ssm_ops_instance_id:"i-0123456789abcdef0"}' > "$session"
if TRACE="$trace" "$script" ops-access apply --bundle-root "$bundle" --inputs "$inputs/hoodi-zero-release-inputs.json" --ops-inputs "$scratch/ops/ops-access-inputs.json" --plan-file "$scratch/plans/ops.tfplan" >/dev/null 2>&1; then
  printf '%s\n' 'ops-access apply unexpectedly accepted without a session handoff' >&2; exit 1
fi
TRACE="$trace" "$script" stage plan --bundle-root "$bundle" --inputs "$inputs/hoodi-zero-release-inputs.json" --private-eks-session-handoff "$session" >/dev/null
rg -F "stage plan --handoff $inputs/validator-deployment/validator-deployment-handoff.json --private-eks-session-handoff $session" "$trace" >/dev/null
jq '.aws_account_id = "999999999999"' "$inputs/validator-deployment/validator-deployment-handoff.json" > "$scratch/mismatch.json"
mv "$scratch/mismatch.json" "$inputs/validator-deployment/validator-deployment-handoff.json"
if TRACE="$trace" "$script" stage plan --bundle-root "$bundle" --inputs "$inputs/hoodi-zero-release-inputs.json" --private-eks-session-handoff "$session" >/dev/null 2>&1; then
  printf '%s\n' 'mismatched validator account unexpectedly accepted' >&2; exit 1
fi
printf '%s\n' 'PASS: Hoodi release command binds each non-secret phase to one validated input contract.'
