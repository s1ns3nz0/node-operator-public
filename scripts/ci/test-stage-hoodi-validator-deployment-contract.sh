#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
script="$root/scripts/release/stage-hoodi-validator-deployment.sh"
policy="$root/deploy/validator/vault-runtime-egress-policy.yaml"
service_accounts="$root/deploy/validator/service-accounts.yaml"
scratch="$(mktemp -d /private/tmp/node-operator-stage-validator.XXXXXX)"
tools="$scratch/tools"; mkdir "$tools"
handoff_dir="$scratch/handoff"; mkdir -m 700 "$handoff_dir"
runtime="$handoff_dir/runtime.yaml"; client="$handoff_dir/client-and-fence.yaml"; handoff="$handoff_dir/validator-deployment-handoff.json"
session="$handoff_dir/private-eks-session.json"

printf '%s\n' 'apiVersion: v1
kind: ConfigMap
metadata: {name: runtime, namespace: validator-operations}' > "$runtime"
printf '%s\n' 'apiVersion: v1
kind: ConfigMap
metadata: {name: client, namespace: validator-operations}' > "$client"
jq -n --arg runtime "$runtime" --arg client "$client" '{schema_version:1,network:"hoodi",validator_set:"hoodi-stage-001",aws_account_id:"123456789012",aws_region:"ap-northeast-2",runtime_manifest:$runtime,client_manifest:$client,staged_client_replicas:0,staged_fence_replicas:0,next_steps:["bounded"]}' > "$handoff"
chmod 600 "$handoff"
jq -n '{schema_version:1,aws_region:"ap-northeast-2",cluster_name:"node-operator",ssm_ops_instance_id:"i-0123456789abcdef0"}' > "$session"
chmod 600 "$session"

cat > "$tools/kubectl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "$KUBECTL_TRACE"
case " $* " in
  *' apply '*' --dry-run=server '*) exit 0 ;;
  *' get '*) exit 1 ;;
  *) printf 'unexpected kubectl call: %s\n' "$*" >&2; exit 1 ;;
esac
EOF
chmod 700 "$tools/kubectl"

test -f "$policy"
test -f "$service_accounts"
grep -Fq -- '--ebs-kms-key-arn' "$script" || { printf '%s\n' 'stage command does not accept an explicit validator EBS CMK ARN' >&2; exit 1; }
grep -Fq 'ensure-validator-encrypted-storageclass.sh' "$script" || { printf '%s\n' 'stage command does not invoke the validator StorageClass helper' >&2; exit 1; }
grep -Fq 'vault-runtime-egress-policy.yaml' "$script" || { printf '%s\n' 'stage command does not install the dedicated Vault egress policy' >&2; exit 1; }
grep -Fq 'service-accounts.yaml' "$script" || { printf '%s\n' 'stage command does not install dedicated ServiceAccounts' >&2; exit 1; }
# shellcheck disable=SC2016 # literal source contract, not interpolation
grep -Fq 'field-manager=node-operator-release-stage -f "$vault_egress_policy"' "$script" || { printf '%s\n' 'stage command does not apply Vault egress before workloads' >&2; exit 1; }

KUBECTL_TRACE="$scratch/kubectl.trace" PATH="$tools:$PATH" PRIVATE_EKS_SESSION=1 "$script" plan --handoff "$handoff" --private-eks-session-handoff "$session" >/dev/null
rg -F -- "--server-side --field-manager=node-operator-release-stage --dry-run=server -f $service_accounts -f $policy -f $runtime -f $client" "$scratch/kubectl.trace" >/dev/null
sed -i.bak 's/\*\x27 get \x27\*) exit 1 ;;/\*\x27 get \x27\*) exit 0 ;;/ ' "$tools/kubectl"
if KUBECTL_TRACE="$scratch/existing.trace" PATH="$tools:$PATH" PRIVATE_EKS_SESSION=1 "$script" plan --handoff "$handoff" --private-eks-session-handoff "$session" >"$scratch/existing.out" 2>&1; then
  printf '%s\n' 'existing validator target unexpectedly accepted' >&2; exit 1
fi
rg -F 'fresh staging will not adopt it' "$scratch/existing.out" >/dev/null
if KUBECTL_TRACE="$scratch/secret.trace" PATH="$tools:$PATH" PRIVATE_EKS_SESSION=1 "$script" plan --handoff /dev/null >/dev/null 2>&1; then
  printf '%s\n' 'unsafe handoff unexpectedly accepted' >&2
  exit 1
fi
printf '%s\n' 'PASS: staging command validates a bounded handoff and performs server-side dry-run before apply.'
