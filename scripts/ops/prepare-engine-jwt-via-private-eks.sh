#!/usr/bin/env bash
# Creates engine-api-jwt through a temporary private SSM-to-EKS tunnel.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
region="${AWS_REGION:-ap-northeast-2}"
cluster="${EKS_CLUSTER_NAME:-node-operator}"
namespace="${HOODI_NAMESPACE:-node-operator}"
tf_profile="${TF_AWS_PROFILE:-node-operator-t2}"
session_profile="${SESSION_AWS_PROFILE:-default}"
tfvars_file="${TFVARS_FILE:-/private/tmp/node-operator-live-current.tfvars}"
termination_at="${TERMINATION_AT:-$(date -v+2H '+%Y-%m-%dT%H:%M:%S')}"
temp_kubeconfig=""; tunnel_log=""; tunnel_pid=""

fail() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
for command in aws terraform kubectl openssl nc; do command -v "$command" >/dev/null 2>&1 || fail "missing $command"; done
test -f "$tfvars_file" || fail "missing Terraform inputs: $tfvars_file"

targets=(
  -target=aws_instance.temporary_ssm_ops_host
  -target=aws_scheduler_schedule.temporary_ssm_ops_host_stop
  -target=aws_iam_role.temporary_ssm_ops_host
  -target=aws_iam_role_policy_attachment.temporary_ssm_ops_host
  -target=aws_iam_instance_profile.temporary_ssm_ops_host
  -target=aws_security_group.temporary_ssm_ops_host
  -target=aws_iam_role.temporary_ssm_ops_host_stop
  -target=aws_iam_role_policy.temporary_ssm_ops_host_stop
  -target=aws_vpc_security_group_egress_rule.temporary_ssm_ops_host_to_endpoints
  -target=aws_vpc_security_group_egress_rule.temporary_ssm_ops_host_to_cluster
  -target=aws_vpc_security_group_ingress_rule.cluster_api_from_temporary_ssm_ops_host
  -target=aws_vpc_security_group_ingress_rule.endpoints_https_from_temporary_ssm_ops_host
)
tf_args=(-input=false -no-color -var-file="$tfvars_file" -var='enable_gitops_client_ecr_publisher=true' -var='enable_temporary_ssm_ops_host=true' -var="temporary_ssm_ops_host_termination_at=$termination_at")

cleanup() {
  set +e
  [ -n "$tunnel_pid" ] && kill -TERM "$tunnel_pid" 2>/dev/null
  [ -n "$tunnel_log" ] && rm -f "$tunnel_log"
  [ -n "$temp_kubeconfig" ] && rm -f "$temp_kubeconfig"
  AWS_PROFILE="$tf_profile" terraform -chdir="$root/infra/terraform" apply -destroy -auto-approve "${tf_args[@]}" "${targets[@]}" >/dev/null 2>&1
}
trap cleanup EXIT

printf '%s\n' 'Creates only temporary SSM access, generates Engine JWT, and removes temporary resources afterward.'
printf '%s\n' 'It does not print Secret data, start Hoodi capacity, or initialize/unseal Vault.'
read -r -p 'Type CREATE_ENGINE_JWT to continue: ' confirmation
[ "$confirmation" = CREATE_ENGINE_JWT ] || fail 'confirmation not received'

AWS_PROFILE="$tf_profile" terraform -chdir="$root/infra/terraform" init -input=false -no-color >/dev/null
AWS_PROFILE="$tf_profile" terraform -chdir="$root/infra/terraform" plan "${tf_args[@]}" "${targets[@]}"
read -r -p 'Confirm only temporary SSM resources are planned; type APPLY_SSM_ONLY: ' confirmation
[ "$confirmation" = APPLY_SSM_ONLY ] || fail 'apply confirmation not received'
AWS_PROFILE="$tf_profile" terraform -chdir="$root/infra/terraform" apply -auto-approve "${tf_args[@]}" "${targets[@]}"

instance_id="$(AWS_PROFILE="$tf_profile" terraform -chdir="$root/infra/terraform" output -raw temporary_ssm_ops_host_instance_id)"
export AWS_PROFILE="$session_profile"
eks_host="$(aws eks describe-cluster --name "$cluster" --region "$region" --query 'cluster.endpoint' --output text | sed 's#^https://##')"
tunnel_log="$(mktemp /private/tmp/node-operator-ssm-tunnel.XXXXXX)"
env -u ANTHROPIC_API_KEY -u OPENAI_API_KEY -u GITHUB_TOKEN AWS_PROFILE="$session_profile" aws ssm start-session --target "$instance_id" --document-name AWS-StartPortForwardingSessionToRemoteHost --parameters "{\"host\":[\"${eks_host}\"],\"portNumber\":[\"443\"],\"localPortNumber\":[\"8443\"]}" --region "$region" >"$tunnel_log" 2>&1 &
tunnel_pid="$!"
for _ in $(seq 1 30); do nc -z 127.0.0.1 8443 2>/dev/null && break; sleep 2; done
nc -z 127.0.0.1 8443 2>/dev/null || fail 'private EKS tunnel did not open'

temp_kubeconfig="$(mktemp -t node-operator-kubeconfig.XXXXXX)"
aws eks update-kubeconfig --name "$cluster" --region "$region" --kubeconfig "$temp_kubeconfig" >/dev/null
cluster_context="$(kubectl --kubeconfig "$temp_kubeconfig" config view --minify -o jsonpath='{.clusters[0].name}')"
kubectl --kubeconfig "$temp_kubeconfig" config set-cluster "$cluster_context" --server=https://127.0.0.1:8443 --tls-server-name="$eks_host" >/dev/null
kubectl --kubeconfig "$temp_kubeconfig" get namespace "$namespace" >/dev/null

set +o history
engine_jwt="$(openssl rand -hex 32)"
printf '%s' "$engine_jwt" | kubectl --kubeconfig "$temp_kubeconfig" -n "$namespace" create secret generic engine-api-jwt --from-file=jwt=/dev/stdin --dry-run=client -o yaml | kubectl --kubeconfig "$temp_kubeconfig" apply -f - >/dev/null
unset engine_jwt
secret_name="$(kubectl --kubeconfig "$temp_kubeconfig" -n "$namespace" get secret engine-api-jwt -o jsonpath='{.metadata.name}')"
[ "$secret_name" = engine-api-jwt ] || fail 'Secret metadata verification failed'
printf '%s\n' 'PASS: engine-api-jwt created and verified by metadata only. Cleaning up temporary access.'
