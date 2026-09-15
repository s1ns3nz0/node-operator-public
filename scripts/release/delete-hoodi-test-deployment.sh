#!/usr/bin/env bash
set -euo pipefail
umask 077

# Deletes only the resources created by the Hoodi zero-resource deployment
# test: the two workload namespaces and the temporary SSM operations host.
# Terraform foundation (VPC/EKS/KMS/S3/ECR) is intentionally not destroyed by
# this script because those resources may be shared by later release tests.
usage() {
  printf '%s\n' "usage: ${0##*/} --execute [--region ap-northeast-2] [--cluster node-operator] [--ops-instance-id i-...] [--bundle-root /absolute/release-bundle]" >&2
  exit 64
}

execute=false
region="${AWS_REGION:-ap-northeast-2}"
cluster="${EKS_CLUSTER_NAME:-node-operator}"
instance="${SSM_OPS_INSTANCE_ID:-}"
bundle_root=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --execute) execute=true; shift ;;
    --region) region="${2:-}"; shift 2 ;;
    --cluster) cluster="${2:-}"; shift 2 ;;
    --ops-instance-id) instance="${2:-}"; shift 2 ;;
    --bundle-root) bundle_root="${2:-}"; shift 2 ;;
    *) usage ;;
  esac
done
[ "$execute" = true ] || { printf '%s\n' 'refusing deletion without --execute' >&2; exit 64; }
[[ "$region" =~ ^[a-z]{2}-[a-z0-9-]+-[0-9]+$ ]] || { printf '%s\n' 'unsupported AWS region' >&2; exit 64; }
[[ "$cluster" =~ ^[a-z][a-z0-9-]{1,38}[a-z0-9]$ ]] || { printf '%s\n' 'invalid EKS cluster name' >&2; exit 64; }
command -v aws >/dev/null 2>&1 || { printf '%s\n' 'missing command: aws' >&2; exit 69; }

if [ -z "$bundle_root" ]; then
  script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
  bundle_root="$(cd "$script_dir/../.." && pwd -P)"
fi
with_private_eks="$bundle_root/scripts/ops/with-private-eks.sh"

if [ -z "$instance" ]; then
  printf '%s\n' 'INFO: no SSM operations instance was supplied; skipping SSM cleanup.'
elif ! aws ec2 describe-instances --region "$region" --instance-ids "$instance" \
    --query 'Reservations[0].Instances[0].InstanceId' --output text 2>/dev/null | grep -qx "$instance"; then
  printf 'INFO: SSM operations instance %s is absent; nothing to terminate.\n' "$instance"
else
  if aws ssm describe-instance-information --region "$region" \
      --filters "Key=InstanceIds,Values=$instance" \
      --query 'InstanceInformationList[0].PingStatus' --output text 2>/dev/null | grep -qx Online; then
    [ -x "$with_private_eks" ] || { printf '%s\n' 'private EKS tunnel helper is missing or not executable' >&2; exit 66; }
    AWS_REGION="$region" EKS_CLUSTER_NAME="$cluster" SSM_OPS_INSTANCE_ID="$instance" \
      "$with_private_eks" -- kubectl delete namespace validator-operations node-operator --ignore-not-found --wait=true
  else
    printf 'INFO: SSM operations instance %s is not online; skipping namespace cleanup.\n' "$instance"
  fi
  aws ec2 terminate-instances --region "$region" --instance-ids "$instance" >/dev/null
  printf 'PASS: requested termination of SSM operations instance %s.\n' "$instance"
fi

printf '%s\n' 'PASS: Hoodi workload cleanup completed (or was already absent). Foundation infrastructure was retained.'
