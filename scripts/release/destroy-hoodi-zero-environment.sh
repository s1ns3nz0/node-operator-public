#!/usr/bin/env bash
set -euo pipefail
umask 077

# Destroy a complete zero-resource Hoodi test environment from its release
# checkpoint. This is intentionally separate from the normal release command:
# it requires --execute and destroys Terraform-managed foundation resources.
# An optional VPC cleanup pass handles resources whose Terraform state was
# already removed; AWS-managed retention/resource policies are never bypassed.
usage() {
  printf '%s\n' "usage: ${0##*/} --execute --work-dir /absolute/deployment-work --inputs /absolute/hoodi-zero-release-inputs.json [--vpc-id vpc-...]" >&2
  exit 64
}

execute=false; work_dir=''; inputs=''; vpc_id=''
while [ "$#" -gt 0 ]; do
  case "$1" in
    --execute) execute=true; shift ;;
    --work-dir) work_dir="${2:-}"; shift 2 ;;
    --inputs) inputs="${2:-}"; shift 2 ;;
    --vpc-id) vpc_id="${2:-}"; shift 2 ;;
    *) usage ;;
  esac
done
[ "$execute" = true ] || { printf '%s\n' 'refusing full environment destruction without --execute' >&2; exit 64; }
case "$work_dir:$inputs" in /*:/*) ;; *) usage ;; esac
[ -d "$work_dir" ] && [ -f "$inputs" ] || { printf '%s\n' 'checkpoint work directory or inputs file is missing' >&2; exit 65; }
command -v terraform >/dev/null 2>&1 || { printf '%s\n' 'missing command: terraform' >&2; exit 69; }
input_parent="$(cd "$(dirname "$inputs")" && pwd -P)"

destroy_module() {
  local module="$1" backend="$2" varfile="$3"
  [ -d "$module" ] || { printf 'INFO: module %s is absent; skipping.\n' "$module"; return 0; }
  [ -f "$backend" ] && [ -f "$varfile" ] || { printf 'INFO: checkpoint for %s is absent; skipping.\n' "$module"; return 0; }
  terraform -chdir="$module" init -input=false -backend-config="$backend" >/dev/null
  terraform -chdir="$module" destroy -input=false -auto-approve -lock-timeout=5m -var-file="$varfile"
}

# Dependency order: workload access, baseline, network, then state backend.
destroy_module "$work_dir/baseline" "$work_dir/baseline.backend.hcl" "$input_parent/zero-resource/baseline.tfvars.json"
destroy_module "$work_dir/foundation-network" "$work_dir/foundation.backend.hcl" "$input_parent/zero-resource/foundation-network.tfvars.json"
destroy_module "$work_dir/bootstrap-state" "$work_dir/bootstrap.backend.hcl" "$input_parent/zero-resource/bootstrap-state.tfvars.json"
printf '%s\n' 'PASS: Terraform-managed Hoodi zero-resource environment destruction completed.'

if [ -n "$vpc_id" ]; then
  printf 'INFO: attempting residual VPC cleanup for %s.\n' "$vpc_id"
  for endpoint in $(aws ec2 describe-vpc-endpoints --region "${AWS_REGION:-ap-northeast-2}" --filters Name=vpc-id,Values="$vpc_id" --query 'VpcEndpoints[].VpcEndpointId' --output text); do
    aws ec2 delete-vpc-endpoints --region "${AWS_REGION:-ap-northeast-2}" --vpc-endpoint-ids "$endpoint" >/dev/null 2>&1 || true
  done
  for subnet in $(aws ec2 describe-subnets --region "${AWS_REGION:-ap-northeast-2}" --filters Name=vpc-id,Values="$vpc_id" --query 'Subnets[].SubnetId' --output text); do
    aws ec2 delete-subnet --region "${AWS_REGION:-ap-northeast-2}" --subnet-id "$subnet" >/dev/null 2>&1 || true
  done
  for sg in $(aws ec2 describe-security-groups --region "${AWS_REGION:-ap-northeast-2}" --filters Name=vpc-id,Values="$vpc_id" --query 'SecurityGroups[?GroupName!=`default`].GroupId' --output text); do
    aws ec2 delete-security-group --region "${AWS_REGION:-ap-northeast-2}" --group-id "$sg" >/dev/null 2>&1 || true
  done
  aws ec2 delete-vpc --region "${AWS_REGION:-ap-northeast-2}" --vpc-id "$vpc_id" >/dev/null 2>&1 || printf 'WARN: VPC %s still has AWS-managed dependencies.\n' "$vpc_id"
fi
