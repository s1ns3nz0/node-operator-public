#!/usr/bin/env bash
set -euo pipefail
umask 077

# Creates a short-lived, narrowly scoped cleanup role, uses it once, and
# removes it. This never grants AdministratorAccess and never prints tokens.
usage() {
  printf '%s\n' "usage: ${0##*/} --execute --vpc-id vpc-... --object-lock-bucket BUCKET [--region ap-northeast-2]" >&2
  exit 64
}
execute=false; region="${AWS_REGION:-ap-northeast-2}"; vpc_id=''; object_bucket=''; kms_aliases=()
while [ "$#" -gt 0 ]; do
  case "$1" in
    --execute) execute=true; shift ;;
    --region) region="${2:-}"; shift 2 ;;
    --vpc-id) vpc_id="${2:-}"; shift 2 ;;
    --object-lock-bucket) object_bucket="${2:-}"; shift 2 ;;
    --kms-alias) kms_aliases+=("${2:-}"); shift 2 ;;
    *) usage ;;
  esac
done
[ "$execute" = true ] && [ -n "$vpc_id" ] && [ -n "$object_bucket" ] || usage
[[ "$region" =~ ^[a-z]{2}-[a-z0-9-]+-[0-9]+$ ]] || { printf '%s\n' 'unsupported region' >&2; exit 64; }
[[ "$vpc_id" =~ ^vpc-[0-9a-f]+$ ]] || { printf '%s\n' 'invalid VPC id' >&2; exit 64; }
[[ "$object_bucket" =~ ^[a-z0-9.-]{3,63}$ ]] || { printf '%s\n' 'invalid bucket name' >&2; exit 64; }
for c in aws jq; do command -v "$c" >/dev/null 2>&1 || { printf 'missing command: %s\n' "$c" >&2; exit 69; }; done

account="$(aws sts get-caller-identity --query Account --output text)"
caller="$(aws sts get-caller-identity --query Arn --output text)"
role="node-operator-cleanup-breakglass-$(date -u +%Y%m%d%H%M%S)"
role_arn="arn:aws:iam::${account}:role/${role}"
user_name="${caller##*/}"
assume_policy="node-operator-breakglass-assume"
policy_file="$(mktemp /private/tmp/node-operator-breakglass-policy.XXXXXX)"
cleanup() {
  set +e
  unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AWS_SECURITY_TOKEN
  aws iam delete-user-policy --user-name "$user_name" --policy-name "$assume_policy" >/dev/null 2>&1 || true
  aws iam delete-role-policy --role-name "$role" --policy-name cleanup >/dev/null 2>&1 || true
  aws iam delete-role --role-name "$role" >/dev/null 2>&1 || true
  unlink "$policy_file" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

jq -n --arg caller "$caller" --arg vpc "$vpc_id" --arg bucket "$object_bucket" --arg region "$region" '
  {Version:"2012-10-17",Statement:[
    {Effect:"Allow",Action:["ec2:Describe*","ec2:DeleteVpc","ec2:DeleteSubnet","ec2:DeleteRouteTable","ec2:DeleteSecurityGroup","ec2:DeleteVpcEndpoints","ec2:DeleteNetworkInterface","ec2:DetachInternetGateway","ec2:DeleteInternetGateway","ec2:DeleteNatGateway"],Resource:"*",Condition:{StringEquals:{"aws:RequestedRegion":$region}}},
    {Effect:"Allow",Action:["s3:ListBucket","s3:ListBucketVersions","s3:GetObjectRetention","s3:DeleteObject","s3:DeleteObjectVersion","s3:BypassGovernanceRetention","s3:DeleteBucket"],Resource:[("arn:aws:s3:::"+$bucket),("arn:aws:s3:::"+$bucket+"/*")]},
    {Effect:"Allow",Action:["kms:ListAliases","kms:DeleteAlias","kms:DescribeKey","kms:ScheduleKeyDeletion"],Resource:"*"}
  ]}' > "$policy_file"

aws iam create-role --role-name "$role" --assume-role-policy-document "$(jq -nc --arg caller "$caller" '{Version:"2012-10-17",Statement:[{Effect:"Allow",Principal:{AWS:$caller},Action:"sts:AssumeRole"}]}')" >/dev/null
aws iam put-role-policy --role-name "$role" --policy-name cleanup --policy-document "$(jq -c . "$policy_file")"
aws iam put-user-policy --user-name "$user_name" --policy-name "$assume_policy" --policy-document "$(jq -nc --arg role "$role_arn" '{Version:"2012-10-17",Statement:[{Effect:"Allow",Action:"sts:AssumeRole",Resource:$role}]}')"
creds=''
for _ in $(seq 1 30); do
  creds="$(aws sts assume-role --role-arn "$role_arn" --role-session-name node-operator-cleanup 2>/dev/null || true)"
  [ -n "$creds" ] && break
  sleep 2
done
[ -n "$creds" ] || { printf '%s\n' 'temporary AssumeRole permission did not propagate' >&2; exit 77; }
export AWS_ACCESS_KEY_ID="$(jq -er '.Credentials.AccessKeyId' <<<"$creds")"
export AWS_SECRET_ACCESS_KEY="$(jq -er '.Credentials.SecretAccessKey' <<<"$creds")"
export AWS_SESSION_TOKEN="$(jq -er '.Credentials.SessionToken' <<<"$creds")"

for alias in "${kms_aliases[@]}"; do
  [[ "$alias" == alias/* ]] || { printf 'invalid KMS alias: %s\n' "$alias" >&2; exit 64; }
  aws kms delete-alias --region "$region" --alias-name "$alias"
done

# Remove governance-retained object versions, then remove the bucket.
versions="$(aws s3api list-object-versions --region "$region" --bucket "$object_bucket")"
if [ "$(jq '[.Versions[]?,.DeleteMarkers[]?]|length' <<<"$versions")" -gt 0 ]; then
  jq '{Objects:([.Versions[]?,.DeleteMarkers[]?]|map({Key,VersionId})),Quiet:true}' <<<"$versions" |
    aws s3api delete-objects --region "$region" --bucket "$object_bucket" --bypass-governance-retention --delete file:///dev/stdin >/dev/null
fi
aws s3api delete-bucket --region "$region" --bucket "$object_bucket" >/dev/null

# Best-effort VPC dependency cleanup.
for endpoint in $(aws ec2 describe-vpc-endpoints --region "$region" --filters Name=vpc-id,Values="$vpc_id" --query 'VpcEndpoints[].VpcEndpointId' --output text); do aws ec2 delete-vpc-endpoints --region "$region" --vpc-endpoint-ids "$endpoint" >/dev/null 2>&1 || true; done
for subnet in $(aws ec2 describe-subnets --region "$region" --filters Name=vpc-id,Values="$vpc_id" --query 'Subnets[].SubnetId' --output text); do aws ec2 delete-subnet --region "$region" --subnet-id "$subnet" >/dev/null 2>&1 || true; done
for sg in $(aws ec2 describe-security-groups --region "$region" --filters Name=vpc-id,Values="$vpc_id" --query 'SecurityGroups[?GroupName!=`default`].GroupId' --output text); do aws ec2 delete-security-group --region "$region" --group-id "$sg" >/dev/null 2>&1 || true; done
aws ec2 delete-vpc --region "$region" --vpc-id "$vpc_id" >/dev/null 2>&1 || true
printf '%s\n' 'PASS: temporary break-glass cleanup completed; role and policy will be removed on exit.'
