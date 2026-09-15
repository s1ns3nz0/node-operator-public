#!/usr/bin/env bash
# Goal: bootstrap AWS-side GitHub OIDC and a least-privilege ECR publisher.
# This script never calls the GitHub API and never handles secrets.
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: bootstrap-github-oidc-ecr-publisher.sh [--env-file /absolute/path] [--dry-run]

Required environment values: AWS_REGION, GITHUB_OWNER, GITHUB_REPOSITORY,
GITHUB_OWNER_ID, GITHUB_REPOSITORY_ID.

Optional: AWS_PROFILE (default: default), ECR_REPOSITORY,
IAM_ROLE_NAME, GITHUB_ENVIRONMENT, GITHUB_OIDC_THUMBPRINT.
EOF
}

env_file=""
dry_run=false
while (($#)); do
  case "$1" in
    --env-file) env_file="${2:-}"; shift 2 ;;
    --dry-run) dry_run=true; shift ;;
    -h|--help) usage; exit 0 ;;
    *) printf 'unknown argument: %s\n' "$1" >&2; usage; exit 64 ;;
  esac
done

if [[ -z "$env_file" && -f release/env ]]; then env_file="$PWD/release/env"; fi
if [[ -n "$env_file" ]]; then
  [[ "$env_file" = /* ]] || { printf '%s\n' '--env-file must be absolute' >&2; exit 64; }
  [[ -r "$env_file" ]] || { printf 'cannot read env file: %s\n' "$env_file" >&2; exit 66; }
  while IFS='=' read -r key value; do
    [[ -z "$key" || "$key" = \#* ]] && continue
    case "$key" in
      AWS_PROFILE|AWS_REGION|GITHUB_OWNER|GITHUB_REPOSITORY|GITHUB_OWNER_ID|GITHUB_REPOSITORY_ID|ECR_REPOSITORY|IAM_ROLE_NAME|GITHUB_ENVIRONMENT|GITHUB_OIDC_THUMBPRINT)
        [[ -n "${!key+x}" ]] || export "$key=$value" ;;
    esac
  done < "$env_file"
fi

command -v aws >/dev/null || { printf '%s\n' 'missing command: aws' >&2; exit 127; }
command -v jq >/dev/null || { printf '%s\n' 'missing command: jq' >&2; exit 127; }
AWS_PROFILE="${AWS_PROFILE:-default}"
AWS_REGION="${AWS_REGION:-ap-northeast-2}"
GITHUB_OWNER="${GITHUB_OWNER:-}"
GITHUB_REPOSITORY="${GITHUB_REPOSITORY:-}"
GITHUB_OWNER_ID="${GITHUB_OWNER_ID:-}"
GITHUB_REPOSITORY_ID="${GITHUB_REPOSITORY_ID:-}"
ECR_REPOSITORY="${ECR_REPOSITORY:-node-operator-baseline-validator-fence}"
IAM_ROLE_NAME="${IAM_ROLE_NAME:-node-operator-baseline-github-validator-client-mirror}"
GITHUB_ENVIRONMENT="${GITHUB_ENVIRONMENT:-validator-client-ecr-mirror}"
GITHUB_OIDC_THUMBPRINT="${GITHUB_OIDC_THUMBPRINT:-6938fd4d98bab03faadb97b34396831e3780aea1}"
for name in GITHUB_OWNER GITHUB_REPOSITORY GITHUB_OWNER_ID GITHUB_REPOSITORY_ID; do
  [[ -n "${!name}" ]] || { printf 'missing required input: %s\n' "$name" >&2; exit 64; }
done

account_id="$(aws --profile "$AWS_PROFILE" --region "$AWS_REGION" sts get-caller-identity --query Account --output text)"
repo_arn="arn:aws:ecr:${AWS_REGION}:${account_id}:repository/${ECR_REPOSITORY}"
provider_arn="arn:aws:iam::${account_id}:oidc-provider/token.actions.githubusercontent.com"
role_arn="arn:aws:iam::${account_id}:role/${IAM_ROLE_NAME}"
subject="repo:${GITHUB_OWNER}@${GITHUB_OWNER_ID}/${GITHUB_REPOSITORY}@${GITHUB_REPOSITORY_ID}:environment:${GITHUB_ENVIRONMENT}"
tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT
jq -n --arg subject "$subject" --arg provider "$provider_arn" '{Version:"2012-10-17",Statement:[{Effect:"Allow",Principal:{Federated:$provider},Action:"sts:AssumeRoleWithWebIdentity",Condition:{StringEquals:{"token.actions.githubusercontent.com:aud":"sts.amazonaws.com","token.actions.githubusercontent.com:sub":$subject}}}]}' > "$tmp_dir/trust.json"
jq -n --arg repo "$repo_arn" '{Version:"2012-10-17",Statement:[{Sid:"EcrAuthToken",Effect:"Allow",Action:["ecr:GetAuthorizationToken"],Resource:"*"},{Sid:"PublishFenceImage",Effect:"Allow",Action:["ecr:BatchCheckLayerAvailability","ecr:BatchGetImage","ecr:CompleteLayerUpload","ecr:DescribeImages","ecr:DescribeRepositories","ecr:GetDownloadUrlForLayer","ecr:InitiateLayerUpload","ecr:PutImage","ecr:UploadLayerPart"],Resource:$repo}]}' > "$tmp_dir/policy.json"

printf 'AWS account: %s\nAWS region: %s\nECR repository: %s\nOIDC subject: %s\n' "$account_id" "$AWS_REGION" "$ECR_REPOSITORY" "$subject"
if "$dry_run"; then printf '%s\n' 'DRY RUN: no AWS resources changed.'; exit 0; fi
if ! aws --profile "$AWS_PROFILE" iam get-open-id-connect-provider --open-id-connect-provider-arn "$provider_arn" >/dev/null 2>&1; then
  aws --profile "$AWS_PROFILE" iam create-open-id-connect-provider --url https://token.actions.githubusercontent.com --client-id-list sts.amazonaws.com --thumbprint-list "$GITHUB_OIDC_THUMBPRINT" >/dev/null
  printf 'Created AWS OIDC provider: %s\n' "$provider_arn"
else printf 'OIDC provider already exists: %s\n' "$provider_arn"; fi
if ! aws --profile "$AWS_PROFILE" --region "$AWS_REGION" ecr describe-repositories --repository-names "$ECR_REPOSITORY" >/dev/null 2>&1; then
  aws --profile "$AWS_PROFILE" --region "$AWS_REGION" ecr create-repository --repository-name "$ECR_REPOSITORY" --image-tag-mutability IMMUTABLE --image-scanning-configuration scanOnPush=true >/dev/null
  printf 'Created ECR repository: %s\n' "$repo_arn"
else printf 'ECR repository already exists: %s\n' "$repo_arn"; fi
if ! aws --profile "$AWS_PROFILE" iam get-role --role-name "$IAM_ROLE_NAME" >/dev/null 2>&1; then
  aws --profile "$AWS_PROFILE" iam create-role --role-name "$IAM_ROLE_NAME" --assume-role-policy-document "file://$tmp_dir/trust.json" >/dev/null
else aws --profile "$AWS_PROFILE" iam update-assume-role-policy --role-name "$IAM_ROLE_NAME" --policy-document "file://$tmp_dir/trust.json"; fi
aws --profile "$AWS_PROFILE" iam put-role-policy --role-name "$IAM_ROLE_NAME" --policy-name "$IAM_ROLE_NAME" --policy-document "file://$tmp_dir/policy.json"
printf '\nAWS bootstrap complete. Enter these non-secret values once in GitHub Environment %s:\n' "$GITHUB_ENVIRONMENT"
printf 'AWS_ACCOUNT_ID=%s\nVALIDATOR_CLIENT_ECR_MIRROR_ROLE_ARN=%s\n' "$account_id" "$role_arn"
