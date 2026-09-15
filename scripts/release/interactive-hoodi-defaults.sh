#!/usr/bin/env bash
# Purpose: derive non-secret Hoodi deployment defaults from local CLI context.
# This helper never loads configuration files or credential-bearing environment values.
set -euo pipefail
umask 077

for command in aws gh git jq date; do
  command -v "$command" >/dev/null 2>&1 || { printf 'missing command: %s\n' "$command" >&2; exit 69; }
done

aws_profile="${AWS_PROFILE:-default}"
[[ "$aws_profile" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$ ]] || { printf '%s\n' 'AWS profile is invalid' >&2; exit 64; }
aws_region="$(env -i PATH="$PATH" HOME="$HOME" aws configure get region --profile "$aws_profile" 2>/dev/null || true)"
aws_region="${aws_region:-ap-northeast-2}"
[[ "$aws_region" =~ ^[a-z]{2}-[a-z0-9-]+-[0-9]+$ ]] || { printf '%s\n' 'AWS CLI region is invalid' >&2; exit 65; }

identity="$(env -i PATH="$PATH" HOME="$HOME" AWS_PROFILE="$aws_profile" AWS_REGION="$aws_region" AWS_DEFAULT_REGION="$aws_region" aws sts get-caller-identity --output json)" || {
  printf '%s\n' 'could not read the selected AWS CLI identity' >&2; exit 69;
}
aws_account_id="$(jq -er '.Account | select(test("^[0-9]{12}$"))' <<<"$identity")" || {
  printf '%s\n' 'AWS CLI identity lacks a valid account ID' >&2; exit 65;
}
caller_arn="$(jq -er '.Arn | select(type == "string" and startswith("arn:aws:"))' <<<"$identity")" || {
  printf '%s\n' 'AWS CLI identity lacks a usable ARN' >&2; exit 65;
}

repository="$(git config --get remote.origin.url 2>/dev/null || true)"
case "$repository" in
  https://github.com/*.git) repository="${repository#https://github.com/}"; repository="${repository%.git}" ;;
  https://github.com/*) repository="${repository#https://github.com/}" ;;
  git@github.com:*.git) repository="${repository#git@github.com:}"; repository="${repository%.git}" ;;
  git@github.com:*) repository="${repository#git@github.com:}" ;;
  *) printf '%s\n' 'repository origin is not a GitHub owner/repository URL' >&2; exit 65 ;;
esac
[[ "$repository" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || { printf '%s\n' 'repository origin is not a GitHub owner/repository URL' >&2; exit 65; }
github_identity="$(gh api "repos/$repository" --jq '[.full_name, (.owner.id|tostring), (.id|tostring)] | @tsv')" || {
  printf '%s\n' 'could not resolve exact GitHub repository identity with gh CLI' >&2; exit 69;
}
IFS=$'\t' read -r github_repository github_owner_id github_repository_id <<<"$github_identity"
[[ "$github_repository" = "$repository" && "$github_owner_id" =~ ^[1-9][0-9]*$ && "$github_repository_id" =~ ^[1-9][0-9]*$ ]] || {
  printf '%s\n' 'gh CLI returned an invalid GitHub repository identity' >&2; exit 65;
}

deployment_name="node-$(date -u +%y%m%d%H%M)-$(printf '%04x' "$RANDOM")"
printf '%s\n' "$identity" | jq -c \
  --arg profile "$aws_profile" --arg region "$aws_region" --arg account "$aws_account_id" --arg caller "$caller_arn" \
  --arg deployment "$deployment_name" --arg repository "$github_repository" --arg owner "$github_owner_id" --arg repository_id "$github_repository_id" \
  '{aws_profile:$profile,aws_region:$region,aws_account_id:$account,caller_arn:$caller,deployment_name:$deployment,github_repository:$repository,github_owner_id:$owner,github_repository_id:$repository_id,gitops_client_github_repository:$repository,gitops_client_github_owner_id:$owner,gitops_client_github_repository_id:$repository_id}'
