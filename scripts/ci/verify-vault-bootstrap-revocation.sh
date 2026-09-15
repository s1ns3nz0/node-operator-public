#!/usr/bin/env bash
set -euo pipefail

: "${AWS_REGION:=ap-northeast-2}"
: "${VAULT_BOOTSTRAP_ROLE_ARN:?VAULT_BOOTSTRAP_ROLE_ARN is required}"
policy_arn='arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy'
policies="$(aws eks list-associated-access-policies --cluster-name node-operator --principal-arn "$VAULT_BOOTSTRAP_ROLE_ARN" --region "$AWS_REGION" --output json)"
if jq -e --arg policy "$policy_arn" '.associatedAccessPolicies[]? | select(.policyArn == $policy)' <<<"$policies" >/dev/null; then
  printf 'Vault bootstrap cluster-admin association remains present.\n' >&2
  exit 1
fi
printf 'PASS Vault bootstrap cluster-admin association is absent.\n'
