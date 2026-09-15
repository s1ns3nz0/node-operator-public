#!/usr/bin/env bash
set -euo pipefail
set +x

usage() { printf 'usage: %s --principal-arn arn:aws:iam::123456789012:user/NAME\n' "${0##*/}" >&2; exit 64; }
principal=''
principal_seen=false
while [ "$#" -gt 0 ]; do
  case "$1" in
    --principal-arn)
      [ "$#" -ge 2 ] || usage
      "$principal_seen" && usage
      principal_seen=true
      principal="$2"
      shift 2
      ;;
    *) usage ;;
  esac
done
[ -n "$principal" ] || usage
[[ "$principal" =~ ^arn:aws:iam::123456789012:user/[A-Za-z0-9+=,.@_-]+$ ]] || {
  printf '%s\n' 'principal must be one exact IAM user ARN in account 123456789012, without a path or wildcard' >&2; exit 64;
}
: "${VAULT_TOKEN:?VAULT_TOKEN must contain an existing Vault administrator token}"
for command in vault jq; do command -v "$command" >/dev/null 2>&1 || { printf 'missing command: %s\n' "$command" >&2; exit 69; }; done

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
policy_file="$root/deploy/vault/operator-recovery-policy.hcl"
test -f "$policy_file" || { printf '%s\n' 'operator recovery policy file is missing' >&2; exit 69; }

fail() { printf '%s\n' "$1" >&2; exit 1; }
mounts="$(vault auth list -format=json 2>/dev/null)" || fail 'cannot list Vault auth mounts'
policies="$(vault policy list -format=json 2>/dev/null)" || fail 'cannot list Vault policies'
jq -e 'type == "object" and (has("operator-aws/") | not)' <<<"$mounts" >/dev/null || fail 'operator-aws auth mount already exists or mount list is malformed; refusing overwrite'
jq -e 'type == "array" and (index("operator-recovery") | not)' <<<"$policies" >/dev/null || fail 'operator-recovery policy already exists or policy list is malformed; refusing overwrite'

vault auth enable -path=operator-aws aws >/dev/null 2>&1 || fail 'failed to create operator-aws auth mount'
vault policy write operator-recovery "$policy_file" >/dev/null 2>&1 || fail 'failed to create operator-recovery policy'
vault write auth/operator-aws/config/client sts_region=ap-northeast-2 sts_endpoint=https://sts.ap-northeast-2.amazonaws.com use_sts_region_from_client=false iam_server_id_header_value=node-operator-vault-operator-123456789012-apne2 >/dev/null 2>&1 || fail 'failed to configure regional STS and IAM server header'
vault write auth/operator-aws/role/operator-recovery auth_type=iam bound_iam_principal_arn="$principal" resolve_aws_unique_ids=true token_policies=operator-recovery token_ttl=5m token_max_ttl=10m token_explicit_max_ttl=10m token_no_default_policy=true >/dev/null 2>&1 || fail 'failed to create operator role; Vault requires IAM:GetUser for unique-ID resolution'

config="$(vault read -format=json auth/operator-aws/config/client 2>/dev/null)" || fail 'cannot read back AWS auth client configuration'
role="$(vault read -format=json auth/operator-aws/role/operator-recovery 2>/dev/null)" || fail 'cannot read back operator role'
actual_policy="$(vault policy read operator-recovery 2>/dev/null)" || fail 'cannot read back operator policy'
jq -e '.data.sts_region == "ap-northeast-2" and .data.sts_endpoint == "https://sts.ap-northeast-2.amazonaws.com" and .data.use_sts_region_from_client == false and .data.iam_server_id_header_value == "node-operator-vault-operator-123456789012-apne2"' <<<"$config" >/dev/null || fail 'AWS auth client readback differs from required configuration'
jq -e --arg principal "$principal" '
 .data.auth_type == "iam" and .data.bound_iam_principal_arn == [$principal] and
 .data.resolve_aws_unique_ids == true and
 (.data.bound_iam_principal_id as $ids | ($ids | type == "array") and ($ids | length == 1) and ($ids[0] | type == "string" and length > 0)) and
 .data.token_policies == ["operator-recovery"] and .data.token_ttl == 300 and .data.token_max_ttl == 600 and
 .data.token_explicit_max_ttl == 600 and .data.token_no_default_policy == true
' <<<"$role" >/dev/null || fail 'operator role readback is incomplete or differs from the required least-privilege contract'
test "$actual_policy" = "$(cat "$policy_file")" || fail 'operator policy readback differs from the reviewed policy'
printf '%s\n' 'PASS operator AWS recovery auth configured; IAM:GetUser prerequisite was required for unique-ID binding.'
