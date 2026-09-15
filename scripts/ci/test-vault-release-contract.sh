#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$script_dir/lib/common.sh"
root="$(repo_root)"
fail() { printf 'FAIL %s\n' "$*" >&2; exit 1; }

role="$root/deploy/vault/auth/github-release-jwt-role.json"
vault_policy="$root/deploy/vault/policies/release-runner-dynamic-aws.hcl"
aws_policy="$root/deploy/vault/aws/release-runner-assumed-role-policy.json"
docs=(
  "$root/deploy/vault/github-release-jwt-auth.md"
  "$root/deploy/vault/release-runner-dynamic-aws.md"
)

require_command jq
for file in "$role" "$vault_policy" "$aws_policy" "${docs[@]}"; do
  test -f "$file" || fail "missing Vault release contract file: $file"
done

jq -e '
  .role_type == "jwt" and
  .bound_audiences == ["https://vault.node-operator.internal"] and
  .user_claim == "repository_id" and
  .bound_claims_type == "glob" and
  .bound_claims.repository == "s1ns3nz0/node-operator" and
  .bound_claims.repository_owner == "s1ns3nz0" and
  .bound_claims.ref_type == "tag" and
  .bound_claims.ref == "refs/tags/v*" and
  .bound_claims.workflow_ref == "s1ns3nz0/node-operator/.github/workflows/release-bundle.yml@refs/tags/v*" and
  .token_policies == ["release-runner-dynamic-aws"] and
  .token_ttl == "15m" and .token_max_ttl == "15m" and
  .token_type == "batch" and
  .token_num_uses == 1 and .token_no_default_policy == true
' "$role" >/dev/null || fail "GitHub release JWT claims or TTL are too broad"

test "$(grep -Ec '^path "aws/creds/release-runner" \{' "$vault_policy")" -eq 1 || fail "dynamic AWS policy must expose only release-runner credentials"
grep -Fqx '  capabilities = ["read"]' "$vault_policy" || fail "dynamic AWS policy must be read-only"
if grep -Eq 'capabilities = \[.*(create|update|delete|list|sudo).*\]' "$vault_policy"; then
  fail "dynamic AWS policy grants broad Vault capabilities"
fi

jq -e '
  .Version == "2012-10-17" and
  ([.Statement[].Action[]] | sort) == ["codebuild:BatchGetBuilds", "codebuild:StartBuild", "s3:GetObject", "s3:ListBucket", "s3:PutObject"] and
  all(.Statement[].Action[]; endswith("*") | not) and
  .Statement[0].Resource == "arn:aws:s3:::REPLACE_WITH_RELEASE_ARTIFACT_BUCKET/release-input/*" and
  .Statement[1].Resource == "arn:aws:s3:::REPLACE_WITH_RELEASE_ARTIFACT_BUCKET/release-signer-output/*" and
  .Statement[2].Resource == "arn:aws:s3:::REPLACE_WITH_RELEASE_ARTIFACT_BUCKET" and
  .Statement[3].Resource == "arn:aws:codebuild:ap-northeast-2:REPLACE_WITH_ACCOUNT_ID:project/node-operator-baseline-release-signer"
' "$aws_policy" >/dev/null || fail "dynamic AWS policy has broad actions or resources"

if grep -REn --include='*.json' --include='*.hcl' '(AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|aws_access_key|aws_secret_key|client_secret|token[[:space:]]*=)' "$root/deploy/vault/auth" "$root/deploy/vault/aws" "$root/deploy/vault/policies"; then
  fail "Vault contract contains a static credential"
fi

grep -Fq 'self-hosted runner' "${docs[0]}" || fail "private runner prerequisite is undocumented"
grep -Fq 'fail closed' "${docs[0]}" || fail "JWT failure behavior is undocumented"
grep -Fq 'static fallback credential' "${docs[0]}" || fail "static fallback prohibition is undocumented"

printf 'PASS Vault release JWT and dynamic AWS contract is structurally constrained.\n'
