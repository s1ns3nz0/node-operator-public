#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$script_dir/lib/common.sh"
root="$(repo_root)"
fail() { printf 'FAIL CodeBuild release activation: %s\n' "$*" >&2; exit 1; }

terraform_file="$root/infra/terraform/vault-signer.tf"
workflow="$root/.github/workflows/release-bundle.yml"
signer_script="$root/scripts/release/sign-release-bundle.sh"
contract="$root/docs/gitops/codebuild-signing-input-contract.md"
for file in "$terraform_file" "$workflow" "$signer_script" "$contract"; do
  test -f "$file" || fail "missing required file: $file"
done
grep -Fq 'scripts/release/sign-release-bundle.sh' "$workflow" || fail 'release workflow must delegate signing to the reviewed signer helper'

terraform_project="$(awk '
  /^resource "aws_codebuild_project" "release_signer" \{/ { in_project=1 }
  in_project { print }
  in_project && /^}$/ { exit }
' "$terraform_file")"
expected_input_version_resource="resources = [\"\${aws_s3_bucket.release_artifacts[0].arn}/release-input/*\"]"
test -n "$terraform_project" || fail 'release signer CodeBuild project is missing'

for required in \
  'variable "release_signer_image"' \
  'default     = ""' \
  'dkr\\.ecr\\.[a-z0-9-]+\\.amazonaws\\.com' \
  '@sha256:' \
  'var.enable_release_signer_ecr_mirror' \
  'image                       = var.release_signer_image' \
  'subnets            = var.release_signer_subnet_ids' \
  'length(var.release_signer_subnet_ids) > 0' \
  'source-location-must-be-overridden.zip' \
  'buildspec = "buildspec-release-sign.yml"' \
  'path                = "release-signer-output"' \
  'name                = "release-signer-output.zip"' \
  'namespace_type      = "BUILD_ID"' \
  'packaging           = "ZIP"'; do
  grep -Fq "$required" "$terraform_file" || fail "Terraform omits required signer guard or contract field: $required"
done

printf '%s\n' "$terraform_project" | grep -Fq 'type      = "S3"' || fail 'CodeBuild source must remain S3'
printf '%s\n' "$terraform_project" | grep -Fq 'encryption_disabled = false' || fail 'CodeBuild output must remain encrypted'
grep -Fq 'sid       = "ListReleaseArtifactVersionsForSignerSource"' "$terraform_file" || fail 'signer role lacks version-list access for immutable S3 source selection'
grep -Fq 'actions   = ["s3:ListBucketVersions"]' "$terraform_file" || fail 'signer role lacks ListBucketVersions for immutable S3 source selection'
grep -Fq 'sid       = "ReadImmutableSignerInputVersions"' "$terraform_file" || fail 'signer role lacks a distinct immutable-input version-read statement'
grep -Fq 'actions   = ["s3:GetObjectVersion"]' "$terraform_file" || fail 'signer role lacks immutable object-version read access'
grep -Fq "$expected_input_version_resource" "$terraform_file" || fail 'signer object-version read scope is missing or broadened'
if printf '%s\n' "$terraform_project" | grep -Eq 'aws/codebuild/standard|bootstrap\.zip|aws_subnet\.private'; then
  fail 'CodeBuild project retains a public standard-image fallback, bootstrap input, or implicit subnet selection'
fi

github_release_runner_policy="$(awk '
  /^resource "aws_iam_role_policy" "github_release_runner" \{/ { in_policy=1 }
  in_policy { print }
  in_policy && /^}$/ { exit }
' "$terraform_file")"
expected_input_resource="Resource = [\"\${aws_s3_bucket.release_artifacts[0].arn}/release-input/sha256/*\"]"
printf '%s\n' "$github_release_runner_policy" | grep -Fq 'Sid      = "ReadImmutableSignerInputs"' || fail 'release runner lacks a distinct immutable-input read statement'
printf '%s\n' "$github_release_runner_policy" | grep -Fq 'Action   = ["s3:GetObject"]' || fail 'release runner cannot read immutable signer inputs for safe retry'
printf '%s\n' "$github_release_runner_policy" | grep -Fq "$expected_input_resource" || fail 'release runner immutable-input read scope is missing or broadened'

for required in \
  'buildspec-release-sign.yml' \
  'node-operator-release-bundle.tar' \
  'node-operator-release-bundle.sha256' \
  'provenance-input.json' \
  'aws s3api put-object' \
  "--if-none-match '*'" \
  "aws s3 cp \"s3://\${INPUT_BUCKET}/\${input_key}\"" \
  "cmp \"\$RUNNER_TEMP/release/node-operator-release-bundle.sha256\"" \
  "input_version=\"\$(aws s3api head-object" \
  '--query VersionId --output text' \
  "--source-version \"\$input_version\"" \
  "--source-location-override \"\${INPUT_BUCKET}/\${input_key}\"" \
  'release_signer_project="${RELEASE_SIGNER_PROJECT:-node-operator-baseline-release-signer}"' \
  '--project-name "$release_signer_project"' \
  'release-verification.json' \
  "scripts/ci/verify-release-signature.sh \"\$signer_output\"" \
  'release-signer-output.zip'; do
  grep -Fq -- "$required" "$signer_script" || fail "signer helper omits required immutable signer boundary: $required"
done

grep -Fq 'output "release_signer_project_name"' "$root/infra/terraform/private-release-runner.tf" || fail 'Terraform does not expose the optional signer project name'

if grep -Eq 'release-input/\$\{?GITHUB_SHA\}?\.zip|signature\.json|verify\.json' "$signer_script"; then
  fail 'release workflow retains a legacy source key or raw Transit response consumption'
fi

# The workflow uses only a short-lived STS response. Literal access keys,
# secret values, Vault tokens, and public Vault URLs are prohibited here.
if grep -Eq 'AKIA[0-9A-Z]{16}|(?i:aws_secret_access_key)[[:space:]]*:|(?i:vault_token)[[:space:]]*:|https?://[^"[:space:]]*(vault|8200)' "$workflow" "$signer_script"; then
  fail 'activation code introduces static credentials or a public Vault endpoint'
fi

for required in \
  'implemented code contract' \
  'enable_release_signer=false' \
  'release_signer_image=""' \
  'If-None-Match: *' \
  'source-version is the S3 VersionId' \
  'cannot replace the input.' \
  'release-signer-output.zip' \
  "same-account ECR \`...@sha256:<digest>\`" \
  'No static credentials, raw Transit response artifacts, or public Vault'; do
  grep -Fq "$required" "$contract" || fail "contract does not document activation state: $required"
done

printf 'PASS CodeBuild signer activation is digest-pinned, source-immutable, output-gated, and disabled by default.\n'
