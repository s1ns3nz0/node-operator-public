#!/usr/bin/env bash
# shellcheck disable=SC2016 # Terraform expressions are checked as literal contract fragments.
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$script_dir/lib/common.sh"
root="$(repo_root)"
fail() { printf 'FAIL GitOps client ECR publisher contract: %s\n' "$*" >&2; exit 1; }
require_command opa

terraform_file="$root/infra/terraform/gitops-client-ecr-publisher.tf"
documentation="$root/docs/gitops/gitops-client-ecr-publisher-contract.md"
policy_file="$root/policy/gitops_ecr_publisher/hardening.rego"
secure_fixture="$root/policy/gitops_ecr_publisher/fixtures/secure.json"
broad_fixture="$root/policy/gitops_ecr_publisher/fixtures/broad.json"
for file in "$terraform_file" "$documentation" "$policy_file" "$secure_fixture" "$broad_fixture"; do
  test -f "$file" || fail "missing required file: $file"
done

for required in \
  'variable "enable_gitops_client_ecr_publisher"' \
  'default     = false' \
  's1ns3nz0/node-operator-gitops' \
  'gitops-client-ecr-publish' \
  'resource "aws_ecr_repository" "gitops_client"' \
  'image_tag_mutability = "IMMUTABLE"' \
  'scan_on_push = true' \
  'prevent_destroy = true' \
  'resource "aws_iam_role" "github_gitops_client_ecr_publisher"' \
  'token.actions.githubusercontent.com:repository' \
  '"ecr:GetAuthorizationToken"' \
  '"ecr:BatchCheckLayerAvailability"' \
  '"ecr:BatchGetImage"' \
  '"ecr:CompleteLayerUpload"' \
  '"ecr:DescribeImages"' \
  '"ecr:InitiateLayerUpload"' \
  '"ecr:PutImage"' \
  '"ecr:UploadLayerPart"' \
  'github_gitops_client_ecr_publisher_role_arn'; do
  grep -Fq "$required" "$terraform_file" || fail "Terraform contract omits: $required"
done

if grep -Eq 'ecr:(DeleteRepository|DeleteImage|SetRepositoryPolicy|PutLifecyclePolicy|\*)' "$terraform_file"; then
  fail 'publisher role exceeds the required ECR upload boundary'
fi

opa eval --format=json --data "$policy_file" --input "$secure_fixture" 'data.nodeoperator.gitops_ecr_publisher.deny' | jq -e '.result[0].expressions[0].value == []' >/dev/null || fail 'secure publisher policy fixture was rejected'
opa eval --format=json --data "$policy_file" --input "$broad_fixture" 'data.nodeoperator.gitops_ecr_publisher.deny' | jq -e '.result[0].expressions[0].value | length > 0' >/dev/null || fail 'broad publisher policy fixture was accepted'

printf 'PASS dedicated GitOps client ECR publisher remains repository- and environment-bound.\n'
