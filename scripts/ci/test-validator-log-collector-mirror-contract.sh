#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
source "$root/scripts/ci/lib/workflow-contract.sh"
terraform_file="$root/infra/terraform/validator-log-collector-ecr-mirror.tf"
workflow="$root/.github/workflows/private-ecr-mirror.yml"

for required in 'enable_validator_log_collector_ecr_mirror' 'default     = false' 'aws_ecr_repository" "validator_log_collector' 'image_tag_mutability = "IMMUTABLE"' 'encryption_type = "KMS"' 'scan_on_push = true' 'local.github_destination_oidc_subject_prefix}:environment:validator-log-collector-ecr-mirror' 'ecr:BatchGetImage' 'ecr:DescribeImages' 'ecr:PutImage'; do
  grep -Fq "$required" "$terraform_file" || { printf 'missing collector mirror contract: %s\n' "$required" >&2; exit 1; }
done
grep -Fq 'cr.fluentbit.io/fluent/fluent-bit@sha256:' <(workflow_job_source "$workflow" validator-log-collector)
grep -Fq 'docker buildx imagetools create' <(workflow_job_source "$workflow" validator-log-collector)
grep -Fq "needs: [preflight]" <(workflow_job_source "$workflow" validator-log-collector)
grep -Fq "inputs.target == 'validator-log-collector'" <(workflow_job_source "$workflow" validator-log-collector)
grep -Fq "github.ref == 'refs/heads/main'" <(workflow_job_source "$workflow" validator-log-collector)
if grep -Eq 'ecr:(DeleteRepository|DeleteImage|SetRepositoryPolicy|\*)' "$terraform_file"; then printf '%s\n' 'collector mirror grants destructive ECR permission' >&2; exit 1; fi
printf '%s\n' 'PASS: Fluent Bit mirror is private, immutable, OIDC-bound, and push-only.'
