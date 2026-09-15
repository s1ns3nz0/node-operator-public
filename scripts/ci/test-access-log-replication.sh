#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
tf="$root/infra/terraform/access-log-replication.tf"

test -f "$tf" || { printf '%s\n' "missing access-log replication Terraform" >&2; exit 1; }

require() { grep -Fq "$1" "$tf" || { printf 'missing required access-log replication contract: %s\n' "$1" >&2; exit 1; }; }
forbid() { ! grep -Fq "$1" "$tf" || { printf 'forbidden access-log replication configuration: %s\n' "$1" >&2; exit 1; }; }

# Literal Terraform interpolation fragments must not expand in this shell test.
# shellcheck disable=SC2016
for value in \
  'resource "aws_s3_bucket_replication_configuration" "audit_access_logs"' \
  'resource "aws_s3_bucket_replication_configuration" "release_artifacts_access_logs"' \
  'data "aws_iam_policy_document" "audit_access_log_replication_assume_role"' \
  'data "aws_iam_policy_document" "release_access_log_replication_assume_role"' \
  'identifiers = ["s3.amazonaws.com"]' \
  'filter { prefix = "audit/" }' \
  'filter { prefix = "validator-audit/" }' \
  'filter { prefix = "vault-snapshot/" }' \
  'filter { prefix = "release-artifacts/" }' \
  'priority = 1' \
  'priority = 2' \
  'priority = 3' \
  'aws_s3_bucket_versioning.audit_access_logs' \
  'aws_s3_bucket_versioning.audit_replica_access_logs' \
  'aws_s3_bucket_versioning.release_artifacts_access_logs' \
  'aws_s3_bucket_versioning.release_artifacts_replica_access_logs' \
  'aws_iam_role_policy.audit_access_log_replication' \
  'aws_iam_role_policy.release_access_log_replication' \
  '"${aws_s3_bucket.audit_replica_access_logs.arn}/audit/*"' \
  '"${aws_s3_bucket.audit_replica_access_logs.arn}/validator-audit/*"' \
  '"${aws_s3_bucket.audit_replica_access_logs.arn}/vault-snapshot/*"' \
  '"${aws_s3_bucket.release_artifacts_replica_access_logs[0].arn}/release-artifacts/*"' \
  'status = "Disabled"'; do
  require "$value"
done

forbid 's3:ReplicateDelete'
forbid 's3:ObjectOwnerOverrideToBucketOwner'
forbid 's3:*'
forbid 'kms:'
forbid 'replica_modifications'
forbid 'existing_object_replication'
forbid 'source_selection_criteria'
forbid 'replication_time'
forbid 'metrics {'
forbid 'encryption_configuration'
forbid 'audit-replica/*'
forbid 'release-artifacts-replica/*'
forbid 'aws:SourceAccount'
forbid 'aws:SourceArn'

terraform fmt -check "$tf"
terraform -chdir="$root/infra/terraform" validate
printf '%s\n' 'PASS: access-log replication is prefix-scoped, one-way, and non-destructive.'
