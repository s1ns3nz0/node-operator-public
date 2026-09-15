output "cluster_name" {
  description = "Private EKS cluster name; this does not expose an endpoint or credential."
  value       = aws_eks_cluster.private.name
}

output "deployment_account_id" {
  description = "Non-secret AWS account identifier bound to this deployment."
  value       = var.aws_account_id
}

output "private_subnet_ids" {
  description = "Private worker subnet identifiers."
  value       = local.system_subnet_ids
}

output "temporary_ssm_ops_host_instance_id" {
  description = "Temporary private SSM tunnel target instance ID, or null while disabled."
  value       = try(aws_instance.temporary_ssm_ops_host[0].id, null)
}

output "audit_bucket_name" {
  description = "Private audit bucket name."
  value       = aws_s3_bucket.audit.id
}

# Non-secret, exact inputs for the post-activation immutable validator-audit
# reader.  These intentionally name the separate Object-Lock archive rather
# than the general audit bucket above; callers must not infer either value.
output "validator_audit_bucket_name" {
  description = "Object-Lock validator event archive bucket name."
  value       = aws_s3_bucket.validator_audit.id
}

output "validator_audit_prefix" {
  description = "Only readable validator event archive prefix."
  value       = "validator/"
}

output "validator_audit_kms_key_arn" {
  description = "KMS key ARN protecting the validator event archive."
  value       = aws_kms_key.validator_audit.arn
}

output "validator_audit_reader_role_arn" {
  description = "Pod-Identity role ARN with read-only validator archive access."
  value       = aws_iam_role.validator_audit_reader.arn
}

output "validator_audit_reader_namespace" {
  description = "Namespace bound to the validator archive reader Pod Identity association."
  value       = "validator-observability"
}

output "validator_audit_reader_service_account" {
  description = "Service account bound to the validator archive reader Pod Identity association."
  value       = "validator-audit-reader"
}

output "vault_unseal_key_arn" {
  description = "KMS key ARN for Vault auto-unseal configuration; no secret material is exposed."
  value       = aws_kms_key.vault.arn
}

output "ebs_kms_key_arn" {
  description = "Deployment-owned EBS KMS key used by the client chart StorageClasses."
  value       = aws_kms_key.ebs.arn
}

output "vault_role_arn" {
  description = "IAM role ARN for the Vault Pod Identity association."
  value       = aws_iam_role.vault.arn
}

output "release_artifact_bucket_arn" {
  description = "Dedicated release artifact bucket ARN when signer is enabled."
  value       = var.enable_release_signer ? aws_s3_bucket.release_artifacts[0].arn : null
}

output "release_artifact_kms_key_arn" {
  description = "Dedicated KMS key ARN for release artifacts when signer is enabled."
  value       = var.enable_release_signer ? aws_kms_key.release_artifacts[0].arn : null
}

output "release_artifact_replica_bucket_arn" {
  description = "Tokyo disaster-recovery release artifact bucket ARN when signer is enabled."
  value       = var.enable_release_signer ? aws_s3_bucket.release_artifacts_replica[0].arn : null
}

output "release_signer_ecr_repository_arn" {
  description = "Private signer-image ECR repository ARN when the ECR mirror foundation is enabled."
  value       = var.enable_release_signer_ecr_mirror ? aws_ecr_repository.release_signer[0].arn : null
}

output "release_signer_ecr_repository_url" {
  description = "Private signer-image ECR repository URL when the ECR mirror foundation is enabled; image digests are non-secret."
  value       = var.enable_release_signer_ecr_mirror ? aws_ecr_repository.release_signer[0].repository_url : null
}
