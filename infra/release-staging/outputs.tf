output "staging_bucket_name" {
  description = "Non-secret versioned OCI staging bucket name."
  value       = aws_s3_bucket.staging.bucket
}

output "access_logs_bucket_name" {
  description = "Non-secret S3 server-access-log bucket name."
  value       = aws_s3_bucket.access_logs.bucket
}

output "evidence_reader_role_arn" {
  description = "Non-secret GitHub OIDC role ARN restricted to exact-version OCI reads."
  value       = aws_iam_role.evidence_reader.arn
}
