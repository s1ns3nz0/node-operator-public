resource "aws_s3_bucket_logging" "validator_audit" {
  bucket        = aws_s3_bucket.validator_audit.id
  target_bucket = aws_s3_bucket.audit_access_logs.id
  target_prefix = "validator-audit/"
  depends_on    = [aws_s3_bucket_policy.audit_access_logs]
}

resource "aws_s3_bucket_logging" "vault_snapshot" {
  bucket        = aws_s3_bucket.vault_snapshot.id
  target_bucket = aws_s3_bucket.audit_access_logs.id
  target_prefix = "vault-snapshot/"
  depends_on    = [aws_s3_bucket_policy.audit_access_logs]
}
