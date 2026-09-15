output "backend" {
  description = "Non-secret backend settings consumed by later release phases."
  value = {
    bucket         = aws_s3_bucket.state.id
    key            = var.baseline_state_key
    region         = var.aws_region
    dynamodb_table = aws_dynamodb_table.lock.name
    encrypt        = true
    kms_key_id     = aws_kms_key.state.arn
  }
}
