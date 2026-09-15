locals {
  generated_state_bucket = "${var.name}-tfstate-${var.aws_account_id}-${replace(var.aws_region, "-", "")}"
  state_bucket           = coalesce(var.state_bucket_name, local.generated_state_bucket)
  state_bucket_arn       = "arn:aws:s3:::${local.state_bucket}"
  lock_table             = "${var.name}-terraform-lock"
  tags = {
    ManagedBy        = "terraform"
    Project          = "node-operator"
    Deployment       = var.name
    DeploymentRegion = var.aws_region
    Purpose          = "terraform-state-bootstrap"
  }
}

resource "aws_s3_bucket" "state" {
  bucket        = local.state_bucket
  force_destroy = false
  tags          = local.tags
  lifecycle {
    prevent_destroy = true

    precondition {
      condition = alltrue([
        for principal_arn in var.backend_principal_arns :
        can(regex("^arn:aws:iam::${var.aws_account_id}:role/", principal_arn))
      ])
      error_message = "backend_principal_arns must contain only IAM roles in aws_account_id."
    }
  }
}

resource "aws_kms_key" "state" {
  description             = "Dedicated encryption for Terraform bootstrap state and locking"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat(
      [{
        Sid       = "EnableAccountIamPermissions", Effect = "Allow"
        Principal = { AWS = "arn:aws:iam::${var.aws_account_id}:root" }
        Action    = "kms:*", Resource = "*"
      }],
      length(var.backend_principal_arns) == 0 ? [] : [
        {
          Sid       = "AllowNamedBackendRolesS3DataCrypto", Effect = "Allow"
          Principal = { AWS = tolist(var.backend_principal_arns) }
          Action    = ["kms:Decrypt", "kms:GenerateDataKey"]
          Resource  = "*"
          Condition = {
            StringEquals = {
              "kms:CallerAccount" = var.aws_account_id
              "kms:ViaService"    = "s3.${var.aws_region}.amazonaws.com"
            }
            StringLike = {
              "kms:EncryptionContext:aws:s3:arn" = "${local.state_bucket_arn}/*"
            }
          }
        },
        {
          Sid       = "AllowNamedBackendRolesDynamoDataCrypto", Effect = "Allow"
          Principal = { AWS = tolist(var.backend_principal_arns) }
          Action = [
            "kms:Encrypt", "kms:Decrypt", "kms:ReEncryptFrom", "kms:ReEncryptTo",
            "kms:GenerateDataKey", "kms:GenerateDataKeyWithoutPlaintext"
          ]
          Resource = "*"
          Condition = {
            StringEquals = {
              "kms:CallerAccount"                               = var.aws_account_id
              "kms:ViaService"                                  = "dynamodb.${var.aws_region}.amazonaws.com"
              "kms:EncryptionContext:aws:dynamodb:tableName"    = local.lock_table
              "kms:EncryptionContext:aws:dynamodb:subscriberId" = var.aws_account_id
            }
          }
        },
        {
          Sid       = "AllowNamedBackendRolesDescribeStateKey", Effect = "Allow"
          Principal = { AWS = tolist(var.backend_principal_arns) }
          Action    = ["kms:DescribeKey"]
          Resource  = "*"
          Condition = {
            StringEquals = { "kms:CallerAccount" = var.aws_account_id }
          }
        }
      ]
    )
  })
  tags = local.tags
  lifecycle { prevent_destroy = true }
}

resource "aws_kms_alias" "state" {
  name          = "alias/node-operator-${var.name}-bootstrap-state"
  target_key_id = aws_kms_key.state.key_id
}

resource "aws_s3_bucket_lifecycle_configuration" "state" {
  bucket = aws_s3_bucket.state.id
  rule {
    id     = "abort-incomplete-uploads"
    status = "Enabled"
    filter {}
    abort_incomplete_multipart_upload { days_after_initiation = 7 }
  }
}

resource "aws_s3_bucket_notification" "state" {
  bucket      = aws_s3_bucket.state.id
  eventbridge = true
}

resource "aws_s3_bucket" "state_access_logs" {
  bucket        = "${substr(local.state_bucket, 0, 48)}-${substr(sha256(local.state_bucket), 0, 8)}-logs"
  force_destroy = false
  tags          = local.tags
  lifecycle { prevent_destroy = true }
}

resource "aws_s3_bucket_public_access_block" "state_access_logs" {
  bucket                  = aws_s3_bucket.state_access_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "state_access_logs" {
  bucket = aws_s3_bucket.state_access_logs.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "state_access_logs" {
  bucket = aws_s3_bucket.state_access_logs.id
  rule {
    apply_server_side_encryption_by_default { sse_algorithm = "AES256" }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "state_access_logs" {
  bucket = aws_s3_bucket.state_access_logs.id
  rule {
    id     = "retain-access-logs"
    status = "Enabled"
    filter {}
    abort_incomplete_multipart_upload { days_after_initiation = 7 }
    expiration { days = 365 }
  }
}

resource "aws_s3_bucket_notification" "state_access_logs" {
  bucket      = aws_s3_bucket.state_access_logs.id
  eventbridge = true
}

resource "aws_s3_bucket_policy" "state_access_logs" {
  bucket = aws_s3_bucket.state_access_logs.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowOnlyStateAccessLogDelivery", Effect = "Allow"
        Principal = { Service = "logging.s3.amazonaws.com" }
        Action    = "s3:PutObject", Resource = "${aws_s3_bucket.state_access_logs.arn}/state/*"
        Condition = {
          StringEquals = { "aws:SourceAccount" = var.aws_account_id }
          ArnLike      = { "aws:SourceArn" = aws_s3_bucket.state.arn }
        }
      },
      {
        Sid       = "DenyInsecureTransport", Effect = "Deny", Principal = "*", Action = "s3:*"
        Resource  = [aws_s3_bucket.state_access_logs.arn, "${aws_s3_bucket.state_access_logs.arn}/*"]
        Condition = { Bool = { "aws:SecureTransport" = "false" } }
      }
    ]
  })
  depends_on = [aws_s3_bucket_public_access_block.state_access_logs]
}

resource "aws_s3_bucket_logging" "state" {
  bucket        = aws_s3_bucket.state.id
  target_bucket = aws_s3_bucket.state_access_logs.id
  target_prefix = "state/"
  depends_on    = [aws_s3_bucket_policy.state_access_logs]
}

resource "aws_s3_bucket_versioning" "state" {
  bucket = aws_s3_bucket.state.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "state" {
  bucket = aws_s3_bucket.state.id
  rule {
    bucket_key_enabled = false
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.state.arn
    }
  }
  # Preserve the denial before changing defaults, including with providers
  # that cannot represent S3's native BlockedEncryptionTypes setting.
  depends_on = [aws_s3_bucket_policy.state]
}

resource "aws_s3_bucket_policy" "state" {
  bucket = aws_s3_bucket.state.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyInsecureTransport", Effect = "Deny", Principal = "*"
        Action    = "s3:*"
        Resource  = [local.state_bucket_arn, "${local.state_bucket_arn}/*"]
        Condition = { Bool = { "aws:SecureTransport" = "false" } }
      },
      {
        Sid       = "DenyCustomerProvidedEncryptionKeys", Effect = "Deny", Principal = "*"
        Action    = "s3:PutObject", Resource = "${local.state_bucket_arn}/*"
        Condition = { Null = { "s3:x-amz-server-side-encryption-customer-algorithm" = "false" } }
      }
    ]
  })
}

resource "aws_s3_bucket_public_access_block" "state" {
  bucket                  = aws_s3_bucket.state.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_dynamodb_table" "lock" {
  name         = local.lock_table
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "LockID"
  attribute {
    name = "LockID"
    type = "S"
  }
  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.state.arn
  }
  point_in_time_recovery {
    enabled = true
  }
  tags = local.tags
  lifecycle {
    prevent_destroy = true
    # Existing bootstrap tables may already be encrypted with an AWS-managed
    # key. Do not block a fresh-region import on a long-running SSE migration;
    # newly created tables still use the customer-managed key above.
    ignore_changes = [server_side_encryption]
  }
}
