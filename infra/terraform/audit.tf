resource "aws_s3_bucket" "audit" {
  bucket_prefix = "${substr(local.name_prefix, 0, 20)}-audit-"
  force_destroy = false

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-audit"
  })
}

resource "aws_s3_bucket_public_access_block" "audit" {
  bucket                  = aws_s3_bucket.audit.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "audit" {
  bucket = aws_s3_bucket.audit.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_versioning" "audit" {
  bucket = aws_s3_bucket.audit.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "audit" {
  bucket = aws_s3_bucket.audit.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.audit.arn
      sse_algorithm     = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "audit" {
  bucket = aws_s3_bucket.audit.id

  rule {
    id     = "retain-audit-records"
    status = "Enabled"

    filter {}

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }

    transition {
      days          = 90
      storage_class = "STANDARD_IA"
    }

    transition {
      days          = 365
      storage_class = "GLACIER"
    }

    noncurrent_version_expiration {
      noncurrent_days = 365
    }
  }
}

# S3 server access logs cannot be delivered to a bucket with default SSE-KMS.
# This dedicated, non-recursive destination therefore uses SSE-S3, while the
# audited source continues to use its purpose-specific KMS key above.
resource "aws_s3_bucket" "audit_access_logs" {
  #checkov:skip=CKV_AWS_145:S3 server access log delivery does not support a default SSE-KMS destination key.
  bucket_prefix = "${substr(local.name_prefix, 0, 20)}-al-"
  force_destroy = false

  tags = merge(local.common_tags, {
    Name    = "${local.name_prefix}-audit-access-logs"
    Purpose = "audit-bucket-server-access-logs"
  })
}

resource "aws_s3_bucket_public_access_block" "audit_access_logs" {
  bucket                  = aws_s3_bucket.audit_access_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "audit_access_logs" {
  bucket = aws_s3_bucket.audit_access_logs.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_versioning" "audit_access_logs" {
  bucket = aws_s3_bucket.audit_access_logs.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "audit_access_logs" {
  bucket = aws_s3_bucket.audit_access_logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "audit_access_logs" {
  bucket = aws_s3_bucket.audit_access_logs.id

  rule {
    id     = "retain-audit-access-logs"
    status = "Enabled"

    filter {}

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }

    transition {
      days          = 90
      storage_class = "STANDARD_IA"
    }

    expiration {
      days = 365
    }
  }
}

data "aws_iam_policy_document" "audit_access_logs" {
  statement {
    sid    = "DenyInsecureTransport"
    effect = "Deny"

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    actions   = ["s3:*"]
    resources = [aws_s3_bucket.audit_access_logs.arn, "${aws_s3_bucket.audit_access_logs.arn}/*"]

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }

  statement {
    sid    = "AllowOnlyAuditBucketServerAccessLogDelivery"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["logging.s3.amazonaws.com"]
    }

    actions = ["s3:PutObject"]
    resources = [
      "${aws_s3_bucket.audit_access_logs.arn}/audit/*",
      "${aws_s3_bucket.audit_access_logs.arn}/validator-audit/*",
      "${aws_s3_bucket.audit_access_logs.arn}/vault-snapshot/*",
    ]

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [var.aws_account_id]
    }

    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = [aws_s3_bucket.audit.arn, aws_s3_bucket.validator_audit.arn, aws_s3_bucket.vault_snapshot.arn]
    }
  }
}

resource "aws_s3_bucket_policy" "audit_access_logs" {
  bucket = aws_s3_bucket.audit_access_logs.id
  policy = data.aws_iam_policy_document.audit_access_logs.json

  depends_on = [aws_s3_bucket_public_access_block.audit_access_logs]
}

resource "aws_s3_bucket_logging" "audit" {
  bucket        = aws_s3_bucket.audit.id
  target_bucket = aws_s3_bucket.audit_access_logs.id
  target_prefix = "audit/"

  depends_on = [aws_s3_bucket_policy.audit_access_logs]
}

resource "aws_s3_bucket_notification" "audit" {
  bucket = aws_s3_bucket.audit.id

  eventbridge = true
}

resource "aws_s3_bucket_notification" "audit_access_logs" {
  bucket = aws_s3_bucket.audit_access_logs.id

  eventbridge = true
}

resource "aws_cloudwatch_log_group" "cloudtrail" {
  name              = "/aws/cloudtrail/${local.name_prefix}-audit"
  retention_in_days = 365
  kms_key_id        = aws_kms_key.audit.arn

  tags = local.common_tags
}

data "aws_iam_policy_document" "audit_notifications_key" {
  source_policy_documents = [data.aws_iam_policy_document.kms_key_administrator.json]

  statement {
    sid    = "AllowSNSToUseNotificationKey"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["sns.amazonaws.com"]
    }

    actions   = ["kms:Decrypt", "kms:GenerateDataKey*"]
    resources = ["*"]
  }

  statement {
    sid    = "AllowCloudTrailToPublishEncryptedAuditNotifications"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    actions   = ["kms:Decrypt", "kms:GenerateDataKey*"]
    resources = ["*"]
  }
}

resource "aws_kms_key" "audit_notifications" {
  description             = "KMS key for CloudTrail audit notifications"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  policy                  = data.aws_iam_policy_document.audit_notifications_key.json

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-audit-notifications"
  })
}

resource "aws_kms_alias" "audit_notifications" {
  name          = "alias/${local.name_prefix}-audit-notifications"
  target_key_id = aws_kms_key.audit_notifications.key_id
}

resource "aws_sns_topic" "audit_notifications" {
  name              = "${local.name_prefix}-audit-notifications"
  kms_master_key_id = aws_kms_key.audit_notifications.arn

  tags = local.common_tags
}

data "aws_iam_policy_document" "audit_notifications" {
  statement {
    sid    = "AllowOnlyApprovedTrailToPublish"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.audit_notifications.arn]

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [var.aws_account_id]
    }

    condition {
      test     = "StringLike"
      variable = "aws:SourceArn"
      values   = ["arn:aws:cloudtrail:${var.aws_region}:${var.aws_account_id}:trail/*"]
    }
  }
}

resource "aws_sns_topic_policy" "audit_notifications" {
  arn    = aws_sns_topic.audit_notifications.arn
  policy = data.aws_iam_policy_document.audit_notifications.json
}

data "aws_iam_policy_document" "cloudtrail_logs_assume_role" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "cloudtrail_logs" {
  name               = "${local.name_prefix}-cloudtrail-logs"
  assume_role_policy = data.aws_iam_policy_document.cloudtrail_logs_assume_role.json

  tags = local.common_tags
}

data "aws_iam_policy_document" "cloudtrail_logs" {
  statement {
    sid       = "WriteOnlyCloudTrailAuditLogGroup"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.cloudtrail.arn}:*"]
  }
}

resource "aws_iam_role_policy" "cloudtrail_logs" {
  name   = "${local.name_prefix}-cloudtrail-logs"
  role   = aws_iam_role.cloudtrail_logs.id
  policy = data.aws_iam_policy_document.cloudtrail_logs.json
}

data "aws_iam_policy_document" "audit_bucket" {
  statement {
    sid    = "AllowCloudTrailToReadBucketAcl"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.audit.arn]

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [var.aws_account_id]
    }

    condition {
      test     = "StringLike"
      variable = "aws:SourceArn"
      values   = ["arn:aws:cloudtrail:${var.aws_region}:${var.aws_account_id}:trail/*"]
    }
  }

  statement {
    sid    = "AllowCloudTrailToWriteLogs"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.audit.arn}/AWSLogs/${var.aws_account_id}/*"]

    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [var.aws_account_id]
    }

    condition {
      test     = "StringLike"
      variable = "aws:SourceArn"
      values   = ["arn:aws:cloudtrail:${var.aws_region}:${var.aws_account_id}:trail/*"]
    }
  }

  statement {
    sid    = "AllowConfigToWriteDeliverySnapshots"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }

    actions   = ["s3:GetBucketAcl", "s3:PutObject"]
    resources = [aws_s3_bucket.audit.arn, "${aws_s3_bucket.audit.arn}/AWSLogs/${var.aws_account_id}/Config/*"]

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [var.aws_account_id]
    }
  }
}

resource "aws_s3_bucket_policy" "audit" {
  bucket = aws_s3_bucket.audit.id
  policy = data.aws_iam_policy_document.audit_bucket.json

  depends_on = [aws_s3_bucket_public_access_block.audit]
}

resource "aws_cloudtrail" "audit" {
  name                          = "${local.name_prefix}-audit"
  s3_bucket_name                = aws_s3_bucket.audit.id
  enable_logging                = true
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  kms_key_id                    = aws_kms_key.audit.arn
  sns_topic_name                = aws_sns_topic.audit_notifications.name
  cloud_watch_logs_group_arn    = "${aws_cloudwatch_log_group.cloudtrail.arn}:*"
  cloud_watch_logs_role_arn     = aws_iam_role.cloudtrail_logs.arn

  depends_on = [
    aws_s3_bucket_policy.audit,
    aws_iam_role_policy.cloudtrail_logs,
    aws_sns_topic_policy.audit_notifications,
  ]

  tags = local.common_tags
}

resource "aws_config_configuration_recorder" "baseline" {
  count    = var.manage_config_recorder ? 1 : 0
  name     = "${local.name_prefix}-config"
  role_arn = aws_iam_role.config.arn

  recording_group {
    all_supported                 = true
    include_global_resource_types = true
  }
}

resource "aws_config_delivery_channel" "baseline" {
  count          = var.manage_config_recorder ? 1 : 0
  name           = "${local.name_prefix}-config"
  s3_bucket_name = aws_s3_bucket.audit.id

  # AWS Config owns the AWSLogs/<account-id>/Config prefix; specifying it here
  # is rejected because the service appends that reserved path automatically.

  snapshot_delivery_properties {
    delivery_frequency = "TwentyFour_Hours"
  }

  depends_on = [aws_s3_bucket_policy.audit]
}

resource "aws_config_configuration_recorder_status" "baseline" {
  # The conditional resource supports accounts that already own the single
  # regional recorder. Checkov's graph rule cannot model that ownership mode;
  # the release contract verifies live recorder status before proceeding.
  #checkov:skip=CKV2_AWS_45:Conditional account-recorder ownership is validated by the release contract.
  count      = var.manage_config_recorder ? 1 : 0
  name       = aws_config_configuration_recorder.baseline[0].name
  is_enabled = true

  depends_on = [
    aws_config_delivery_channel.baseline,
    aws_iam_role_policy_attachment.config,
  ]
}
