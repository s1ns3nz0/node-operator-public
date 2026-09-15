# A separate bucket is mandatory because S3 Object Lock is enabled only when a
# bucket is created. This is the canonical archive for non-secret validator
# lifecycle records; CloudWatch and OpenSearch are derived stores.
resource "aws_s3_bucket" "validator_audit" {
  # bucket_prefix leaves room for Terraform's random suffix (S3 permits at
  # most 37 prefix characters).
  bucket_prefix       = "${substr(local.name_prefix, 0, 20)}-va-"
  force_destroy       = false
  object_lock_enabled = true

  tags = merge(local.common_tags, {
    Name    = "${local.name_prefix}-validator-audit"
    Purpose = "hoodi-validator-lifecycle-canonical-audit"
  })
}

resource "aws_s3_bucket_public_access_block" "validator_audit" {
  bucket                  = aws_s3_bucket.validator_audit.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "validator_audit" {
  bucket = aws_s3_bucket.validator_audit.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_versioning" "validator_audit" {
  bucket = aws_s3_bucket.validator_audit.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_object_lock_configuration" "validator_audit" {
  bucket              = aws_s3_bucket.validator_audit.id
  object_lock_enabled = "Enabled"
  token               = null
  rule {
    default_retention {
      mode  = "GOVERNANCE"
      years = 2
    }
  }
  depends_on = [aws_s3_bucket_versioning.validator_audit]
}

data "aws_iam_policy_document" "validator_audit_key" {
  source_policy_documents = [data.aws_iam_policy_document.kms_key_administrator.json]

  statement {
    sid    = "AllowValidatorAuditWriterViaS3"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = [aws_iam_role.validator_log_collector.arn]
    }
    actions   = ["kms:Encrypt", "kms:GenerateDataKey", "kms:DescribeKey"]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["s3.${var.aws_region}.amazonaws.com"]
    }
  }

  statement {
    sid    = "AllowCloudWatchLogsToEncryptValidatorLogGroups"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["logs.${var.aws_region}.amazonaws.com"]
    }
    actions   = ["kms:Encrypt", "kms:Decrypt", "kms:ReEncrypt*", "kms:GenerateDataKey*", "kms:DescribeKey"]
    resources = ["*"]
    condition {
      test     = "ArnLike"
      variable = "kms:EncryptionContext:aws:logs:arn"
      values   = ["arn:aws:logs:${var.aws_region}:${var.aws_account_id}:log-group:/aws/eks/${var.name}/validator-*"]
    }
  }

  statement {
    sid    = "AllowValidatorAuditReaderViaS3"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = [aws_iam_role.validator_audit_reader.arn]
    }
    actions   = ["kms:Decrypt", "kms:DescribeKey"]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["s3.${var.aws_region}.amazonaws.com"]
    }
  }

  statement {
    sid    = "AllowFirehoseArchiveWriteViaS3"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = [aws_iam_role.validator_audit_firehose.arn]
    }
    actions   = ["kms:Encrypt", "kms:GenerateDataKey", "kms:DescribeKey"]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["s3.${var.aws_region}.amazonaws.com"]
    }
  }
}

resource "aws_kms_key" "validator_audit" {
  description             = "Encryption key for immutable Hoodi validator lifecycle audit records"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  policy                  = data.aws_iam_policy_document.validator_audit_key.json
  tags                    = local.common_tags
}

resource "aws_kms_alias" "validator_audit" {
  name          = "alias/${local.name_prefix}-validator-audit"
  target_key_id = aws_kms_key.validator_audit.key_id
}

resource "aws_s3_bucket_server_side_encryption_configuration" "validator_audit" {
  bucket = aws_s3_bucket.validator_audit.id
  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.validator_audit.arn
      sse_algorithm     = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "validator_audit" {
  bucket = aws_s3_bucket.validator_audit.id
  rule {
    id     = "tier-immutable-validator-audit"
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
  }
}

data "aws_iam_policy_document" "validator_audit_bucket" {
  statement {
    sid    = "DenyInsecureTransport"
    effect = "Deny"
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.validator_audit.arn, "${aws_s3_bucket.validator_audit.arn}/*"]
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
  statement {
    sid    = "DenyUnencryptedObjectWrites"
    effect = "Deny"
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.validator_audit.arn}/*"]
    condition {
      test     = "StringNotEquals"
      variable = "s3:x-amz-server-side-encryption"
      values   = ["aws:kms"]
    }
  }
}

resource "aws_s3_bucket_policy" "validator_audit" {
  bucket     = aws_s3_bucket.validator_audit.id
  policy     = data.aws_iam_policy_document.validator_audit_bucket.json
  depends_on = [aws_s3_bucket_public_access_block.validator_audit]
}

# Only the collector has write access. The reader role is deliberately separate
# so an ingestion compromise cannot retrieve archive contents.
# EKS Pod Identity request tags bind the cluster, namespace and service account:
# https://docs.aws.amazon.com/eks/latest/userguide/pod-id-role.html
# The created cluster also uses var.name; no arbitrary external cluster is adopted.
data "aws_iam_policy_document" "validator_collector_assume_role" {
  statement {
    actions = ["sts:AssumeRole", "sts:TagSession"]
    principals {
      type        = "Service"
      identifiers = ["pods.eks.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:RequestTag/eks-cluster-arn"
      values   = ["arn:aws:eks:${var.aws_region}:${var.aws_account_id}:cluster/${var.name}"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:RequestTag/kubernetes-namespace"
      values   = ["validator-observability"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:RequestTag/kubernetes-service-account"
      values   = ["validator-log-collector"]
    }
  }
}

resource "aws_iam_role" "validator_log_collector" {
  name               = "${local.name_prefix}-validator-log-collector"
  assume_role_policy = data.aws_iam_policy_document.validator_collector_assume_role.json
  tags               = local.common_tags
}

data "aws_iam_policy_document" "validator_audit_reader_assume_role" {
  statement {
    actions = ["sts:AssumeRole", "sts:TagSession"]
    principals {
      type        = "Service"
      identifiers = ["pods.eks.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:RequestTag/eks-cluster-arn"
      values   = ["arn:aws:eks:${var.aws_region}:${var.aws_account_id}:cluster/${var.name}"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:RequestTag/kubernetes-namespace"
      values   = ["validator-observability"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:RequestTag/kubernetes-service-account"
      values   = ["validator-audit-reader"]
    }
  }
}

resource "aws_iam_role" "validator_audit_reader" {
  name               = "${local.name_prefix}-validator-audit-reader"
  assume_role_policy = data.aws_iam_policy_document.validator_audit_reader_assume_role.json
  tags               = local.common_tags
}

resource "aws_cloudwatch_log_group" "validator_workloads" {
  name              = "/aws/eks/${var.name}/validator-workloads"
  retention_in_days = 365
  kms_key_id        = aws_kms_key.validator_audit.arn
  tags              = local.common_tags
}

resource "aws_cloudwatch_log_group" "validator_security" {
  name              = "/aws/eks/${var.name}/validator-security"
  retention_in_days = 365
  kms_key_id        = aws_kms_key.validator_audit.arn
  tags              = local.common_tags
}

data "aws_iam_policy_document" "validator_log_collector" {
  statement {
    sid     = "WriteOnlyValidatorCloudWatchLogs"
    actions = ["logs:CreateLogStream", "logs:DescribeLogStreams", "logs:PutLogEvents"]
    # The collector relays the approved chain observer's stdout EMF as well as
    # workload/audit logs. DescribeLogStreams reads stream metadata, not events.
    # It cannot read stored events, create groups or change retention.
    resources = ["${aws_cloudwatch_log_group.validator_workloads.arn}:*", "${aws_cloudwatch_log_group.validator_security.arn}:*", "${aws_cloudwatch_log_group.validator_metrics.arn}:*"]
  }
}

resource "aws_iam_role_policy" "validator_log_collector" {
  name   = "${local.name_prefix}-validator-log-collector"
  role   = aws_iam_role.validator_log_collector.id
  policy = data.aws_iam_policy_document.validator_log_collector.json
}

data "aws_iam_policy_document" "validator_audit_reader" {
  statement {
    sid       = "ReadOnlyCanonicalValidatorAudit"
    actions   = ["s3:GetObject", "s3:GetObjectVersion", "s3:GetObjectRetention"]
    resources = ["${aws_s3_bucket.validator_audit.arn}/validator/*"]
  }
  statement {
    sid       = "ListOnlyCanonicalValidatorAudit"
    actions   = ["s3:ListBucket"]
    resources = [aws_s3_bucket.validator_audit.arn]
    condition {
      test     = "StringLike"
      variable = "s3:prefix"
      values   = ["validator/*"]
    }
  }
}

resource "aws_iam_role_policy" "validator_audit_reader" {
  name   = "${local.name_prefix}-validator-audit-reader"
  role   = aws_iam_role.validator_audit_reader.id
  policy = data.aws_iam_policy_document.validator_audit_reader.json
}

data "aws_iam_policy_document" "validator_firehose_assume_role" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["firehose.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "validator_audit_firehose" {
  name               = "${local.name_prefix}-validator-audit-firehose"
  assume_role_policy = data.aws_iam_policy_document.validator_firehose_assume_role.json
  tags               = local.common_tags
}

data "aws_iam_policy_document" "validator_audit_firehose" {
  statement {
    sid = "WriteOnlyCanonicalValidatorAudit"
    actions = [
      "s3:AbortMultipartUpload", "s3:GetBucketLocation", "s3:ListBucket",
      "s3:ListBucketMultipartUploads", "s3:PutObject", "s3:PutObjectRetention"
    ]
    resources = [aws_s3_bucket.validator_audit.arn, "${aws_s3_bucket.validator_audit.arn}/validator/*"]
  }
  statement {
    sid       = "EncryptOnlyCanonicalValidatorAudit"
    actions   = ["kms:Encrypt", "kms:GenerateDataKey", "kms:DescribeKey"]
    resources = [aws_kms_key.validator_audit.arn]
  }
}

resource "aws_iam_role_policy" "validator_audit_firehose" {
  name   = "${local.name_prefix}-validator-audit-firehose"
  role   = aws_iam_role.validator_audit_firehose.id
  policy = data.aws_iam_policy_document.validator_audit_firehose.json
}

resource "aws_kinesis_firehose_delivery_stream" "validator_audit" {
  name        = "${local.name_prefix}-validator-audit"
  destination = "extended_s3"

  # Firehose buffering encryption is separate from destination S3 encryption.
  server_side_encryption {
    enabled  = true
    key_type = "CUSTOMER_MANAGED_CMK"
    key_arn  = aws_kms_key.validator_firehose_buffer.arn
  }

  extended_s3_configuration {
    role_arn   = aws_iam_role.validator_audit_firehose.arn
    bucket_arn = aws_s3_bucket.validator_audit.arn
    prefix     = "validator/year=!{timestamp:yyyy}/month=!{timestamp:MM}/day=!{timestamp:dd}/"
    # Firehose requires its error-output type token in every error prefix. It
    # keeps delivery failures separately attributable without weakening the
    # canonical validator record prefix.
    error_output_prefix = "validator-errors/type=!{firehose:error-output-type}/year=!{timestamp:yyyy}/month=!{timestamp:MM}/day=!{timestamp:dd}/"
    buffering_size      = 5
    buffering_interval  = 300
    compression_format  = "GZIP"
    kms_key_arn         = aws_kms_key.validator_audit.arn
  }

  depends_on = [
    aws_iam_role_policy.validator_audit_firehose,
    aws_iam_role_policy.validator_firehose_buffer,
  ]
}

data "aws_iam_policy_document" "validator_cloudwatch_subscription_assume_role" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["logs.${var.aws_region}.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "validator_cloudwatch_subscription" {
  name               = "${local.name_prefix}-validator-cloudwatch-subscription"
  assume_role_policy = data.aws_iam_policy_document.validator_cloudwatch_subscription_assume_role.json
  tags               = local.common_tags
}

data "aws_iam_policy_document" "validator_cloudwatch_subscription" {
  statement {
    actions   = ["firehose:PutRecord", "firehose:PutRecordBatch"]
    resources = [aws_kinesis_firehose_delivery_stream.validator_audit.arn]
  }
}

resource "aws_iam_role_policy" "validator_cloudwatch_subscription" {
  name   = "${local.name_prefix}-validator-cloudwatch-subscription"
  role   = aws_iam_role.validator_cloudwatch_subscription.id
  policy = data.aws_iam_policy_document.validator_cloudwatch_subscription.json
}

resource "aws_cloudwatch_log_subscription_filter" "validator_workloads_archive" {
  name            = "validator-workloads-immutable-archive"
  log_group_name  = aws_cloudwatch_log_group.validator_workloads.name
  filter_pattern  = ""
  destination_arn = aws_kinesis_firehose_delivery_stream.validator_audit.arn
  role_arn        = aws_iam_role.validator_cloudwatch_subscription.arn
  distribution    = "ByLogStream"
}

resource "aws_cloudwatch_log_subscription_filter" "validator_security_archive" {
  name            = "validator-security-immutable-archive"
  log_group_name  = aws_cloudwatch_log_group.validator_security.name
  filter_pattern  = ""
  destination_arn = aws_kinesis_firehose_delivery_stream.validator_audit.arn
  role_arn        = aws_iam_role.validator_cloudwatch_subscription.arn
  distribution    = "ByLogStream"
}

resource "aws_eks_pod_identity_association" "validator_log_collector" {
  # Fresh deployments must create EKS before associating its workload role.
  cluster_name    = aws_eks_cluster.private.name
  namespace       = "validator-observability"
  service_account = "validator-log-collector"
  role_arn        = aws_iam_role.validator_log_collector.arn
}

resource "aws_eks_pod_identity_association" "validator_audit_reader" {
  cluster_name    = aws_eks_cluster.private.name
  namespace       = "validator-observability"
  service_account = "validator-audit-reader"
  role_arn        = aws_iam_role.validator_audit_reader.arn
}
