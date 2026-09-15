variable "enable_ci_evidence_archive" {
  description = "Create the dedicated immutable S3 archive and GitHub OIDC publisher for redacted CI evidence."
  type        = bool
  default     = true
}

variable "ci_evidence_archive_retention_days" {
  description = "Compliance Object Lock retention for signed CI evidence."
  type        = number
  default     = 365

  validation {
    condition     = var.ci_evidence_archive_retention_days >= 90 && var.ci_evidence_archive_retention_days <= 3650
    error_message = "ci_evidence_archive_retention_days must be between 90 and 3650 days."
  }
}

resource "aws_kms_key" "ci_evidence_archive" {
  count                   = var.enable_ci_evidence_archive ? 1 : 0
  description             = "KMS key for long-term signed CI evidence archive"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  policy                  = data.aws_iam_policy_document.ci_evidence_archive_key[0].json
  tags = merge(local.common_tags, {
    Name    = "${local.name_prefix}-ci-evidence-archive"
    Purpose = "signed-ci-evidence-archive"
  })
}

resource "aws_kms_alias" "ci_evidence_archive" {
  count         = var.enable_ci_evidence_archive ? 1 : 0
  name          = "alias/${local.name_prefix}-ci-evidence-archive"
  target_key_id = aws_kms_key.ci_evidence_archive[0].key_id
}

resource "aws_s3_bucket" "ci_evidence_archive" {
  # Checkov graph checks below are satisfied by companion resources in this module.
  # The archive intentionally has no CRR target until a separately approved
  # cross-region KMS/object-lock replication design exists.
  #checkov:skip=CKV2_AWS_62:EventBridge notifications are enabled by aws_s3_bucket_notification.ci_evidence_archive.
  #checkov:skip=CKV_AWS_21:Versioning is enabled by aws_s3_bucket_versioning.ci_evidence_archive.
  #checkov:skip=CKV_AWS_145:KMS default encryption is enabled by aws_s3_bucket_server_side_encryption_configuration.ci_evidence_archive.
  #checkov:skip=CKV2_AWS_6:Public access is blocked by aws_s3_bucket_public_access_block.ci_evidence_archive.
  #checkov:skip=CKV_AWS_144:Cross-region object-lock replication requires a separately approved destination and KMS policy.
  #checkov:skip=CKV2_AWS_61:Lifecycle retention is configured by aws_s3_bucket_lifecycle_configuration.ci_evidence_archive.
  #checkov:skip=CKV_AWS_18:Access logging is configured by aws_s3_bucket_logging.ci_evidence_archive when the release log target exists.
  count               = var.enable_ci_evidence_archive ? 1 : 0
  bucket_prefix       = "${substr(local.name_prefix, 0, 20)}-ci-"
  force_destroy       = false
  object_lock_enabled = true
  tags = merge(local.common_tags, {
    Name    = "${local.name_prefix}-ci-evidence"
    Purpose = "signed-ci-evidence-archive"
  })
}

resource "aws_s3_bucket_versioning" "ci_evidence_archive" {
  count  = var.enable_ci_evidence_archive ? 1 : 0
  bucket = aws_s3_bucket.ci_evidence_archive[0].id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_object_lock_configuration" "ci_evidence_archive" {
  count  = var.enable_ci_evidence_archive ? 1 : 0
  bucket = aws_s3_bucket.ci_evidence_archive[0].id
  rule {
    default_retention {
      mode = "COMPLIANCE"
      days = var.ci_evidence_archive_retention_days
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "ci_evidence_archive" {
  count  = var.enable_ci_evidence_archive ? 1 : 0
  bucket = aws_s3_bucket.ci_evidence_archive[0].id

  rule {
    id     = "retain-ci-evidence-versions"
    status = "Enabled"
    filter {}

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }

    noncurrent_version_expiration {
      noncurrent_days = var.ci_evidence_archive_retention_days
    }
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "ci_evidence_archive" {
  count  = var.enable_ci_evidence_archive ? 1 : 0
  bucket = aws_s3_bucket.ci_evidence_archive[0].id
  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.ci_evidence_archive[0].arn
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "ci_evidence_archive" {
  count                   = var.enable_ci_evidence_archive ? 1 : 0
  bucket                  = aws_s3_bucket.ci_evidence_archive[0].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

data "aws_iam_policy_document" "ci_evidence_archive_key" {
  count                   = var.enable_ci_evidence_archive ? 1 : 0
  source_policy_documents = [data.aws_iam_policy_document.kms_key_administrator.json]

  statement {
    sid    = "AllowCiEvidenceArchiveRoleThroughS3"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = [aws_iam_role.github_ci_evidence_archive[0].arn]
    }
    actions   = ["kms:Decrypt", "kms:DescribeKey", "kms:Encrypt", "kms:GenerateDataKey*"]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["s3.${var.aws_region}.amazonaws.com"]
    }
    condition {
      test     = "StringLike"
      variable = "kms:EncryptionContext:aws:s3:arn"
      # Bucket Keys use the bucket ARN; older per-object encryption uses its key ARN.
      # Object access remains restricted to ci/* by the role's S3 permissions.
      values = [
        aws_s3_bucket.ci_evidence_archive[0].arn,
        "${aws_s3_bucket.ci_evidence_archive[0].arn}/ci/*",
      ]
    }
  }
}

data "aws_iam_policy_document" "github_ci_evidence_archive_assume_role" {
  #checkov:skip=CKV_AWS_358:Repository and environment subject claims are explicitly restricted; Checkov's claim-order heuristic is not applicable to this generated policy.
  count = var.enable_ci_evidence_archive ? 1 : 0
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = ["arn:aws:iam::${var.aws_account_id}:oidc-provider/token.actions.githubusercontent.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:repository"
      values   = [var.github_repository]
    }
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:sub"
      values   = ["${local.github_destination_oidc_subject_prefix}:environment:ci-evidence-archive"]
    }
  }
}

resource "aws_iam_role" "github_ci_evidence_archive" {
  count              = var.enable_ci_evidence_archive ? 1 : 0
  name               = "${local.name_prefix}-github-ci-evidence-archive"
  assume_role_policy = data.aws_iam_policy_document.github_ci_evidence_archive_assume_role[0].json
  tags               = local.common_tags
}

data "aws_iam_policy_document" "github_ci_evidence_archive" {
  count = var.enable_ci_evidence_archive ? 1 : 0
  statement {
    sid       = "WriteSignedEvidenceOnly"
    actions   = ["s3:AbortMultipartUpload", "s3:PutObject"]
    resources = ["${aws_s3_bucket.ci_evidence_archive[0].arn}/ci/*"]
  }
  statement {
    sid       = "ListEvidencePrefix"
    actions   = ["s3:ListBucket"]
    resources = [aws_s3_bucket.ci_evidence_archive[0].arn]
    condition {
      test     = "StringLike"
      variable = "s3:prefix"
      values   = ["ci/*"]
    }
  }
  statement {
    sid = "VerifyAfterWrite"
    # HeadObject is an API operation authorized by s3:GetObject, not an IAM action.
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.ci_evidence_archive[0].arn}/ci/*"]
  }
}

resource "aws_iam_role_policy" "github_ci_evidence_archive" {
  count  = var.enable_ci_evidence_archive ? 1 : 0
  name   = "${local.name_prefix}-github-ci-evidence-archive"
  role   = aws_iam_role.github_ci_evidence_archive[0].id
  policy = data.aws_iam_policy_document.github_ci_evidence_archive[0].json
}

data "aws_iam_policy_document" "ci_evidence_archive" {
  count = var.enable_ci_evidence_archive ? 1 : 0
  statement {
    sid    = "DenyInsecureTransport"
    effect = "Deny"
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.ci_evidence_archive[0].arn, "${aws_s3_bucket.ci_evidence_archive[0].arn}/*"]
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "ci_evidence_archive" {
  count  = var.enable_ci_evidence_archive ? 1 : 0
  bucket = aws_s3_bucket.ci_evidence_archive[0].id
  policy = data.aws_iam_policy_document.ci_evidence_archive[0].json
}

resource "aws_s3_bucket_notification" "ci_evidence_archive" {
  count       = var.enable_ci_evidence_archive ? 1 : 0
  bucket      = aws_s3_bucket.ci_evidence_archive[0].id
  eventbridge = true
}

resource "aws_s3_bucket_logging" "ci_evidence_archive" {
  count         = var.enable_ci_evidence_archive && var.enable_release_signer ? 1 : 0
  bucket        = aws_s3_bucket.ci_evidence_archive[0].id
  target_bucket = aws_s3_bucket.release_artifacts_access_logs[0].id
  target_prefix = "ci-evidence-archive/"
  depends_on    = [aws_s3_bucket_policy.release_artifacts_access_logs]
}

output "ci_evidence_archive_bucket_name" {
  description = "Immutable S3 bucket for redacted, Cosign-signed CI evidence."
  value       = try(aws_s3_bucket.ci_evidence_archive[0].id, null)
}

output "ci_evidence_archive_role_arn" {
  description = "GitHub OIDC role that can write only the signed CI evidence prefix."
  value       = try(aws_iam_role.github_ci_evidence_archive[0].arn, null)
}
