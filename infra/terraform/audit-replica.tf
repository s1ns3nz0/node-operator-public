# The audit replica is intentionally in Tokyo, not in the primary Seoul Region.
# It is a recovery copy only: lifecycle rules retain delete markers and the
# replication role cannot delete either source or destination records.
resource "aws_s3_bucket" "audit_replica" {
  provider      = aws.audit_replica
  bucket_prefix = "${substr(local.name_prefix, 0, 20)}-audit-dr-"
  force_destroy = false

  tags = merge(local.common_tags, {
    Name    = "${local.name_prefix}-audit-dr"
    Purpose = "audit-disaster-recovery"
  })
}

resource "aws_s3_bucket_public_access_block" "audit_replica" {
  provider                = aws.audit_replica
  bucket                  = aws_s3_bucket.audit_replica.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "audit_replica" {
  provider = aws.audit_replica
  bucket   = aws_s3_bucket.audit_replica.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_versioning" "audit_replica" {
  provider = aws.audit_replica
  bucket   = aws_s3_bucket.audit_replica.id

  versioning_configuration {
    status = "Enabled"
  }
}

data "aws_iam_policy_document" "audit_replica_key" {
  # KMS validates key creation against the caller's future ability to recover
  # the key policy.  This standard root delegation enables same-account IAM
  # authorization; it is not direct workload cryptographic access.
  statement {
    sid    = "EnableAccountIAMPolicyDelegation"
    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${var.aws_account_id}:root"]
    }

    actions   = ["kms:*"]
    resources = ["*"]
  }

  statement {
    sid    = "AllowDedicatedKMSAdministrator"
    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = [aws_iam_role.kms_administrator.arn]
    }

    actions   = ["kms:*"]
    resources = ["*"]
  }

  # Keep the replica key independently manageable only by an explicitly
  # selected role; an omitted role produces no synthetic policy principal.
  dynamic "statement" {
    for_each = var.terraform_apply_role_arn == null || var.terraform_apply_role_arn == "" ? [] : [var.terraform_apply_role_arn]
    content {
      sid    = "AllowSelectedTerraformApplyKeyLifecycleManagement"
      effect = "Allow"

      principals {
        type        = "AWS"
        identifiers = [statement.value]
      }

      actions = [
        "kms:CancelKeyDeletion",
        "kms:CreateAlias",
        "kms:DeleteAlias",
        "kms:DescribeKey",
        "kms:EnableKeyRotation",
        "kms:GetKeyPolicy",
        "kms:GetKeyRotationStatus",
        "kms:ListAliases",
        "kms:ListResourceTags",
        "kms:PutKeyPolicy",
        "kms:ScheduleKeyDeletion",
        "kms:TagResource",
      ]
      resources = ["*"]
    }
  }

  statement {
    sid    = "AllowAuditReplicationRoleToEncryptReplicaObjects"
    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = [aws_iam_role.audit_replication.arn]
    }

    actions   = ["kms:Encrypt", "kms:GenerateDataKey", "kms:DescribeKey"]
    resources = ["*"]

    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["s3.${var.audit_replica_region}.amazonaws.com"]
    }
  }
}

resource "aws_kms_key" "audit_replica" {
  provider                = aws.audit_replica
  description             = "Tokyo disaster-recovery encryption key for replicated audit logs"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  policy                  = data.aws_iam_policy_document.audit_replica_key.json

  lifecycle {
    precondition {
      condition     = var.terraform_apply_role_arn == null || var.terraform_apply_role_arn == "" || can(regex("^arn:aws:iam::${var.aws_account_id}:role/[A-Za-z0-9+=,.@_/-]{1,64}$", var.terraform_apply_role_arn))
      error_message = "terraform_apply_role_arn must be empty or an IAM role in aws_account_id."
    }
  }

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-audit-dr"
  })
}

resource "aws_kms_alias" "audit_replica" {
  provider      = aws.audit_replica
  name          = "alias/${local.name_prefix}-audit-dr"
  target_key_id = aws_kms_key.audit_replica.key_id
}

resource "aws_s3_bucket_server_side_encryption_configuration" "audit_replica" {
  provider = aws.audit_replica
  bucket   = aws_s3_bucket.audit_replica.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.audit_replica.arn
      sse_algorithm     = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "audit_replica" {
  provider = aws.audit_replica
  bucket   = aws_s3_bucket.audit_replica.id

  rule {
    id     = "retain-replicated-audit-records"
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

# This Tokyo bucket is deliberately not access-logged itself: it is the
# non-recursive destination for the Tokyo replica bucket's S3 access logs.
# S3 server access log delivery supports SSE-S3 but not default SSE-KMS.
resource "aws_s3_bucket" "audit_replica_access_logs" {
  #checkov:skip=CKV_AWS_144:Replicating this DR delivery target would create a second unbounded audit-log stream; the audited source is replicated instead.
  #checkov:skip=CKV_AWS_145:S3 server access log delivery does not support a default SSE-KMS destination key.
  provider      = aws.audit_replica
  bucket_prefix = "${substr(local.name_prefix, 0, 20)}-al-dr-"
  force_destroy = false

  tags = merge(local.common_tags, {
    Name    = "${local.name_prefix}-audit-dr-access-logs"
    Purpose = "audit-replica-bucket-server-access-logs"
  })
}

resource "aws_s3_bucket_public_access_block" "audit_replica_access_logs" {
  provider                = aws.audit_replica
  bucket                  = aws_s3_bucket.audit_replica_access_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "audit_replica_access_logs" {
  provider = aws.audit_replica
  bucket   = aws_s3_bucket.audit_replica_access_logs.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_versioning" "audit_replica_access_logs" {
  provider = aws.audit_replica
  bucket   = aws_s3_bucket.audit_replica_access_logs.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "audit_replica_access_logs" {
  provider = aws.audit_replica
  bucket   = aws_s3_bucket.audit_replica_access_logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "audit_replica_access_logs" {
  provider = aws.audit_replica
  bucket   = aws_s3_bucket.audit_replica_access_logs.id

  rule {
    id     = "retain-audit-replica-access-logs"
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

data "aws_iam_policy_document" "audit_replica_access_logs" {
  statement {
    sid    = "DenyInsecureTransport"
    effect = "Deny"

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    actions   = ["s3:*"]
    resources = [aws_s3_bucket.audit_replica_access_logs.arn, "${aws_s3_bucket.audit_replica_access_logs.arn}/*"]

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }

  statement {
    sid    = "AllowOnlyAuditReplicaServerAccessLogDelivery"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["logging.s3.amazonaws.com"]
    }

    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.audit_replica_access_logs.arn}/audit-replica/*"]

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [var.aws_account_id]
    }

    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = [aws_s3_bucket.audit_replica.arn]
    }
  }
}

resource "aws_s3_bucket_policy" "audit_replica_access_logs" {
  provider = aws.audit_replica
  bucket   = aws_s3_bucket.audit_replica_access_logs.id
  policy   = data.aws_iam_policy_document.audit_replica_access_logs.json

  depends_on = [aws_s3_bucket_public_access_block.audit_replica_access_logs]
}

resource "aws_s3_bucket_logging" "audit_replica" {
  provider      = aws.audit_replica
  bucket        = aws_s3_bucket.audit_replica.id
  target_bucket = aws_s3_bucket.audit_replica_access_logs.id
  target_prefix = "audit-replica/"

  depends_on = [aws_s3_bucket_policy.audit_replica_access_logs]
}

resource "aws_s3_bucket_notification" "audit_replica" {
  provider = aws.audit_replica
  bucket   = aws_s3_bucket.audit_replica.id

  eventbridge = true
}

resource "aws_s3_bucket_notification" "audit_replica_access_logs" {
  provider = aws.audit_replica
  bucket   = aws_s3_bucket.audit_replica_access_logs.id

  eventbridge = true
}

data "aws_iam_policy_document" "audit_replication_assume_role" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["s3.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "audit_replication" {
  name               = "${local.name_prefix}-audit-replication"
  assume_role_policy = data.aws_iam_policy_document.audit_replication_assume_role.json

  tags = local.common_tags
}

data "aws_iam_policy_document" "audit_replication" {
  statement {
    sid       = "ReadOnlyAuditSourceVersions"
    actions   = ["s3:GetReplicationConfiguration", "s3:ListBucket", "s3:GetObjectVersionForReplication", "s3:GetObjectVersionAcl", "s3:GetObjectVersionTagging"]
    resources = [aws_s3_bucket.audit.arn, "${aws_s3_bucket.audit.arn}/*"]
  }

  statement {
    sid       = "WriteOnlyAuditReplicaVersions"
    actions   = ["s3:ReplicateObject", "s3:ReplicateDelete", "s3:ReplicateTags", "s3:ObjectOwnerOverrideToBucketOwner"]
    resources = ["${aws_s3_bucket.audit_replica.arn}/*"]
  }

  statement {
    sid       = "UseOnlyApprovedAuditKeysForReplication"
    actions   = ["kms:Decrypt", "kms:DescribeKey"]
    resources = [aws_kms_key.audit.arn]
  }

  statement {
    sid       = "EncryptOnlyWithAuditReplicaKey"
    actions   = ["kms:Encrypt", "kms:GenerateDataKey", "kms:DescribeKey"]
    resources = [aws_kms_key.audit_replica.arn]
  }
}

resource "aws_iam_role_policy" "audit_replication" {
  name   = "${local.name_prefix}-audit-replication"
  role   = aws_iam_role.audit_replication.id
  policy = data.aws_iam_policy_document.audit_replication.json
}

resource "aws_s3_bucket_replication_configuration" "audit" {
  bucket = aws_s3_bucket.audit.id
  role   = aws_iam_role.audit_replication.arn

  rule {
    id     = "replicate-audit-records-to-tokyo"
    status = "Enabled"

    filter {}

    delete_marker_replication {
      status = "Disabled"
    }

    destination {
      bucket        = aws_s3_bucket.audit_replica.arn
      storage_class = "STANDARD"

      encryption_configuration {
        replica_kms_key_id = aws_kms_key.audit_replica.arn
      }
    }

    source_selection_criteria {
      sse_kms_encrypted_objects {
        status = "Enabled"
      }
    }
  }

  depends_on = [
    aws_s3_bucket_versioning.audit,
    aws_s3_bucket_versioning.audit_replica,
    aws_iam_role_policy.audit_replication,
  ]
}
