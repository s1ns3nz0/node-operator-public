# Raft snapshots contain encrypted Vault state and must never share the
# validator evidence archive.  Object Lock is enabled only at bucket creation.
resource "aws_s3_bucket" "vault_snapshot" {
  bucket_prefix       = "${substr(local.name_prefix, 0, 20)}-vs-"
  force_destroy       = false
  object_lock_enabled = true

  tags = merge(local.common_tags, {
    Name    = "${local.name_prefix}-vault-snapshot"
    Purpose = "private-vault-raft-migration-backup"
  })
}

# Preserve every completed snapshot and its Object Lock retention. Only
# abandoned multipart uploads are cleaned up.
resource "aws_s3_bucket_lifecycle_configuration" "vault_snapshot" {
  bucket = aws_s3_bucket.vault_snapshot.id
  rule {
    id     = "abort-incomplete-uploads"
    status = "Enabled"
    filter {}
    abort_incomplete_multipart_upload { days_after_initiation = 7 }
  }
}

resource "aws_s3_bucket_notification" "vault_snapshot" {
  bucket      = aws_s3_bucket.vault_snapshot.id
  eventbridge = true
}

resource "aws_s3_bucket_public_access_block" "vault_snapshot" {
  bucket                  = aws_s3_bucket.vault_snapshot.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "vault_snapshot" {
  bucket = aws_s3_bucket.vault_snapshot.id
  rule { object_ownership = "BucketOwnerEnforced" }
}

resource "aws_s3_bucket_versioning" "vault_snapshot" {
  bucket = aws_s3_bucket.vault_snapshot.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_object_lock_configuration" "vault_snapshot" {
  bucket              = aws_s3_bucket.vault_snapshot.id
  object_lock_enabled = "Enabled"
  token               = null
  rule {
    default_retention {
      mode = "GOVERNANCE"
      days = 90
    }
  }
  depends_on = [aws_s3_bucket_versioning.vault_snapshot]
}

data "aws_iam_policy_document" "vault_snapshot_key" {
  source_policy_documents = [data.aws_iam_policy_document.kms_key_administrator.json]
}

resource "aws_kms_key" "vault_snapshot" {
  description             = "Encryption key for private Vault Raft migration snapshots"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  policy                  = data.aws_iam_policy_document.vault_snapshot_key.json
  tags                    = local.common_tags
}

resource "aws_kms_alias" "vault_snapshot" {
  name          = "alias/${local.name_prefix}-vault-snapshot"
  target_key_id = aws_kms_key.vault_snapshot.key_id
}

resource "aws_s3_bucket_server_side_encryption_configuration" "vault_snapshot" {
  bucket = aws_s3_bucket.vault_snapshot.id
  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.vault_snapshot.arn
      sse_algorithm     = "aws:kms"
    }
  }
}

data "aws_iam_policy_document" "vault_snapshot_bucket" {
  statement {
    sid    = "DenyInsecureTransport"
    effect = "Deny"
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.vault_snapshot.arn, "${aws_s3_bucket.vault_snapshot.arn}/*"]
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
    resources = ["${aws_s3_bucket.vault_snapshot.arn}/*"]
    condition {
      test     = "StringNotEquals"
      variable = "s3:x-amz-server-side-encryption"
      values   = ["aws:kms"]
    }
  }
}

resource "aws_s3_bucket_policy" "vault_snapshot" {
  bucket     = aws_s3_bucket.vault_snapshot.id
  policy     = data.aws_iam_policy_document.vault_snapshot_bucket.json
  depends_on = [aws_s3_bucket_public_access_block.vault_snapshot]
}
