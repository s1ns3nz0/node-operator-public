data "aws_caller_identity" "current" {}

locals {
  staging_bucket_name     = "${var.deployment_name}-oci-staging"
  access_logs_bucket_name = "${var.deployment_name}-oci-access-logs"
  staging_object_arn      = "arn:aws:s3:::${local.staging_bucket_name}/${var.object_prefix}*"
  tags = {
    ManagedBy  = "terraform"
    Project    = "node-operator"
    Purpose    = "ephemeral-release"
    Deployment = var.deployment_name
  }
}

# The provider allow-list is the first account fence. This separate assertion
# makes the actual caller check visible in the plan before either bucket exists.
resource "terraform_data" "account_guard" {
  input = var.aws_account_id

  lifecycle {
    precondition {
      condition     = data.aws_caller_identity.current.account_id == var.aws_account_id
      error_message = "AWS caller account does not match aws_account_id; refuse to create release staging resources."
    }

    precondition {
      condition     = split(":", var.github_oidc_provider_arn)[4] == var.aws_account_id
      error_message = "github_oidc_provider_arn must belong to aws_account_id."
    }

    precondition {
      condition     = split(":", var.allowed_uploader_principal_arn)[4] == var.aws_account_id
      error_message = "allowed_uploader_principal_arn must belong to aws_account_id."
    }
  }
}

resource "aws_s3_bucket" "access_logs" {
  bucket        = local.access_logs_bucket_name
  force_destroy = false
  depends_on    = [terraform_data.account_guard]
}

resource "aws_s3_bucket_ownership_controls" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_public_access_block" "access_logs" {
  bucket                  = aws_s3_bucket.access_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

data "aws_iam_policy_document" "access_logs" {
  statement {
    sid     = "AllowS3ServerAccessLogDelivery"
    effect  = "Allow"
    actions = ["s3:PutObject"]
    resources = [
      "${aws_s3_bucket.access_logs.arn}/oci-staging/",
      "${aws_s3_bucket.access_logs.arn}/oci-staging/*",
    ]

    principals {
      type        = "Service"
      identifiers = ["logging.s3.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [var.aws_account_id]
    }

    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = [aws_s3_bucket.staging.arn]
    }
  }

  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.access_logs.arn, "${aws_s3_bucket.access_logs.arn}/*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "access_logs" {
  bucket     = aws_s3_bucket.access_logs.id
  policy     = data.aws_iam_policy_document.access_logs.json
  depends_on = [aws_s3_bucket_public_access_block.access_logs]
}

resource "aws_s3_bucket" "staging" {
  bucket        = local.staging_bucket_name
  force_destroy = false
  depends_on    = [terraform_data.account_guard]
}

resource "aws_s3_bucket_ownership_controls" "staging" {
  bucket = aws_s3_bucket.staging.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_public_access_block" "staging" {
  bucket                  = aws_s3_bucket.staging.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "staging" {
  bucket = aws_s3_bucket.staging.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "staging" {
  bucket = aws_s3_bucket.staging.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

data "aws_iam_policy_document" "staging" {
  statement {
    sid       = "DenyPutObjectExceptApprovedUploader"
    effect    = "Deny"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.staging.arn}/*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "ArnNotEquals"
      variable = "aws:PrincipalArn"
      values   = [var.allowed_uploader_principal_arn]
    }
  }

  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.staging.arn, "${aws_s3_bucket.staging.arn}/*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "staging" {
  bucket     = aws_s3_bucket.staging.id
  policy     = data.aws_iam_policy_document.staging.json
  depends_on = [aws_s3_bucket_public_access_block.staging]
}

resource "aws_s3_bucket_logging" "staging" {
  bucket        = aws_s3_bucket.staging.id
  target_bucket = aws_s3_bucket.access_logs.id
  target_prefix = "oci-staging/"
  depends_on    = [aws_s3_bucket_policy.access_logs]
}

data "aws_iam_policy_document" "evidence_reader_assume_role" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [var.github_oidc_provider_arn]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:sub"
      values = [
        "repo:${var.github_repository}:environment:gitops-evidence-reader",
        "repo:${var.github_repository}:environment:release",
      ]
    }
  }
}

resource "aws_iam_role" "evidence_reader" {
  name               = "${var.deployment_name}-evidence-reader"
  assume_role_policy = data.aws_iam_policy_document.evidence_reader_assume_role.json
  depends_on         = [terraform_data.account_guard]
}

data "aws_iam_policy_document" "evidence_reader" {
  statement {
    sid       = "ReadOnlyExactVersionedOciPrefix"
    effect    = "Allow"
    actions   = ["s3:GetObjectVersion"]
    resources = [local.staging_object_arn]
  }
}

resource "aws_iam_role_policy" "evidence_reader" {
  name   = "read-exact-versioned-oci-prefix"
  role   = aws_iam_role.evidence_reader.id
  policy = data.aws_iam_policy_document.evidence_reader.json
}
