variable "vault_signer_endpoint" {
  description = "Private Vault Transit signer endpoint; never a public URL."
  type        = string
  default     = ""
  validation {
    condition     = var.vault_signer_endpoint == "" || can(regex("^https://[^/]+:8200$", var.vault_signer_endpoint))
    error_message = "vault_signer_endpoint must be an HTTPS endpoint explicitly using TCP port 8200 when configured."
  }
}

variable "vault_signer_auth_role" {
  description = "Vault AWS auth role used only by the private release signer."
  type        = string
  default     = "release-signer"
}

variable "enable_release_signer" {
  description = "Enable the private CodeBuild release signer only after plan review."
  type        = bool
  default     = false
}

variable "release_signer_subnet_ids" {
  description = "Explicit private subnet IDs for the release signer CodeBuild project. Required when the signer is enabled."
  type        = list(string)
  default     = []
}

variable "release_signer_image" {
  description = "Digest-pinned private ECR signer image. It is required only when enable_release_signer is true."
  type        = string
  default     = ""

  validation {
    condition     = var.release_signer_image == "" || can(regex("^[0-9]{12}\\.dkr\\.ecr\\.[a-z0-9-]+\\.amazonaws\\.com/[a-z0-9][a-z0-9._/-]*@sha256:[a-f0-9]{64}$", var.release_signer_image))
    error_message = "release_signer_image must be empty while disabled or a private ECR image pinned by a sha256 digest."
  }
}

data "aws_secretsmanager_secret" "vault_client_ca" {
  count = var.enable_release_signer ? 1 : 0
  name  = "${local.name_prefix}-vault-client-ca"
}

resource "aws_security_group" "release_signer" {
  count       = var.enable_release_signer ? 1 : 0
  name_prefix = "${local.name_prefix}-signer-"
  description = "Private release signer egress to approved VPC services only."
  vpc_id      = local.network_vpc_id
  egress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [local.network_vpc_cidr]
    description = "HTTPS to private AWS and service endpoints"
  }

  # Vault Transit uses HTTPS over TCP 8200. The listener is an internal NLB
  # addressed only through the private node-operator.internal hosted zone.
  egress {
    from_port   = 8200
    to_port     = 8200
    protocol    = "tcp"
    cidr_blocks = [local.network_vpc_cidr]
    description = "Vault Transit HTTPS to the private internal NLB"
  }
  tags = local.common_tags
}

variable "github_repository" {
  description = "Exact non-secret GitHub repository allowed to use destination publisher roles, owner/name."
  type        = string
  default     = ""

  validation {
    condition     = var.github_repository == "" || can(regex("^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$", var.github_repository))
    error_message = "github_repository must be blank or an exact owner/repository name."
  }
}

variable "github_owner_id" {
  description = "Exact non-secret numeric GitHub owner ID for github_repository."
  type        = string
  default     = ""
  validation {
    condition     = var.github_owner_id == "" || can(regex("^[0-9]+$", var.github_owner_id))
    error_message = "github_owner_id must be blank or a numeric GitHub owner ID."
  }
}

variable "github_repository_id" {
  description = "Exact non-secret numeric GitHub repository ID for github_repository."
  type        = string
  default     = ""
  validation {
    condition     = var.github_repository_id == "" || can(regex("^[0-9]+$", var.github_repository_id))
    error_message = "github_repository_id must be blank or a numeric GitHub repository ID."
  }
}

# Destination publisher trust is selected explicitly and never discovered at
# installer runtime. No public-repository identity is a deployment default.
locals {
  github_destination_oidc_subject_prefix    = "repo:${split("/", var.github_repository)[0]}@${var.github_owner_id}/${split("/", var.github_repository)[1]}@${var.github_repository_id}"
  github_destination_identity_is_explicit   = var.github_repository != "" && var.github_owner_id != "" && var.github_repository_id != ""
  release_signer_source_oidc_subject_prefix = local.github_destination_oidc_subject_prefix
}

resource "aws_vpc_security_group_egress_rule" "release_signer_s3_gateway_https" {
  count             = var.enable_release_signer ? 1 : 0
  description       = "HTTPS to the S3 gateway endpoint for immutable signer input and output"
  security_group_id = aws_security_group.release_signer[0].id
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  prefix_list_id    = data.aws_prefix_list.s3[0].id
}

variable "release_artifact_bucket_arn" {
  description = "Dedicated release artifact bucket ARN; empty keeps signer disabled."
  type        = string
  default     = ""
}

resource "aws_s3_bucket" "release_artifacts" {
  count               = var.enable_release_signer ? 1 : 0
  bucket_prefix       = "${substr(local.name_prefix, 0, 20)}-release-"
  force_destroy       = false
  object_lock_enabled = true
  tags                = local.common_tags
}

# Release artifacts and CodeBuild logs have separate keys so a signer role
# cannot use its artifact key to read or write operational log data. The
# dedicated KMS administrator role remains the break-glass administrator; the
# account root principal does not receive direct kms:* access.
data "aws_iam_policy_document" "release_artifacts_key" {
  count = var.enable_release_signer ? 1 : 0

  source_policy_documents = [data.aws_iam_policy_document.kms_key_administrator.json]

  statement {
    sid    = "AllowReleaseSignerToUseArtifactKeyOnlyThroughS3"
    effect = "Allow"

    principals {
      type = "AWS"
      identifiers = [
        aws_iam_role.release_codebuild_signer[0].arn,
        aws_iam_role.github_release_runner[0].arn,
      ]
    }

    actions = [
      "kms:Decrypt",
      "kms:DescribeKey",
      "kms:Encrypt",
      "kms:GenerateDataKey*",
    ]
    resources = ["*"]

    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["s3.${var.aws_region}.amazonaws.com"]
    }

    condition {
      test     = "StringLike"
      variable = "kms:EncryptionContext:aws:s3:arn"
      values   = ["${aws_s3_bucket.release_artifacts[0].arn}/*"]
    }
  }

  statement {
    sid    = "AllowArtifactReplicationRoleToDecryptOnlyThroughSourceS3"
    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = [aws_iam_role.release_artifact_replication[0].arn]
    }

    actions   = ["kms:Decrypt", "kms:DescribeKey"]
    resources = ["*"]

    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["s3.${var.aws_region}.amazonaws.com"]
    }
  }
}

resource "aws_kms_key" "release_artifacts" {
  count                   = var.enable_release_signer ? 1 : 0
  description             = "Release signer artifact encryption key"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  policy                  = data.aws_iam_policy_document.release_artifacts_key[0].json

  tags = merge(local.common_tags, {
    Name    = "${local.name_prefix}-release-artifacts"
    Purpose = "release-artifact-encryption"
  })
}

resource "aws_kms_alias" "release_artifacts" {
  count         = var.enable_release_signer ? 1 : 0
  name          = "alias/${local.name_prefix}-release-artifacts"
  target_key_id = aws_kms_key.release_artifacts[0].key_id
}

data "aws_iam_policy_document" "release_artifacts" {
  count = var.enable_release_signer ? 1 : 0

  statement {
    sid    = "DenyInsecureTransport"
    effect = "Deny"
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.release_artifacts[0].arn, "${aws_s3_bucket.release_artifacts[0].arn}/*"]
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "release_artifacts" {
  count  = var.enable_release_signer ? 1 : 0
  bucket = aws_s3_bucket.release_artifacts[0].id
  policy = data.aws_iam_policy_document.release_artifacts[0].json
}

resource "aws_s3_bucket_public_access_block" "release_artifacts" {
  count                   = var.enable_release_signer ? 1 : 0
  bucket                  = aws_s3_bucket.release_artifacts[0].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "release_artifacts" {
  count  = var.enable_release_signer ? 1 : 0
  bucket = aws_s3_bucket.release_artifacts[0].id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_lifecycle_configuration" "release_artifacts" {
  count  = var.enable_release_signer ? 1 : 0
  bucket = aws_s3_bucket.release_artifacts[0].id

  rule {
    id     = "retain-releases-and-expire-stale-versions"
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

# The logging destination must remain non-recursive. S3 server access log
# delivery supports SSE-S3 but does not support a default SSE-KMS key.
resource "aws_s3_bucket" "release_artifacts_access_logs" {
  #checkov:skip=CKV_AWS_145:S3 server access log delivery does not support a default SSE-KMS destination key.
  count         = var.enable_release_signer ? 1 : 0
  bucket_prefix = "${substr(local.name_prefix, 0, 20)}-rl-"
  force_destroy = false

  tags = merge(local.common_tags, {
    Name    = "${local.name_prefix}-release-access-logs"
    Purpose = "release-artifact-bucket-server-access-logs"
  })
}

resource "aws_s3_bucket_public_access_block" "release_artifacts_access_logs" {
  count                   = var.enable_release_signer ? 1 : 0
  bucket                  = aws_s3_bucket.release_artifacts_access_logs[0].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "release_artifacts_access_logs" {
  count  = var.enable_release_signer ? 1 : 0
  bucket = aws_s3_bucket.release_artifacts_access_logs[0].id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_versioning" "release_artifacts_access_logs" {
  count  = var.enable_release_signer ? 1 : 0
  bucket = aws_s3_bucket.release_artifacts_access_logs[0].id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "release_artifacts_access_logs" {
  count  = var.enable_release_signer ? 1 : 0
  bucket = aws_s3_bucket.release_artifacts_access_logs[0].id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "release_artifacts_access_logs" {
  count  = var.enable_release_signer ? 1 : 0
  bucket = aws_s3_bucket.release_artifacts_access_logs[0].id

  rule {
    id     = "retain-release-access-logs"
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

data "aws_iam_policy_document" "release_artifacts_access_logs" {
  count = var.enable_release_signer ? 1 : 0

  statement {
    sid    = "DenyInsecureTransport"
    effect = "Deny"

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    actions   = ["s3:*"]
    resources = [aws_s3_bucket.release_artifacts_access_logs[0].arn, "${aws_s3_bucket.release_artifacts_access_logs[0].arn}/*"]

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }

  statement {
    sid    = "AllowOnlyReleaseArtifactServerAccessLogDelivery"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["logging.s3.amazonaws.com"]
    }

    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.release_artifacts_access_logs[0].arn}/release-artifacts/*"]

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [var.aws_account_id]
    }

    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = [aws_s3_bucket.release_artifacts[0].arn]
    }
  }
}

resource "aws_s3_bucket_policy" "release_artifacts_access_logs" {
  count  = var.enable_release_signer ? 1 : 0
  bucket = aws_s3_bucket.release_artifacts_access_logs[0].id
  policy = data.aws_iam_policy_document.release_artifacts_access_logs[0].json

  depends_on = [aws_s3_bucket_public_access_block.release_artifacts_access_logs]
}

resource "aws_s3_bucket_logging" "release_artifacts" {
  count         = var.enable_release_signer ? 1 : 0
  bucket        = aws_s3_bucket.release_artifacts[0].id
  target_bucket = aws_s3_bucket.release_artifacts_access_logs[0].id
  target_prefix = "release-artifacts/"

  depends_on = [aws_s3_bucket_policy.release_artifacts_access_logs]
}

resource "aws_s3_bucket_notification" "release_artifacts_access_logs" {
  count  = var.enable_release_signer ? 1 : 0
  bucket = aws_s3_bucket.release_artifacts_access_logs[0].id

  eventbridge = true
}

# EventBridge is the approved in-account event integration point. Consumers
# (for example, a SIEM forwarding rule) are intentionally not created here;
# their destination and retention need an independent approval.
resource "aws_s3_bucket_notification" "release_artifacts" {
  count  = var.enable_release_signer ? 1 : 0
  bucket = aws_s3_bucket.release_artifacts[0].id

  eventbridge = true
}

resource "aws_s3_bucket_object_lock_configuration" "release_artifacts" {
  count  = var.enable_release_signer ? 1 : 0
  bucket = aws_s3_bucket.release_artifacts[0].id

  rule {
    default_retention {
      mode = "COMPLIANCE"
      days = 30
    }
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "release_artifacts" {
  count  = var.enable_release_signer ? 1 : 0
  bucket = aws_s3_bucket.release_artifacts[0].id
  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.release_artifacts[0].arn
      sse_algorithm     = "aws:kms"
    }
  }
}

data "aws_iam_policy_document" "release_signer_logs_key" {
  count = var.enable_release_signer ? 1 : 0

  source_policy_documents = [data.aws_iam_policy_document.kms_key_administrator.json]

  statement {
    sid    = "AllowCloudWatchLogsToUseReleaseSignerLogKey"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["logs.${var.aws_region}.amazonaws.com"]
    }

    actions   = ["kms:Decrypt*", "kms:Describe*", "kms:Encrypt*", "kms:GenerateDataKey*", "kms:ReEncrypt*"]
    resources = ["*"]

    condition {
      test     = "ArnLike"
      variable = "kms:EncryptionContext:aws:logs:arn"
      values   = ["arn:aws:logs:${var.aws_region}:${var.aws_account_id}:log-group:/aws/codebuild/${local.name_prefix}-release-signer"]
    }
  }
}

resource "aws_kms_key" "release_signer_logs" {
  count                   = var.enable_release_signer ? 1 : 0
  description             = "Release signer CodeBuild log encryption key"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  policy                  = data.aws_iam_policy_document.release_signer_logs_key[0].json

  tags = merge(local.common_tags, {
    Name    = "${local.name_prefix}-release-signer-logs"
    Purpose = "release-signer-log-encryption"
  })
}

resource "aws_kms_alias" "release_signer_logs" {
  count         = var.enable_release_signer ? 1 : 0
  name          = "alias/${local.name_prefix}-release-signer-logs"
  target_key_id = aws_kms_key.release_signer_logs[0].key_id
}

resource "aws_s3_bucket" "release_artifacts_replica" {
  count         = var.enable_release_signer ? 1 : 0
  provider      = aws.audit_replica
  bucket_prefix = "${substr(local.name_prefix, 0, 20)}-rel-dr-"
  force_destroy = false

  object_lock_enabled = true

  tags = merge(local.common_tags, {
    Name    = "${local.name_prefix}-release-dr"
    Purpose = "release-artifact-disaster-recovery"
  })
}

resource "aws_s3_bucket_public_access_block" "release_artifacts_replica" {
  count                   = var.enable_release_signer ? 1 : 0
  provider                = aws.audit_replica
  bucket                  = aws_s3_bucket.release_artifacts_replica[0].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "release_artifacts_replica" {
  count    = var.enable_release_signer ? 1 : 0
  provider = aws.audit_replica
  bucket   = aws_s3_bucket.release_artifacts_replica[0].id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_versioning" "release_artifacts_replica" {
  count    = var.enable_release_signer ? 1 : 0
  provider = aws.audit_replica
  bucket   = aws_s3_bucket.release_artifacts_replica[0].id

  versioning_configuration { status = "Enabled" }
}

data "aws_iam_policy_document" "release_artifacts_replica_key" {
  count = var.enable_release_signer ? 1 : 0

  source_policy_documents = [data.aws_iam_policy_document.kms_key_administrator.json]

  statement {
    sid    = "AllowArtifactReplicationRoleToEncryptOnlyThroughReplicaS3"
    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = [aws_iam_role.release_artifact_replication[0].arn]
    }

    actions   = ["kms:DescribeKey", "kms:Encrypt", "kms:GenerateDataKey"]
    resources = ["*"]

    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["s3.${var.audit_replica_region}.amazonaws.com"]
    }
  }
}

resource "aws_kms_key" "release_artifacts_replica" {
  count                   = var.enable_release_signer ? 1 : 0
  provider                = aws.audit_replica
  description             = "Tokyo disaster-recovery encryption key for release signer artifacts"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  policy                  = data.aws_iam_policy_document.release_artifacts_replica_key[0].json

  tags = merge(local.common_tags, {
    Name    = "${local.name_prefix}-release-dr"
    Purpose = "release-artifact-disaster-recovery-encryption"
  })
}

resource "aws_kms_alias" "release_artifacts_replica" {
  count         = var.enable_release_signer ? 1 : 0
  provider      = aws.audit_replica
  name          = "alias/${local.name_prefix}-release-artifacts-dr"
  target_key_id = aws_kms_key.release_artifacts_replica[0].key_id
}

resource "aws_s3_bucket_server_side_encryption_configuration" "release_artifacts_replica" {
  count    = var.enable_release_signer ? 1 : 0
  provider = aws.audit_replica
  bucket   = aws_s3_bucket.release_artifacts_replica[0].id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.release_artifacts_replica[0].arn
      sse_algorithm     = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "release_artifacts_replica" {
  count    = var.enable_release_signer ? 1 : 0
  provider = aws.audit_replica
  bucket   = aws_s3_bucket.release_artifacts_replica[0].id

  rule {
    id     = "retain-replicated-releases-and-expire-stale-versions"
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

# This Tokyo bucket is a non-recursive S3 server access-log destination, not a
# data bucket. It therefore uses the AWS-required SSE-S3 delivery mode.
resource "aws_s3_bucket" "release_artifacts_replica_access_logs" {
  #checkov:skip=CKV_AWS_144:Replicating this DR delivery target would create a second unbounded audit-log stream; the release artifacts are replicated instead.
  #checkov:skip=CKV_AWS_145:S3 server access log delivery does not support a default SSE-KMS destination key.
  count         = var.enable_release_signer ? 1 : 0
  provider      = aws.audit_replica
  bucket_prefix = "${substr(local.name_prefix, 0, 20)}-rl-dr-"
  force_destroy = false

  tags = merge(local.common_tags, {
    Name    = "${local.name_prefix}-release-dr-access-logs"
    Purpose = "release-artifact-replica-bucket-server-access-logs"
  })
}

resource "aws_s3_bucket_public_access_block" "release_artifacts_replica_access_logs" {
  count                   = var.enable_release_signer ? 1 : 0
  provider                = aws.audit_replica
  bucket                  = aws_s3_bucket.release_artifacts_replica_access_logs[0].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "release_artifacts_replica_access_logs" {
  count    = var.enable_release_signer ? 1 : 0
  provider = aws.audit_replica
  bucket   = aws_s3_bucket.release_artifacts_replica_access_logs[0].id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_versioning" "release_artifacts_replica_access_logs" {
  count    = var.enable_release_signer ? 1 : 0
  provider = aws.audit_replica
  bucket   = aws_s3_bucket.release_artifacts_replica_access_logs[0].id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "release_artifacts_replica_access_logs" {
  count    = var.enable_release_signer ? 1 : 0
  provider = aws.audit_replica
  bucket   = aws_s3_bucket.release_artifacts_replica_access_logs[0].id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "release_artifacts_replica_access_logs" {
  count    = var.enable_release_signer ? 1 : 0
  provider = aws.audit_replica
  bucket   = aws_s3_bucket.release_artifacts_replica_access_logs[0].id

  rule {
    id     = "retain-release-replica-access-logs"
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

data "aws_iam_policy_document" "release_artifacts_replica_access_logs" {
  count = var.enable_release_signer ? 1 : 0

  statement {
    sid    = "DenyInsecureTransport"
    effect = "Deny"

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    actions   = ["s3:*"]
    resources = [aws_s3_bucket.release_artifacts_replica_access_logs[0].arn, "${aws_s3_bucket.release_artifacts_replica_access_logs[0].arn}/*"]

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }

  statement {
    sid    = "AllowOnlyReleaseReplicaServerAccessLogDelivery"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["logging.s3.amazonaws.com"]
    }

    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.release_artifacts_replica_access_logs[0].arn}/release-artifacts-replica/*"]

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [var.aws_account_id]
    }

    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = [aws_s3_bucket.release_artifacts_replica[0].arn]
    }
  }
}

resource "aws_s3_bucket_policy" "release_artifacts_replica_access_logs" {
  count    = var.enable_release_signer ? 1 : 0
  provider = aws.audit_replica
  bucket   = aws_s3_bucket.release_artifacts_replica_access_logs[0].id
  policy   = data.aws_iam_policy_document.release_artifacts_replica_access_logs[0].json

  depends_on = [aws_s3_bucket_public_access_block.release_artifacts_replica_access_logs]
}

resource "aws_s3_bucket_logging" "release_artifacts_replica" {
  count         = var.enable_release_signer ? 1 : 0
  provider      = aws.audit_replica
  bucket        = aws_s3_bucket.release_artifacts_replica[0].id
  target_bucket = aws_s3_bucket.release_artifacts_replica_access_logs[0].id
  target_prefix = "release-artifacts-replica/"

  depends_on = [aws_s3_bucket_policy.release_artifacts_replica_access_logs]
}

resource "aws_s3_bucket_notification" "release_artifacts_replica_access_logs" {
  count    = var.enable_release_signer ? 1 : 0
  provider = aws.audit_replica
  bucket   = aws_s3_bucket.release_artifacts_replica_access_logs[0].id

  eventbridge = true
}

resource "aws_s3_bucket_notification" "release_artifacts_replica" {
  count    = var.enable_release_signer ? 1 : 0
  provider = aws.audit_replica
  bucket   = aws_s3_bucket.release_artifacts_replica[0].id

  eventbridge = true
}

resource "aws_s3_bucket_object_lock_configuration" "release_artifacts_replica" {
  count    = var.enable_release_signer ? 1 : 0
  provider = aws.audit_replica
  bucket   = aws_s3_bucket.release_artifacts_replica[0].id

  rule {
    default_retention {
      mode = "COMPLIANCE"
      days = 30
    }
  }
}

resource "aws_cloudwatch_log_group" "release_signer" {
  count             = var.enable_release_signer ? 1 : 0
  name              = "/aws/codebuild/${local.name_prefix}-release-signer"
  retention_in_days = 90
  kms_key_id        = aws_kms_key.release_signer_logs[0].arn
  tags              = local.common_tags
}

resource "aws_iam_role" "github_release_runner" {
  count = var.enable_release_signer ? 1 : 0
  name  = "${local.name_prefix}-github-release-runner"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Federated = "arn:aws:iam::${var.aws_account_id}:oidc-provider/token.actions.githubusercontent.com" }
      Action    = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = {
          "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
          "token.actions.githubusercontent.com:sub" = "${local.release_signer_source_oidc_subject_prefix}:environment:release"
        }
      }
    }]
  })
  tags = local.common_tags

  lifecycle {
    precondition {
      condition     = local.github_destination_identity_is_explicit
      error_message = "Release signer trust requires an exact operator repository and both exact numeric GitHub owner and repository IDs."
    }
  }
}

resource "aws_iam_role_policy" "github_release_runner" {
  count = var.enable_release_signer ? 1 : 0
  role  = aws_iam_role.github_release_runner[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["codebuild:StartBuild", "codebuild:BatchGetBuilds"]
        Resource = aws_codebuild_project.release_signer[0].arn
      },
      {
        Sid      = "WriteImmutableSignerInputs"
        Effect   = "Allow"
        Action   = ["s3:PutObject"]
        Resource = ["${aws_s3_bucket.release_artifacts[0].arn}/release-input/sha256/*"]
      },
      {
        Sid      = "ReadImmutableSignerInputs"
        Effect   = "Allow"
        Action   = ["s3:GetObject"]
        Resource = ["${aws_s3_bucket.release_artifacts[0].arn}/release-input/sha256/*"]
      },
      {
        Sid      = "ReadSignerOutputs"
        Effect   = "Allow"
        Action   = ["s3:GetObject"]
        Resource = ["${aws_s3_bucket.release_artifacts[0].arn}/release-signer-output/*"]
      },
      {
        Effect   = "Allow"
        Action   = ["kms:Decrypt", "kms:DescribeKey", "kms:Encrypt", "kms:GenerateDataKey*"]
        Resource = [aws_kms_key.release_artifacts[0].arn]
      },
    ]
  })
}

resource "aws_iam_role" "release_codebuild_signer" {
  count              = var.enable_release_signer ? 1 : 0
  name               = "${local.name_prefix}-release-signer"
  assume_role_policy = jsonencode({ Version = "2012-10-17", Statement = [{ Effect = "Allow", Principal = { Service = "codebuild.amazonaws.com" }, Action = "sts:AssumeRole" }] })
  tags               = local.common_tags
}

data "aws_iam_policy_document" "release_codebuild_signer" {
  count = var.enable_release_signer ? 1 : 0

  # CodeBuild validates the VPC attachment using its service role before it
  # creates a build. These permissions are limited to VPC interface lifecycle
  # and discovery; they grant neither instance control nor route management.
  statement {
    sid = "PrivateCodeBuildVpcAttachment"
    actions = [
      "ec2:CreateNetworkInterface",
      "ec2:CreateNetworkInterfacePermission",
      "ec2:DeleteNetworkInterface",
      "ec2:DescribeDhcpOptions",
      "ec2:DescribeNetworkInterfaces",
      "ec2:DescribeSecurityGroups",
      "ec2:DescribeSubnets",
      "ec2:DescribeVpcs",
    ]
    resources = ["*"]
  }

  statement {
    sid       = "Logs"
    actions   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.release_signer[0].arn}:*"]
  }

  statement {
    sid       = "ReadOnlyVaultClientTrustAnchor"
    actions   = ["secretsmanager:GetSecretValue"]
    resources = [data.aws_secretsmanager_secret.vault_client_ca[0].arn]
  }
  dynamic "statement" {
    for_each = var.release_artifact_bucket_arn == "" ? [] : [var.release_artifact_bucket_arn]
    content {
      sid       = "ReleaseArtifacts"
      actions   = ["s3:GetObject", "s3:PutObject"]
      resources = ["${statement.value}/release/*"]
    }
  }
  dynamic "statement" {
    for_each = var.enable_release_signer ? [1] : []
    content {
      sid       = "ReleaseBucketPrefixes"
      actions   = ["s3:GetObject", "s3:PutObject"]
      resources = ["${aws_s3_bucket.release_artifacts[0].arn}/release-input/*", "${aws_s3_bucket.release_artifacts[0].arn}/release-signer-output/*"]
    }
  }
  dynamic "statement" {
    for_each = var.enable_release_signer ? [1] : []
    content {
      sid       = "ReadImmutableSignerInputVersions"
      actions   = ["s3:GetObjectVersion"]
      resources = ["${aws_s3_bucket.release_artifacts[0].arn}/release-input/*"]
    }
  }
  dynamic "statement" {
    for_each = var.enable_release_signer ? [1] : []
    content {
      sid       = "ListReleaseArtifactVersionsForSignerSource"
      actions   = ["s3:ListBucketVersions"]
      resources = [aws_s3_bucket.release_artifacts[0].arn]
    }
  }
  statement {
    sid = "UseOnlyReleaseArtifactEncryptionKeyThroughS3"
    actions = [
      "kms:Decrypt",
      "kms:DescribeKey",
      "kms:Encrypt",
      "kms:GenerateDataKey*",
    ]
    resources = [aws_kms_key.release_artifacts[0].arn]

    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["s3.${var.aws_region}.amazonaws.com"]
    }
  }

  dynamic "statement" {
    for_each = var.enable_release_signer_ecr_mirror ? [1] : []
    content {
      sid       = "GetEcrAuthorizationToken"
      actions   = ["ecr:GetAuthorizationToken"]
      resources = ["*"]
    }
  }

  dynamic "statement" {
    for_each = var.enable_release_signer_ecr_mirror ? [1] : []
    content {
      sid = "PullOnlyPrivateSignerImage"
      actions = [
        "ecr:BatchCheckLayerAvailability",
        "ecr:BatchGetImage",
        "ecr:GetDownloadUrlForLayer",
      ]
      resources = [aws_ecr_repository.release_signer[0].arn]
    }
  }
}

resource "aws_iam_role_policy" "release_codebuild_signer" {
  count  = var.enable_release_signer ? 1 : 0
  role   = aws_iam_role.release_codebuild_signer[0].id
  policy = data.aws_iam_policy_document.release_codebuild_signer[0].json
}

data "aws_iam_policy_document" "release_artifact_replication_assume_role" {
  count = var.enable_release_signer ? 1 : 0

  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["s3.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "release_artifact_replication" {
  count              = var.enable_release_signer ? 1 : 0
  name               = "${local.name_prefix}-release-artifact-replication"
  assume_role_policy = data.aws_iam_policy_document.release_artifact_replication_assume_role[0].json

  tags = local.common_tags
}

data "aws_iam_policy_document" "release_artifact_replication" {
  count = var.enable_release_signer ? 1 : 0

  statement {
    sid = "ReadOnlyReleaseArtifactSourceVersions"
    actions = [
      "s3:GetObjectLegalHold",
      "s3:GetObjectRetention",
      "s3:GetObjectVersionAcl",
      "s3:GetObjectVersionForReplication",
      "s3:GetObjectVersionTagging",
      "s3:GetReplicationConfiguration",
      "s3:ListBucket",
    ]
    resources = [aws_s3_bucket.release_artifacts[0].arn, "${aws_s3_bucket.release_artifacts[0].arn}/*"]
  }

  statement {
    sid       = "WriteOnlyReleaseArtifactReplicaVersions"
    actions   = ["s3:ObjectOwnerOverrideToBucketOwner", "s3:ReplicateDelete", "s3:ReplicateObject", "s3:ReplicateTags"]
    resources = ["${aws_s3_bucket.release_artifacts_replica[0].arn}/*"]
  }

  statement {
    sid       = "UseOnlyApprovedReleaseArtifactKeys"
    actions   = ["kms:Decrypt", "kms:DescribeKey"]
    resources = [aws_kms_key.release_artifacts[0].arn]
  }

  statement {
    sid       = "EncryptOnlyWithReleaseArtifactReplicaKey"
    actions   = ["kms:DescribeKey", "kms:Encrypt", "kms:GenerateDataKey"]
    resources = [aws_kms_key.release_artifacts_replica[0].arn]
  }
}

resource "aws_iam_role_policy" "release_artifact_replication" {
  count  = var.enable_release_signer ? 1 : 0
  name   = "${local.name_prefix}-release-artifact-replication"
  role   = aws_iam_role.release_artifact_replication[0].id
  policy = data.aws_iam_policy_document.release_artifact_replication[0].json
}

resource "aws_s3_bucket_replication_configuration" "release_artifacts" {
  count  = var.enable_release_signer ? 1 : 0
  bucket = aws_s3_bucket.release_artifacts[0].id
  role   = aws_iam_role.release_artifact_replication[0].arn

  rule {
    id     = "replicate-release-artifacts-to-tokyo"
    status = "Enabled"

    filter {}

    delete_marker_replication {
      status = "Disabled"
    }

    destination {
      bucket        = aws_s3_bucket.release_artifacts_replica[0].arn
      storage_class = "STANDARD"

      encryption_configuration {
        replica_kms_key_id = aws_kms_key.release_artifacts_replica[0].arn
      }
    }

    source_selection_criteria {
      sse_kms_encrypted_objects {
        status = "Enabled"
      }
    }
  }

  depends_on = [
    aws_s3_bucket_versioning.release_artifacts,
    aws_s3_bucket_versioning.release_artifacts_replica,
    aws_iam_role_policy.release_artifact_replication,
  ]
}

resource "aws_codebuild_project" "release_signer" {
  count         = var.enable_release_signer ? 1 : 0
  name          = "${local.name_prefix}-release-signer"
  service_role  = aws_iam_role.release_codebuild_signer[0].arn
  build_timeout = 30
  artifacts {
    type                = "S3"
    location            = aws_s3_bucket.release_artifacts[0].id
    path                = "release-signer-output"
    name                = "release-signer-output.zip"
    namespace_type      = "BUILD_ID"
    packaging           = "ZIP"
    encryption_disabled = false
  }
  environment {
    compute_type                = "BUILD_GENERAL1_SMALL"
    image                       = var.release_signer_image
    type                        = "LINUX_CONTAINER"
    privileged_mode             = false
    image_pull_credentials_type = "SERVICE_ROLE"

    environment_variable {
      name  = "VAULT_ADDR"
      value = var.vault_signer_endpoint
    }

    environment_variable {
      name  = "VAULT_AUTH_ROLE"
      value = var.vault_signer_auth_role
    }

    environment_variable {
      name  = "VAULT_CA_CERT"
      value = data.aws_secretsmanager_secret.vault_client_ca[0].arn
      type  = "SECRETS_MANAGER"
    }
  }
  vpc_config {
    vpc_id             = local.network_vpc_id
    subnets            = var.release_signer_subnet_ids
    security_group_ids = [aws_security_group.release_signer[0].id]
  }
  source {
    type      = "S3"
    location  = "${aws_s3_bucket.release_artifacts[0].id}/release-input/sha256/source-location-must-be-overridden.zip"
    buildspec = "buildspec-release-sign.yml"
  }
  lifecycle {
    precondition {
      condition = (
        var.enable_release_signer_ecr_mirror &&
        var.vault_signer_endpoint != "" &&
        can(regex("^${var.aws_account_id}\\.dkr\\.ecr\\.${var.aws_region}\\.amazonaws\\.com/${local.name_prefix}-vault-release-signer@sha256:[a-f0-9]{64}$", var.release_signer_image)) &&
        length(var.release_signer_subnet_ids) > 0 &&
        alltrue([for subnet_id in var.release_signer_subnet_ids : can(regex("^subnet-[a-z0-9]+$", subnet_id))])
      )
      error_message = "Enabled release signer requires its enabled private ECR mirror, a same-account ECR digest, and one or more explicit private subnet IDs."
    }
  }
  tags = local.common_tags
}
