variable "enable_validator_log_collector_ecr_mirror" {
  description = "Create the disabled-by-default private ECR mirror for reviewed Fluent Bit collector digests."
  type        = bool
  default     = false
}

data "aws_iam_policy_document" "validator_log_collector_ecr_key" {
  count                   = var.enable_validator_log_collector_ecr_mirror ? 1 : 0
  source_policy_documents = [data.aws_iam_policy_document.kms_key_administrator.json]

  statement {
    principals {
      type        = "Service"
      identifiers = ["ecr.amazonaws.com"]
    }
    actions   = ["kms:CreateGrant", "kms:Decrypt", "kms:DescribeKey", "kms:Encrypt", "kms:GenerateDataKey*", "kms:ReEncrypt*"]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "kms:CallerAccount"
      values   = [var.aws_account_id]
    }
    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["ecr.${var.aws_region}.amazonaws.com"]
    }
  }
}

resource "aws_kms_key" "validator_log_collector_ecr" {
  count                   = var.enable_validator_log_collector_ecr_mirror ? 1 : 0
  description             = "Validator log collector ECR image encryption key"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  policy                  = data.aws_iam_policy_document.validator_log_collector_ecr_key[0].json
  tags                    = merge(local.common_tags, { Name = "${local.name_prefix}-validator-log-collector-ecr", Purpose = "validator-log-collector-ecr-encryption" })
}

resource "aws_ecr_repository" "validator_log_collector" {
  count                = var.enable_validator_log_collector_ecr_mirror ? 1 : 0
  name                 = "${local.name_prefix}-validator-fluent-bit"
  image_tag_mutability = "IMMUTABLE"
  encryption_configuration {
    encryption_type = "KMS"
    kms_key         = aws_kms_key.validator_log_collector_ecr[0].arn
  }
  image_scanning_configuration {
    scan_on_push = true
  }
  tags = merge(local.common_tags, { Name = "${local.name_prefix}-validator-fluent-bit", Purpose = "private-validator-log-collector-image" })
}

data "aws_iam_policy_document" "github_validator_log_collector_mirror_assume_role" {
  count = var.enable_validator_log_collector_ecr_mirror ? 1 : 0
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
      variable = "token.actions.githubusercontent.com:sub"
      values   = ["${local.github_destination_oidc_subject_prefix}:environment:validator-log-collector-ecr-mirror"]
    }
  }
}

locals {
  validator_log_collector_publisher_role_name = "${local.name_prefix}-github-validator-log-collector-mirror"
}

resource "aws_iam_role" "github_validator_log_collector_mirror" {
  count              = var.enable_validator_log_collector_ecr_mirror ? 1 : 0
  name               = length(local.validator_log_collector_publisher_role_name) <= 64 ? local.validator_log_collector_publisher_role_name : "${substr(local.validator_log_collector_publisher_role_name, 0, 55)}-${substr(sha256(local.validator_log_collector_publisher_role_name), 0, 8)}"
  assume_role_policy = data.aws_iam_policy_document.github_validator_log_collector_mirror_assume_role[0].json
  tags               = local.common_tags
  lifecycle {
    precondition {
      condition     = local.github_destination_identity_is_explicit
      error_message = "A custom GitHub destination repository requires explicit numeric owner and repository IDs; it cannot inherit the maintainer identity."
    }
  }
}

data "aws_iam_policy_document" "github_validator_log_collector_mirror" {
  count = var.enable_validator_log_collector_ecr_mirror ? 1 : 0
  statement {
    actions   = ["ecr:GetAuthorizationToken"]
    resources = ["*"]
  }
  statement {
    actions   = ["ecr:BatchCheckLayerAvailability", "ecr:BatchGetImage", "ecr:CompleteLayerUpload", "ecr:DescribeImages", "ecr:InitiateLayerUpload", "ecr:PutImage", "ecr:UploadLayerPart"]
    resources = [aws_ecr_repository.validator_log_collector[0].arn]
  }
}

resource "aws_iam_role_policy" "github_validator_log_collector_mirror" {
  count  = var.enable_validator_log_collector_ecr_mirror ? 1 : 0
  name   = "${local.name_prefix}-github-validator-log-collector-mirror"
  role   = aws_iam_role.github_validator_log_collector_mirror[0].id
  policy = data.aws_iam_policy_document.github_validator_log_collector_mirror[0].json
}
