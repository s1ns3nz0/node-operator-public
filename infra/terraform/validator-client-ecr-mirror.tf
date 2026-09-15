variable "enable_validator_client_ecr_mirror" {
  description = "Create the disabled-by-default private ECR mirror for reviewed Prysm validator client digests."
  type        = bool
  default     = false
}

data "aws_iam_policy_document" "validator_client_ecr_key" {
  count                   = var.enable_validator_client_ecr_mirror ? 1 : 0
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

resource "aws_kms_key" "validator_client_ecr" {
  count                   = var.enable_validator_client_ecr_mirror ? 1 : 0
  description             = "Prysm validator ECR image encryption key"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  policy                  = data.aws_iam_policy_document.validator_client_ecr_key[0].json
  tags                    = merge(local.common_tags, { Name = "${local.name_prefix}-validator-client-ecr", Purpose = "validator-client-ecr-encryption" })
}

resource "aws_ecr_repository" "validator_client" {
  count                = var.enable_validator_client_ecr_mirror ? 1 : 0
  name                 = "${local.name_prefix}-validator-prysm"
  image_tag_mutability = "IMMUTABLE"
  encryption_configuration {
    encryption_type = "KMS"
    kms_key         = aws_kms_key.validator_client_ecr[0].arn
  }
  image_scanning_configuration {
    scan_on_push = true
  }
  tags = merge(local.common_tags, { Name = "${local.name_prefix}-validator-prysm", Purpose = "private-prysm-validator-image" })
}

resource "aws_ecr_repository" "validator_signing_fence" {
  count                = var.enable_validator_client_ecr_mirror ? 1 : 0
  name                 = "${local.name_prefix}-validator-fence"
  image_tag_mutability = "IMMUTABLE"
  encryption_configuration {
    encryption_type = "KMS"
    kms_key         = aws_kms_key.validator_client_ecr[0].arn
  }
  image_scanning_configuration {
    scan_on_push = true
  }
  tags = merge(local.common_tags, { Name = "${local.name_prefix}-validator-fence", Purpose = "validator-signing-fence-image" })
}

data "aws_iam_policy_document" "github_validator_client_mirror_assume_role" {
  count = var.enable_validator_client_ecr_mirror ? 1 : 0
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
      values   = ["${local.github_destination_oidc_subject_prefix}:environment:validator-client-ecr-mirror"]
    }
  }
}

resource "aws_iam_role" "github_validator_client_mirror" {
  count              = var.enable_validator_client_ecr_mirror ? 1 : 0
  name               = "${local.name_prefix}-github-validator-client-mirror"
  assume_role_policy = data.aws_iam_policy_document.github_validator_client_mirror_assume_role[0].json
  tags               = local.common_tags
  lifecycle {
    precondition {
      condition     = local.github_destination_identity_is_explicit
      error_message = "A custom GitHub destination repository requires explicit numeric owner and repository IDs; it cannot inherit the maintainer identity."
    }
  }
}

data "aws_iam_policy_document" "github_validator_client_mirror" {
  count = var.enable_validator_client_ecr_mirror ? 1 : 0
  statement {
    actions   = ["ecr:GetAuthorizationToken"]
    resources = ["*"]
  }
  statement {
    actions   = ["ecr:BatchCheckLayerAvailability", "ecr:BatchGetImage", "ecr:CompleteLayerUpload", "ecr:DescribeImages", "ecr:InitiateLayerUpload", "ecr:PutImage", "ecr:UploadLayerPart"]
    resources = [aws_ecr_repository.validator_client[0].arn, aws_ecr_repository.validator_signing_fence[0].arn]
  }
  # Registry-backed verification reads layers only for the three reviewed images
  # published by this protected environment: Prysm, Fence, and the GET-only probe.
  statement {
    actions   = ["ecr:GetDownloadUrlForLayer"]
    resources = [aws_ecr_repository.validator_client[0].arn, aws_ecr_repository.validator_signing_fence[0].arn, aws_ecr_repository.validator_signer_identity_probe[0].arn]
  }
}

resource "aws_iam_role_policy" "github_validator_client_mirror" {
  count  = var.enable_validator_client_ecr_mirror ? 1 : 0
  name   = "${local.name_prefix}-github-validator-client-mirror"
  role   = aws_iam_role.github_validator_client_mirror[0].id
  policy = data.aws_iam_policy_document.github_validator_client_mirror[0].json
}
