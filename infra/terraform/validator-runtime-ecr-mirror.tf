variable "enable_validator_runtime_ecr_mirror" {
  description = "Create disabled-by-default private ECR mirrors and a narrowly scoped GitHub OIDC identity for reviewed Web3Signer and PostgreSQL runtime images."
  type        = bool
  default     = false
}

data "aws_iam_policy_document" "validator_runtime_ecr_key" {
  count                   = var.enable_validator_runtime_ecr_mirror ? 1 : 0
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

resource "aws_kms_key" "validator_runtime_ecr" {
  count                   = var.enable_validator_runtime_ecr_mirror ? 1 : 0
  description             = "Validator runtime ECR image encryption key"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  policy                  = data.aws_iam_policy_document.validator_runtime_ecr_key[0].json
  tags                    = merge(local.common_tags, { Name = "${local.name_prefix}-validator-runtime-ecr", Purpose = "validator-runtime-ecr-encryption" })
}

resource "aws_ecr_repository" "validator_runtime" {
  # The older validator-web3signer/postgres repository names already contain
  # untracked AES256 images. Keep them untouched; this KMS boundary owns new,
  # unambiguous destinations only.
  for_each             = var.enable_validator_runtime_ecr_mirror ? toset(["validator-runtime-web3signer", "validator-runtime-postgres"]) : toset([])
  name                 = "${local.name_prefix}-${each.value}"
  image_tag_mutability = "IMMUTABLE"
  encryption_configuration {
    encryption_type = "KMS"
    kms_key         = aws_kms_key.validator_runtime_ecr[0].arn
  }
  image_scanning_configuration {
    scan_on_push = true
  }
  tags = merge(local.common_tags, { Name = "${local.name_prefix}-${each.value}", Purpose = "private-validator-runtime-image" })
}

data "aws_iam_policy_document" "github_validator_runtime_mirror_assume_role" {
  count = var.enable_validator_runtime_ecr_mirror ? 1 : 0
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
      values   = ["${local.github_destination_oidc_subject_prefix}:environment:validator-runtime-ecr-mirror"]
    }
  }
}

resource "aws_iam_role" "github_validator_runtime_mirror" {
  count              = var.enable_validator_runtime_ecr_mirror ? 1 : 0
  name               = "${local.name_prefix}-github-validator-runtime-mirror"
  assume_role_policy = data.aws_iam_policy_document.github_validator_runtime_mirror_assume_role[0].json
  tags               = local.common_tags
}

data "aws_iam_policy_document" "github_validator_runtime_mirror" {
  count = var.enable_validator_runtime_ecr_mirror ? 1 : 0
  statement {
    actions   = ["ecr:GetAuthorizationToken"]
    resources = ["*"]
  }
  statement {
    actions   = ["ecr:BatchCheckLayerAvailability", "ecr:BatchGetImage", "ecr:CompleteLayerUpload", "ecr:DescribeImages", "ecr:InitiateLayerUpload", "ecr:PutImage", "ecr:UploadLayerPart"]
    resources = values(aws_ecr_repository.validator_runtime)[*].arn
  }
}

resource "aws_iam_role_policy" "github_validator_runtime_mirror" {
  count  = var.enable_validator_runtime_ecr_mirror ? 1 : 0
  name   = "${local.name_prefix}-github-validator-runtime-mirror"
  role   = aws_iam_role.github_validator_runtime_mirror[0].id
  policy = data.aws_iam_policy_document.github_validator_runtime_mirror[0].json
}

output "validator_runtime_ecr_repository_urls" {
  description = "Private immutable validator runtime repositories by component, or an empty map while disabled."
  value       = { for component, repository in aws_ecr_repository.validator_runtime : component => repository.repository_url }
}

output "github_validator_runtime_ecr_mirror_role_arn" {
  description = "GitHub OIDC role for the validator-runtime-ecr-mirror environment, or null while disabled."
  value       = try(aws_iam_role.github_validator_runtime_mirror[0].arn, null)
}
