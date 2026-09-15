variable "enable_private_dast_ecr_mirror" {
  description = "Create the disabled-by-default private immutable ECR destination and GitHub OIDC mirror identity for the reviewed DAST scanner."
  type        = bool
  default     = false
}

data "aws_iam_policy_document" "private_dast_ecr_key" {
  count                   = var.enable_private_dast_ecr_mirror ? 1 : 0
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

resource "aws_kms_key" "private_dast_ecr" {
  count                   = var.enable_private_dast_ecr_mirror ? 1 : 0
  description             = "Private DAST scanner ECR image encryption key"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  policy                  = data.aws_iam_policy_document.private_dast_ecr_key[0].json
  tags                    = merge(local.common_tags, { Name = "${local.name_prefix}-dast-ecr", Purpose = "private-dast-ecr-encryption" })
}

resource "aws_ecr_repository" "private_dast" {
  count                = var.enable_private_dast_ecr_mirror ? 1 : 0
  name                 = "${local.name_prefix}-dast-zap-baseline"
  image_tag_mutability = "IMMUTABLE"
  encryption_configuration {
    encryption_type = "KMS"
    kms_key         = aws_kms_key.private_dast_ecr[0].arn
  }
  image_scanning_configuration {
    scan_on_push = true
  }
  tags = merge(local.common_tags, { Name = "${local.name_prefix}-dast-zap-baseline", Purpose = "private-baseline-dast-scanner" })
}

data "aws_iam_policy_document" "github_private_dast_mirror_assume_role" {
  count = var.enable_private_dast_ecr_mirror ? 1 : 0
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
      values   = ["${local.github_destination_oidc_subject_prefix}:environment:private-dast-ecr-mirror"]
    }
  }
}

resource "aws_iam_role" "github_private_dast_mirror" {
  count              = var.enable_private_dast_ecr_mirror ? 1 : 0
  name               = "${local.name_prefix}-github-private-dast-mirror"
  assume_role_policy = data.aws_iam_policy_document.github_private_dast_mirror_assume_role[0].json
  tags               = local.common_tags
}

data "aws_iam_policy_document" "github_private_dast_mirror" {
  count = var.enable_private_dast_ecr_mirror ? 1 : 0
  statement {
    actions   = ["ecr:GetAuthorizationToken"]
    resources = ["*"]
  }
  statement {
    actions   = ["ecr:BatchCheckLayerAvailability", "ecr:BatchGetImage", "ecr:CompleteLayerUpload", "ecr:DescribeImages", "ecr:InitiateLayerUpload", "ecr:PutImage", "ecr:UploadLayerPart"]
    resources = [aws_ecr_repository.private_dast[0].arn]
  }
}

resource "aws_iam_role_policy" "github_private_dast_mirror" {
  count  = var.enable_private_dast_ecr_mirror ? 1 : 0
  name   = "${local.name_prefix}-github-private-dast-mirror"
  role   = aws_iam_role.github_private_dast_mirror[0].id
  policy = data.aws_iam_policy_document.github_private_dast_mirror[0].json
}

output "private_dast_ecr_repository_url" {
  description = "Private immutable DAST scanner repository URL, or null while disabled."
  value       = try(aws_ecr_repository.private_dast[0].repository_url, null)
}
