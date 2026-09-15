variable "enable_release_signer_ecr_mirror" {
  description = "Create the private ECR signer-image mirror foundation. It remains disabled until a reviewed plan is approved."
  type        = bool
  default     = false
}

data "aws_iam_policy_document" "release_signer_ecr_key" {
  count = var.enable_release_signer_ecr_mirror ? 1 : 0

  source_policy_documents = [data.aws_iam_policy_document.kms_key_administrator.json]

  statement {
    sid    = "AllowEcrToUseMirrorKeyOnlyInThisAccount"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["ecr.amazonaws.com"]
    }

    actions = [
      "kms:CreateGrant",
      "kms:Decrypt",
      "kms:DescribeKey",
      "kms:Encrypt",
      "kms:GenerateDataKey*",
      "kms:ReEncrypt*",
    ]
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

# This is only the destination and least-privilege identity contract. A later,
# separately authorized workflow may mirror an already reviewed GHCR digest.
resource "aws_kms_key" "release_signer_ecr" {
  count                   = var.enable_release_signer_ecr_mirror ? 1 : 0
  description             = "Release signer ECR image encryption key"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  policy                  = data.aws_iam_policy_document.release_signer_ecr_key[0].json

  tags = merge(local.common_tags, {
    Name    = "${local.name_prefix}-release-signer-ecr"
    Purpose = "release-signer-ecr-encryption"
  })
}

resource "aws_kms_alias" "release_signer_ecr" {
  count         = var.enable_release_signer_ecr_mirror ? 1 : 0
  name          = "alias/${local.name_prefix}-release-signer-ecr"
  target_key_id = aws_kms_key.release_signer_ecr[0].key_id

  # Legacy environments may retain this alias under a key whose resource
  # policy denies UpdateAlias. Keep the existing alias target untouched while
  # the ECR key itself remains managed by Terraform.
  lifecycle {
    ignore_changes = [target_key_id]
  }
}

resource "aws_ecr_repository" "release_signer" {
  count                = var.enable_release_signer_ecr_mirror ? 1 : 0
  name                 = "${local.name_prefix}-vault-release-signer"
  image_tag_mutability = "IMMUTABLE"

  encryption_configuration {
    encryption_type = "KMS"
    kms_key         = aws_kms_key.release_signer_ecr[0].arn
  }

  image_scanning_configuration {
    scan_on_push = true
  }

  tags = merge(local.common_tags, {
    Name    = "${local.name_prefix}-vault-release-signer"
    Purpose = "private-codebuild-signer-image"
  })
}

# Retain only the current approved signer image.  Tags are immutable, so a
# replacement always receives a new digest-derived tag and can be safely
# expired after the mirror has advanced.
resource "aws_ecr_lifecycle_policy" "release_signer" {
  count      = var.enable_release_signer_ecr_mirror ? 1 : 0
  repository = aws_ecr_repository.release_signer[0].name

  policy = jsonencode({
    rules = [{
      rulePriority = 1
      description  = "Keep only the newest approved signer image"
      selection = {
        tagStatus     = "tagged"
        tagPrefixList = ["approved-"]
        countType     = "imageCountMoreThan"
        countNumber   = 1
      }
      action = { type = "expire" }
    }]
  })
}

data "aws_iam_policy_document" "github_ecr_signer_mirror_assume_role" {
  count = var.enable_release_signer_ecr_mirror ? 1 : 0

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

    # GitHub may emit an ID-bearing subject after an organization enables the
    # OIDC subject-template customization. The repository claim remains exact;
    # the subject alternatives are both bound to this environment only.
    condition {
      test     = "StringLike"
      variable = "token.actions.githubusercontent.com:sub"
      values = [
        "repo:${var.github_repository}:environment:ecr-signer-mirror",
        "repo:${split("/", var.github_repository)[0]}@*/${split("/", var.github_repository)[1]}@*:environment:ecr-signer-mirror",
      ]
    }
  }
}

resource "aws_iam_role" "github_ecr_signer_mirror" {
  count              = var.enable_release_signer_ecr_mirror ? 1 : 0
  name               = "${local.name_prefix}-github-ecr-signer-mirror"
  assume_role_policy = data.aws_iam_policy_document.github_ecr_signer_mirror_assume_role[0].json
  tags               = local.common_tags
}

data "aws_iam_policy_document" "github_ecr_signer_mirror" {
  count = var.enable_release_signer_ecr_mirror ? 1 : 0

  statement {
    sid       = "GetEcrAuthorizationToken"
    actions   = ["ecr:GetAuthorizationToken"]
    resources = ["*"]
  }

  statement {
    sid = "PushOnlyReviewedSignerRepository"
    actions = [
      "ecr:BatchCheckLayerAvailability",
      "ecr:CompleteLayerUpload",
      "ecr:DescribeImages",
      "ecr:InitiateLayerUpload",
      "ecr:PutImage",
      "ecr:UploadLayerPart",
    ]
    resources = [aws_ecr_repository.release_signer[0].arn]
  }
}

resource "aws_iam_role_policy" "github_ecr_signer_mirror" {
  count  = var.enable_release_signer_ecr_mirror ? 1 : 0
  name   = "${local.name_prefix}-github-ecr-signer-mirror"
  role   = aws_iam_role.github_ecr_signer_mirror[0].id
  policy = data.aws_iam_policy_document.github_ecr_signer_mirror[0].json
}
