variable "enable_vault_audit_relay_ecr_publisher" {
  description = "Create the private immutable ECR destination and GitHub OIDC publisher for the Vault audit relay."
  type        = bool
  default     = false
}

variable "enable_vault_audit_relay_repository" {
  description = "Create the private immutable ECR destination for the Vault audit relay without granting GitHub publishing authority."
  type        = bool
  default     = false
}

locals {
  vault_audit_relay_repository_name = "${local.name_prefix}-vault-audit-relay"
  vault_audit_relay_repository_enabled = (
    var.enable_vault_audit_relay_repository || var.enable_vault_audit_relay_ecr_publisher
  )
}

data "aws_iam_policy_document" "vault_audit_relay_ecr_key" {
  count                   = local.vault_audit_relay_repository_enabled ? 1 : 0
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

resource "aws_kms_key" "vault_audit_relay_ecr" {
  count                   = local.vault_audit_relay_repository_enabled ? 1 : 0
  description             = "Vault audit relay ECR image encryption key"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  policy                  = data.aws_iam_policy_document.vault_audit_relay_ecr_key[0].json
  tags                    = merge(local.common_tags, { Name = "${local.name_prefix}-vault-audit-relay-ecr", Purpose = "vault-audit-relay-ecr-encryption" })
}

resource "aws_ecr_repository" "vault_audit_relay" {
  count                = local.vault_audit_relay_repository_enabled ? 1 : 0
  name                 = local.vault_audit_relay_repository_name
  image_tag_mutability = "IMMUTABLE"
  encryption_configuration {
    encryption_type = "KMS"
    kms_key         = aws_kms_key.vault_audit_relay_ecr[0].arn
  }
  image_scanning_configuration {
    scan_on_push = true
  }
  tags = merge(local.common_tags, { Name = local.vault_audit_relay_repository_name, Purpose = "private-vault-audit-relay-image" })
  lifecycle {
    prevent_destroy = true
    precondition {
      condition     = local.github_destination_identity_is_explicit
      error_message = "A custom GitHub destination repository requires explicit numeric owner and repository IDs; it cannot inherit the maintainer identity."
    }
  }
}

data "aws_iam_policy_document" "github_vault_audit_relay_publisher_assume_role" {
  count = var.enable_vault_audit_relay_ecr_publisher ? 1 : 0
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
      test     = "StringLike"
      variable = "token.actions.githubusercontent.com:sub"
      values   = ["${local.github_destination_oidc_subject_prefix}:environment:vault-audit-relay-ecr-publish"]
    }
  }
}

resource "aws_iam_role" "github_vault_audit_relay_publisher" {
  count              = var.enable_vault_audit_relay_ecr_publisher ? 1 : 0
  name               = "${local.name_prefix}-github-vault-audit-relay-publisher"
  assume_role_policy = data.aws_iam_policy_document.github_vault_audit_relay_publisher_assume_role[0].json
  tags               = local.common_tags
  lifecycle {
    prevent_destroy = true
  }
}

data "aws_iam_policy_document" "github_vault_audit_relay_publisher" {
  count = var.enable_vault_audit_relay_ecr_publisher ? 1 : 0
  statement {
    actions   = ["ecr:GetAuthorizationToken"]
    resources = ["*"]
  }
  statement {
    actions   = ["ecr:BatchCheckLayerAvailability", "ecr:BatchGetImage", "ecr:CompleteLayerUpload", "ecr:DescribeImages", "ecr:GetDownloadUrlForLayer", "ecr:InitiateLayerUpload", "ecr:PutImage", "ecr:UploadLayerPart"]
    resources = [aws_ecr_repository.vault_audit_relay[0].arn]
  }
}

resource "aws_iam_role_policy" "github_vault_audit_relay_publisher" {
  count  = var.enable_vault_audit_relay_ecr_publisher ? 1 : 0
  name   = "${local.name_prefix}-github-vault-audit-relay-publisher"
  role   = aws_iam_role.github_vault_audit_relay_publisher[0].id
  policy = data.aws_iam_policy_document.github_vault_audit_relay_publisher[0].json
}

output "vault_audit_relay_ecr_repository_url" {
  value       = try(aws_ecr_repository.vault_audit_relay[0].repository_url, null)
  description = "Private immutable ECR URL for the Vault audit relay, or null while disabled."
}

output "github_vault_audit_relay_publisher_role_arn" {
  value       = try(aws_iam_role.github_vault_audit_relay_publisher[0].arn, null)
  description = "GitHub OIDC publishing role restricted to the protected relay environment, or null while disabled."
}
