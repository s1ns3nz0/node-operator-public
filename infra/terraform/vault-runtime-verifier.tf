# This identity is intentionally disabled until the manual, main-only
# verification workflow is ready to use it.
variable "enable_vault_runtime_ci_verifier" {
  description = "Create the dedicated read-only GitHub OIDC role for manual Vault runtime candidate verification. Requires enable_vault_runtime_ecr and enable_node_runtime_ecr."
  type        = bool
  default     = false
}

data "aws_iam_policy_document" "github_vault_runtime_verifier_assume_role" {
  count = var.enable_vault_runtime_ci_verifier ? 1 : 0

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
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:sub"
      values   = ["${local.github_destination_oidc_subject_prefix}:ref:refs/heads/main"]
    }
  }
}

resource "aws_iam_role" "github_vault_runtime_verifier" {
  count              = var.enable_vault_runtime_ci_verifier ? 1 : 0
  name               = "${local.name_prefix}-github-vault-runtime-verifier"
  assume_role_policy = data.aws_iam_policy_document.github_vault_runtime_verifier_assume_role[0].json
  tags               = local.common_tags

  lifecycle {
    precondition {
      condition     = var.enable_vault_runtime_ecr && var.enable_node_runtime_ecr
      error_message = "Vault runtime CI verification requires enable_vault_runtime_ecr and enable_node_runtime_ecr to be true."
    }
  }
}

data "aws_iam_policy_document" "github_vault_runtime_verifier" {
  count = var.enable_vault_runtime_ci_verifier ? 1 : 0

  statement {
    actions   = ["ecr:GetAuthorizationToken"]
    resources = ["*"]
  }
  statement {
    actions   = ["ecr:BatchCheckLayerAvailability", "ecr:BatchGetImage", "ecr:DescribeImages", "ecr:GetDownloadUrlForLayer"]
    resources = values(aws_ecr_repository.vault_runtime)[*].arn
  }
}

resource "aws_iam_role_policy" "github_vault_runtime_verifier" {
  count  = var.enable_vault_runtime_ci_verifier ? 1 : 0
  name   = "${local.name_prefix}-github-vault-runtime-verifier"
  role   = aws_iam_role.github_vault_runtime_verifier[0].id
  policy = data.aws_iam_policy_document.github_vault_runtime_verifier[0].json
}

output "github_vault_runtime_ci_verifier_role_arn" {
  description = "GitHub OIDC role for read-only Vault runtime verification from main, or null while disabled."
  value       = try(aws_iam_role.github_vault_runtime_verifier[0].arn, null)
}
