# Separate source builds from upstream-only mirrors. Provisioning grants no
# GitHub publisher permissions and does not constitute trusted CI promotion.
variable "enable_node_runtime_ecr" {
  description = "Create KMS-encrypted immutable repositories for reviewed Nethermind and Prysm Beacon runtime builds."
  type        = bool
  default     = false
}

data "aws_iam_policy_document" "node_runtime_ecr_key" {
  count                   = var.enable_node_runtime_ecr ? 1 : 0
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

resource "aws_kms_key" "node_runtime_ecr" {
  count                   = var.enable_node_runtime_ecr ? 1 : 0
  description             = "Source-built node runtime ECR image encryption key"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  policy                  = data.aws_iam_policy_document.node_runtime_ecr_key[0].json
  tags                    = merge(local.common_tags, { Name = "${local.name_prefix}-node-runtime-ecr", Purpose = "node-runtime-ecr-encryption" })
}

resource "aws_ecr_repository" "node_runtime" {
  for_each             = var.enable_node_runtime_ecr ? toset(["nethermind", "prysm-beacon"]) : toset([])
  name                 = "${local.name_prefix}-node-runtime-${each.key}"
  image_tag_mutability = "IMMUTABLE"
  encryption_configuration {
    encryption_type = "KMS"
    kms_key         = aws_kms_key.node_runtime_ecr[0].arn
  }
  image_scanning_configuration {
    scan_on_push = true
  }
  tags = merge(local.common_tags, { Name = "${local.name_prefix}-node-runtime-${each.key}", Purpose = "source-built-node-runtime-image" })
}

output "node_runtime_ecr_repository_urls" {
  description = "Reviewed source-built node runtime repositories; empty when disabled."
  value       = { for component, repository in aws_ecr_repository.node_runtime : component => repository.repository_url }
}
