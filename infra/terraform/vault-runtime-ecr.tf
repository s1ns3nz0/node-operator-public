# Source-built Vault components must never replace upstream-only mirror tags.
# These repositories grant no publisher permissions and deploy no workloads.
variable "enable_vault_runtime_ecr" {
  description = "Create separate reviewed Vault runtime repositories under the existing node-runtime KMS boundary. Requires enable_node_runtime_ecr."
  type        = bool
  default     = false
}

resource "aws_ecr_repository" "vault_runtime" {
  for_each             = var.enable_vault_runtime_ecr ? toset(["server", "agent", "injector"]) : toset([])
  name                 = "${local.name_prefix}-vault-runtime-${each.key}"
  image_tag_mutability = "IMMUTABLE"
  force_delete         = false
  encryption_configuration {
    encryption_type = "KMS"
    kms_key         = aws_kms_key.node_runtime_ecr[0].arn
  }
  image_scanning_configuration {
    scan_on_push = true
  }
  tags = merge(local.common_tags, { Name = "${local.name_prefix}-vault-runtime-${each.key}", Purpose = "source-built-vault-runtime-image" })
  lifecycle {
    precondition {
      condition     = var.enable_node_runtime_ecr
      error_message = "Vault runtime repositories require the existing node-runtime KMS boundary; enable_node_runtime_ecr must be true."
    }
  }
}

output "vault_runtime_ecr_repository_urls" {
  description = "Separate source-built Vault component repositories; empty when disabled."
  value       = { for component, repository in aws_ecr_repository.vault_runtime : component => repository.repository_url }
}
