# Health runtime is distinct from both the ZAP scanner and node executables.
# Reuses only the existing node-runtime encryption boundary; no publisher IAM.
resource "aws_ecr_repository" "upcheck_runtime" {
  count                = var.enable_node_runtime_ecr ? 1 : 0
  name                 = "${local.name_prefix}-node-runtime-upcheck-python"
  image_tag_mutability = "IMMUTABLE"
  encryption_configuration {
    encryption_type = "KMS"
    kms_key         = aws_kms_key.node_runtime_ecr[0].arn
  }
  image_scanning_configuration {
    scan_on_push = true
  }
  tags = merge(local.common_tags, { Name = "${local.name_prefix}-node-runtime-upcheck-python", Purpose = "health-proxy-runtime-image" })
}

output "upcheck_runtime_ecr_repository_url" {
  description = "Immutable health-proxy Python runtime repository, separate from the DAST scanner."
  value       = try(aws_ecr_repository.upcheck_runtime[0].repository_url, null)
}
