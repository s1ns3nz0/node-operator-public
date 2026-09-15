# Keep the GET-only signer identity probe in a repository distinct from both
# the validator client and the signing fence. All three share the existing,
# narrowly scoped validator-client ECR KMS key and publisher identity.
resource "aws_ecr_repository" "validator_signer_identity_probe" {
  count                = var.enable_validator_client_ecr_mirror ? 1 : 0
  name                 = "${local.name_prefix}-validator-signer-identity-probe"
  image_tag_mutability = "IMMUTABLE"

  encryption_configuration {
    encryption_type = "KMS"
    kms_key         = aws_kms_key.validator_client_ecr[0].arn
  }

  image_scanning_configuration {
    scan_on_push = true
  }

  tags = merge(local.common_tags, {
    Name    = "${local.name_prefix}-validator-signer-identity-probe"
    Purpose = "validator-signer-identity-probe-image"
  })
}

data "aws_iam_policy_document" "github_validator_signer_identity_probe_mirror" {
  count = var.enable_validator_client_ecr_mirror ? 1 : 0

  statement {
    actions = [
      "ecr:BatchCheckLayerAvailability",
      "ecr:BatchGetImage",
      "ecr:CompleteLayerUpload",
      "ecr:DescribeImages",
      "ecr:InitiateLayerUpload",
      "ecr:PutImage",
      "ecr:UploadLayerPart",
    ]
    resources = [aws_ecr_repository.validator_signer_identity_probe[0].arn]
  }
}

resource "aws_iam_role_policy" "github_validator_signer_identity_probe_mirror" {
  count  = var.enable_validator_client_ecr_mirror ? 1 : 0
  name   = "${local.name_prefix}-github-validator-signer-identity-probe-mirror"
  role   = aws_iam_role.github_validator_client_mirror[0].id
  policy = data.aws_iam_policy_document.github_validator_signer_identity_probe_mirror[0].json
}

output "validator_signer_identity_probe_ecr_repository_url" {
  description = "Private immutable signer identity probe repository URL, or null while disabled."
  value       = try(aws_ecr_repository.validator_signer_identity_probe[0].repository_url, null)
}
