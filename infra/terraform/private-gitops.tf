variable "enable_private_gitops_foundation" {
  description = "Create the private ECR OCI foundation for Argo CD and reviewed GitOps charts."
  type        = bool
  default     = true
}

locals {
  private_gitops_repositories = {
    argocd = "${local.name_prefix}-gitops-argocd"
    # The Argo bootstrap image and Helm chart are distinct OCI artifacts. Helm
    # publishes the chart beneath Chart.yaml's `argo-cd` path, so keep that
    # chart repository separate from the executable image repository.
    argocd_chart = "${local.name_prefix}-gitops-argocd/argo-cd"
    charts       = "${local.name_prefix}-gitops-charts"
    nodes        = "${local.name_prefix}-gitops-nodes"
    vault        = "${local.name_prefix}-gitops-vault"
    cert_manager = "${local.name_prefix}-gitops-cert-manager"
    # Helm OCI appends Chart.yaml's name to the supplied registry location.
    # Keep runtime images in the root Vault repository and pre-create the
    # resulting chart path so the mirror role never needs CreateRepository.
    vault_chart = "${local.name_prefix}-gitops-vault/vault"
    # Helm OCI appends Chart.yaml's name to the supplied registry location.
    # Pre-create the resulting chart path so mirror delivery never needs
    # CreateRepository and private nodes never need a public registry.
    cert_manager_chart = "${local.name_prefix}-gitops-cert-manager/cert-manager"
  }
}

# The repositories are intentionally empty at foundation apply time. A later
# digest-reviewed mirror action is the only permitted publisher.
resource "aws_ecr_repository" "private_gitops" {
  for_each = var.enable_private_gitops_foundation ? local.private_gitops_repositories : {}

  # Existing GitOps mirrors are deliberately retained with AWS-managed
  # encryption (AES256); ECR encryption cannot be changed in place without
  # replacing deployment artifacts. Secret material is never published here.
  #checkov:skip=CKV_AWS_136:Existing immutable GitOps mirrors use AES256; migration to KMS requires a separately approved repository cutover.

  name                 = each.value
  image_tag_mutability = "IMMUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }

  tags = merge(local.common_tags, {
    Name    = each.value
    Purpose = "private-gitops-${each.key}"
  })

  # These repositories retain reviewed deployment inputs. Deletion requires an
  # explicit configuration change and a separately approved destroy plan.
  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_ecr_lifecycle_policy" "private_gitops" {
  for_each = aws_ecr_repository.private_gitops

  repository = each.value.name
  policy = jsonencode({
    rules = [{
      rulePriority = 1
      description  = "Retain the latest 20 immutable GitOps artifacts"
      selection = {
        tagStatus   = "any"
        countType   = "imageCountMoreThan"
        countNumber = 20
      }
      action = { type = "expire" }
    }]
  })
}

data "aws_iam_policy_document" "github_gitops_oci_mirror_assume_role" {
  count = var.enable_private_gitops_foundation ? 1 : 0

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
    # Match the observed immutable repository/owner IDs. A renamed/recreated
    # repository or an unreviewed legacy subject must not inherit this role.
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:sub"
      values = [
        "${local.github_destination_oidc_subject_prefix}:environment:gitops-oci-mirror",
      ]
    }
  }
}

resource "aws_iam_role" "github_gitops_oci_mirror" {
  count              = var.enable_private_gitops_foundation ? 1 : 0
  name               = "${local.name_prefix}-github-gitops-oci-mirror"
  assume_role_policy = data.aws_iam_policy_document.github_gitops_oci_mirror_assume_role[0].json
  tags               = local.common_tags

  lifecycle {
    prevent_destroy = true
  }
}

data "aws_iam_policy_document" "github_gitops_oci_mirror" {
  count = var.enable_private_gitops_foundation ? 1 : 0
  statement {
    actions   = ["ecr:GetAuthorizationToken"]
    resources = ["*"]
  }
  statement {
    sid = "ReadMirroredArtifactDigest"
    # Helm probes an existing OCI manifest with HEAD before pushing. ECR
    # authorizes that probe as BatchGetImage; it is read-only and remains
    # restricted to the reviewed GitOps repositories.
    actions   = ["ecr:BatchGetImage", "ecr:DescribeImages"]
    resources = values(aws_ecr_repository.private_gitops)[*].arn
  }
  statement {
    sid       = "PushOnlyReviewedGitOpsArtifacts"
    actions   = ["ecr:BatchCheckLayerAvailability", "ecr:CompleteLayerUpload", "ecr:InitiateLayerUpload", "ecr:PutImage", "ecr:UploadLayerPart"]
    resources = values(aws_ecr_repository.private_gitops)[*].arn
  }
}

resource "aws_iam_role_policy" "github_gitops_oci_mirror" {
  count  = var.enable_private_gitops_foundation ? 1 : 0
  name   = "${local.name_prefix}-github-gitops-oci-mirror"
  role   = aws_iam_role.github_gitops_oci_mirror[0].id
  policy = data.aws_iam_policy_document.github_gitops_oci_mirror[0].json
}

# Syft reads manifest layers after the Kyverno CLI publisher has written the
# reviewed image. Keep this permission separate from the mirror's push policy
# and confined to the one canonical repository that contains the CLI.
resource "aws_iam_role_policy" "github_kyverno_cli_layer_read" {
  count = var.enable_private_gitops_foundation ? 1 : 0
  name  = "${local.name_prefix}-kyverno-cli-layer-read"
  role  = aws_iam_role.github_gitops_oci_mirror[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "ReadKyvernoCliLayers"
      Effect   = "Allow"
      Action   = ["ecr:GetDownloadUrlForLayer"]
      Resource = [aws_ecr_repository.private_gitops["nodes"].arn]
    }]
  })
}

output "private_gitops_ecr_repository_urls" {
  description = "Private ECR OCI destinations; empty until the GitOps foundation is explicitly enabled."
  value       = { for key, repository in aws_ecr_repository.private_gitops : key => repository.repository_url }
}

output "github_gitops_oci_mirror_role_arn" {
  description = "GitHub OIDC role ARN for the protected GitOps OCI mirror environment; null until enabled."
  value       = try(aws_iam_role.github_gitops_oci_mirror[0].arn, null)
}
