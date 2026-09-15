# The Argo CD repository server consumes a private ECR-hosted Helm OCI chart.
# ECR passwords expire, so a dedicated in-cluster refresher gets only the
# registry read permissions needed to renew the Argo repo-creds Secret.
data "aws_iam_policy_document" "argocd_ecr_refresher_assume_role" {
  statement {
    actions = ["sts:AssumeRole", "sts:TagSession"]
    principals {
      type        = "Service"
      identifiers = ["pods.eks.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "argocd_ecr_refresher" {
  count              = var.enable_gitops_client_ecr_publisher ? 1 : 0
  name               = "${local.name_prefix}-argocd-ecr-refresher"
  assume_role_policy = data.aws_iam_policy_document.argocd_ecr_refresher_assume_role.json
  tags               = local.common_tags
}

data "aws_iam_policy_document" "argocd_ecr_refresher" {
  count = var.enable_gitops_client_ecr_publisher ? 1 : 0
  statement {
    sid       = "GetEcrAuthorizationToken"
    actions   = ["ecr:GetAuthorizationToken"]
    resources = ["*"]
  }
  statement {
    sid       = "ReadOnlyGitOpsClientChart"
    actions   = ["ecr:BatchGetImage", "ecr:BatchCheckLayerAvailability", "ecr:GetDownloadUrlForLayer"]
    resources = [aws_ecr_repository.gitops_client_chart[0].arn]
  }
}

resource "aws_iam_role_policy" "argocd_ecr_refresher" {
  count  = var.enable_gitops_client_ecr_publisher ? 1 : 0
  name   = "${local.name_prefix}-argocd-ecr-refresher"
  role   = aws_iam_role.argocd_ecr_refresher[0].id
  policy = data.aws_iam_policy_document.argocd_ecr_refresher[0].json
}

resource "aws_eks_pod_identity_association" "argocd_ecr_refresher" {
  count           = var.enable_gitops_client_ecr_publisher ? 1 : 0
  cluster_name    = aws_eks_cluster.private.name
  namespace       = "argocd"
  service_account = "argocd-ecr-refresher"
  role_arn        = aws_iam_role.argocd_ecr_refresher[0].arn
  depends_on      = [aws_eks_addon.pod_identity_agent]
}

output "argocd_ecr_refresher_role_arn" {
  value       = try(aws_iam_role.argocd_ecr_refresher[0].arn, null)
  description = "Pod Identity role that can refresh only Argo CD's private ECR chart credentials."
}
