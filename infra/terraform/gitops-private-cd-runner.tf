variable "enable_gitops_private_cd_runner" {
  description = "Create the GitOps-repository-only, VPC-internal CodeBuild GitHub Actions runner for read-only CD verification and bounded DAST."
  type        = bool
  default     = false
}

variable "gitops_private_cd_runner_connection_arn" {
  description = "Existing operator-authorized GitHub CodeConnections ARN. It is not a credential and remains outside repository state."
  type        = string
  default     = ""

  validation {
    condition     = var.gitops_private_cd_runner_connection_arn == "" || can(regex("^arn:aws:codeconnections:[a-z0-9-]+:[0-9]{12}:connection/[0-9a-f-]{36}$", var.gitops_private_cd_runner_connection_arn))
    error_message = "gitops_private_cd_runner_connection_arn must be empty while disabled or a CodeConnections ARN."
  }
}

variable "gitops_private_cd_runner_subnet_ids" {
  description = "Explicit private subnets for the GitOps private CD runner."
  type        = list(string)
  default     = []
}

resource "aws_security_group" "gitops_private_cd_runner" {
  count       = var.enable_gitops_private_cd_runner ? 1 : 0
  name_prefix = "${local.name_prefix}-gitops-private-cd-"
  description = "GitOps private CD runner egress to GitHub through NAT, the private EKS API, and approved VPC endpoints."
  vpc_id      = local.network_vpc_id

  egress {
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    security_groups = [aws_security_group.cluster.id, aws_security_group.endpoints.id]
    cidr_blocks     = ["0.0.0.0/0"]
    prefix_list_ids = [var.offline_validation ? "pl-78a54011" : data.aws_prefix_list.s3[0].id]
    description     = "HTTPS to the private EKS API, approved endpoints, ECR layers, and GitHub Actions runner control plane through NAT"
  }

  tags = merge(local.common_tags, {
    Name    = "${local.name_prefix}-gitops-private-cd"
    Purpose = "gitops-private-cd-verification-and-bounded-dast"
  })
}

resource "aws_vpc_security_group_ingress_rule" "cluster_api_from_gitops_private_cd_runner" {
  count                        = var.enable_gitops_private_cd_runner ? 1 : 0
  description                  = "Kubernetes API from GitOps private CD runner"
  security_group_id            = aws_security_group.cluster.id
  referenced_security_group_id = aws_security_group.gitops_private_cd_runner[0].id
  from_port                    = 443
  to_port                      = 443
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "endpoints_from_gitops_private_cd_runner" {
  count                        = var.enable_gitops_private_cd_runner ? 1 : 0
  description                  = "HTTPS from GitOps private CD runner to interface endpoints"
  security_group_id            = aws_security_group.endpoints.id
  referenced_security_group_id = aws_security_group.gitops_private_cd_runner[0].id
  from_port                    = 443
  to_port                      = 443
  ip_protocol                  = "tcp"
}

resource "aws_iam_role" "gitops_private_cd_runner" {
  count = var.enable_gitops_private_cd_runner ? 1 : 0
  name  = "${local.name_prefix}-gitops-private-cd-runner"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "codebuild.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
  tags = local.common_tags
}

data "aws_iam_policy_document" "gitops_private_cd_runner" {
  count = var.enable_gitops_private_cd_runner ? 1 : 0

  statement {
    sid       = "WriteOnlyPrivateCdLogs"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.gitops_private_cd_runner[0].arn}:*"]
  }

  statement {
    sid       = "DescribeOnlyTargetCluster"
    actions   = ["eks:DescribeCluster"]
    resources = [aws_eks_cluster.private.arn]
  }

  # Helm OCI Applications track the immutable chart version as targetRevision.
  # Resolve it only at the private immutable ECR repository before comparing
  # the resulting manifest digest to the reviewed workflow input.
  statement {
    sid = "ReadOnlyVerifiedGitOpsChartForCdAdmission"
    actions = [
      "ecr:DescribeImages",
      "ecr:BatchGetImage",
      "ecr:GetDownloadUrlForLayer",
    ]
    resources = [aws_ecr_repository.gitops_client_chart[0].arn]
  }

  # ECR authorization tokens cannot be resource-scoped. The runner uses this
  # only to pull the repository constrained by the statement above.
  statement {
    sid       = "AuthorizeReadOnlyEcrChartPull"
    actions   = ["ecr:GetAuthorizationToken"]
    resources = ["*"]
  }

  statement {
    sid = "UseOnlyApprovedGitHubConnection"
    actions = [
      "codeconnections:GetConnection",
      "codeconnections:GetConnectionToken",
      "codeconnections:UseConnection",
    ]
    resources = [var.gitops_private_cd_runner_connection_arn]
  }

  statement {
    sid = "ManageOnlyCodeBuildVpcNetworkInterfaces"
    actions = [
      "ec2:CreateNetworkInterface",
      "ec2:CreateNetworkInterfacePermission",
      "ec2:DeleteNetworkInterface",
      "ec2:DescribeDhcpOptions",
      "ec2:DescribeNetworkInterfaces",
      "ec2:DescribeSecurityGroups",
      "ec2:DescribeSubnets",
      "ec2:DescribeVpcs",
    ]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "gitops_private_cd_runner" {
  count  = var.enable_gitops_private_cd_runner ? 1 : 0
  name   = "${local.name_prefix}-gitops-private-cd-runner"
  role   = aws_iam_role.gitops_private_cd_runner[0].id
  policy = data.aws_iam_policy_document.gitops_private_cd_runner[0].json
}

resource "aws_cloudwatch_log_group" "gitops_private_cd_runner" {
  count             = var.enable_gitops_private_cd_runner ? 1 : 0
  name              = "/aws/codebuild/${local.name_prefix}-gitops-private-cd"
  retention_in_days = 90
  tags              = local.common_tags
}

# This identity can only read the Argo Application and the disposable DAST
# namespace. It has no sync, exec, secret-read, or workload-write authority.
resource "aws_eks_access_entry" "gitops_private_cd_runner" {
  count         = var.enable_gitops_private_cd_runner ? 1 : 0
  cluster_name  = aws_eks_cluster.private.name
  principal_arn = aws_iam_role.gitops_private_cd_runner[0].arn
  # AWS managed EKS access policies intentionally do not cover custom-resource
  # APIs.  A stable group lets the GitOps bundle bind the one required CRD
  # permission without granting the runner any Kubernetes write authority.
  kubernetes_groups = ["node-operator:gitops-private-cd-readers"]
  type              = "STANDARD"
}

resource "aws_eks_access_policy_association" "gitops_private_cd_runner" {
  count         = var.enable_gitops_private_cd_runner ? 1 : 0
  cluster_name  = aws_eks_cluster.private.name
  principal_arn = aws_iam_role.gitops_private_cd_runner[0].arn
  policy_arn    = "arn:aws:eks::aws:cluster-access-policy/AmazonEKSViewPolicy"

  access_scope {
    type       = "namespace"
    namespaces = ["argocd", "node-operator-dast"]
  }

  depends_on = [aws_eks_access_entry.gitops_private_cd_runner]
}

resource "aws_codebuild_project" "gitops_private_cd_runner" {
  count         = var.enable_gitops_private_cd_runner ? 1 : 0
  name          = "${local.name_prefix}-gitops-private-cd"
  description   = "GitOps-repository-only ephemeral runner for read-only CD verification and bounded private DAST"
  service_role  = aws_iam_role.gitops_private_cd_runner[0].arn
  build_timeout = 30

  artifacts { type = "NO_ARTIFACTS" }

  environment {
    compute_type                = "BUILD_GENERAL1_MEDIUM"
    image                       = "aws/codebuild/standard:7.0"
    type                        = "LINUX_CONTAINER"
    privileged_mode             = true
    image_pull_credentials_type = "CODEBUILD"
  }

  vpc_config {
    vpc_id             = local.network_vpc_id
    subnets            = var.gitops_private_cd_runner_subnet_ids
    security_group_ids = [aws_security_group.gitops_private_cd_runner[0].id]
  }

  source {
    type      = "GITHUB"
    location  = "https://github.com/s1ns3nz0/node-operator-gitops"
    buildspec = "version: 0.2\nphases:\n  build:\n    commands:\n      - true\n"

    auth {
      type     = "CODECONNECTIONS"
      resource = var.gitops_private_cd_runner_connection_arn
    }
  }

  lifecycle {
    precondition {
      condition = (
        var.gitops_private_cd_runner_connection_arn != "" &&
        can(regex("^arn:aws:codeconnections:${var.aws_region}:${var.aws_account_id}:connection/[0-9a-f-]{36}$", var.gitops_private_cd_runner_connection_arn)) &&
        length(var.gitops_private_cd_runner_subnet_ids) > 0 &&
        alltrue([for subnet_id in var.gitops_private_cd_runner_subnet_ids : can(regex("^subnet-[a-z0-9]+$", subnet_id))])
      )
      error_message = "Enabled GitOps private CD runner requires the approved CodeConnections ARN and explicit private subnet IDs."
    }
  }

  tags = local.common_tags

  depends_on = [aws_eks_access_policy_association.gitops_private_cd_runner]
}

resource "aws_codebuild_webhook" "gitops_private_cd_runner" {
  count        = var.enable_gitops_private_cd_runner ? 1 : 0
  project_name = aws_codebuild_project.gitops_private_cd_runner[0].name

  filter_group {
    filter {
      type    = "EVENT"
      pattern = "WORKFLOW_JOB_QUEUED"
    }
  }
}

output "gitops_private_cd_runner_project_name" {
  description = "GitOps-repository-only private CodeBuild runner, or null while disabled."
  value       = try(aws_codebuild_project.gitops_private_cd_runner[0].name, null)
}
