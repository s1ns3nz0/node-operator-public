# The runner is deliberately opt-in. It restores the repository-scoped
# CodeBuild GitHub Actions boundary; it does not enable a release or change
# any GitHub Environment, Vault, or connection state.
variable "enable_private_release_runner" {
  description = "Create the repository-scoped private CodeBuild GitHub Actions release runner after plan review."
  type        = bool
  default     = false
}

variable "private_release_runner_connection_arn" {
  description = "Existing operator-authorized same-account GitHub CodeConnections ARN for the private release runner."
  type        = string
  default     = ""
}

variable "private_release_runner_subnet_ids" {
  description = "Explicit current private subnet IDs for the private release runner; historical subnet IDs are never reused."
  type        = list(string)
  default     = []
}

resource "aws_security_group" "private_release_runner" {
  count       = var.enable_private_release_runner ? 1 : 0
  name_prefix = "${local.name_prefix}-private-release-"
  description = "Private CodeBuild release runner outbound-only access to GitHub through NAT and private Vault Transit."
  vpc_id      = local.network_vpc_id

  # The runner has no inbound rule or public address. HTTPS exits through the
  # selected private subnet's existing NAT route to GitHub's runner control
  # plane and Actions dependencies; it is not a public Vault path.
  egress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTPS to GitHub Actions control plane through the existing private-subnet NAT route"
  }

  # Vault is reachable only on its private VPC address space. No ingress rule
  # is created here, and this does not create a public listener or DNS name.
  egress {
    from_port   = 8200
    to_port     = 8200
    protocol    = "tcp"
    cidr_blocks = [local.network_vpc_cidr]
    description = "Vault Transit HTTPS to the private internal endpoint only"
  }

  tags = merge(local.common_tags, {
    Name    = "${local.name_prefix}-private-release-runner"
    Purpose = "repository-scoped-ephemeral-github-actions-release-runner"
  })
}

resource "aws_iam_role" "private_release_runner" {
  count = var.enable_private_release_runner ? 1 : 0
  name  = "${local.name_prefix}-private-release-runner"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "codebuild.amazonaws.com" }
      Action    = "sts:AssumeRole"
      Condition = {
        StringEquals = {
          "aws:SourceAccount" = var.aws_account_id
        }
        ArnEquals = {
          "aws:SourceArn" = "arn:aws:codebuild:${var.aws_region}:${var.aws_account_id}:project/${local.name_prefix}-private-release"
        }
      }
    }]
  })

  tags = local.common_tags
}

resource "aws_cloudwatch_log_group" "private_release_runner" {
  count             = var.enable_private_release_runner ? 1 : 0
  name              = "/aws/codebuild/${local.name_prefix}-private-release"
  retention_in_days = 90
  kms_key_id        = aws_kms_key.private_release_runner_logs[0].arn
  tags              = local.common_tags
}

data "aws_iam_policy_document" "private_release_runner_logs_key" {
  count = var.enable_private_release_runner ? 1 : 0

  source_policy_documents = [data.aws_iam_policy_document.kms_key_administrator.json]

  statement {
    sid    = "AllowCloudWatchLogsForPrivateReleaseRunnerOnly"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["logs.${var.aws_region}.amazonaws.com"]
    }

    actions   = ["kms:Encrypt*", "kms:Decrypt*", "kms:ReEncrypt*", "kms:GenerateDataKey*", "kms:Describe*"]
    resources = ["*"]

    condition {
      test     = "ArnLike"
      variable = "kms:EncryptionContext:aws:logs:arn"
      values   = ["arn:aws:logs:${var.aws_region}:${var.aws_account_id}:log-group:/aws/codebuild/${local.name_prefix}-private-release"]
    }
  }
}

resource "aws_kms_key" "private_release_runner_logs" {
  count                   = var.enable_private_release_runner ? 1 : 0
  description             = "Private release runner CodeBuild log encryption key"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  policy                  = data.aws_iam_policy_document.private_release_runner_logs_key[0].json
  tags                    = local.common_tags
}

resource "aws_kms_alias" "private_release_runner_logs" {
  count         = var.enable_private_release_runner ? 1 : 0
  name          = "alias/${local.name_prefix}-private-release-runner-logs"
  target_key_id = aws_kms_key.private_release_runner_logs[0].key_id
}

data "aws_iam_policy_document" "private_release_runner" {
  count = var.enable_private_release_runner ? 1 : 0

  statement {
    sid       = "WriteOnlyEncryptedPrivateReleaseLogs"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.private_release_runner[0].arn}:*"]
  }

  statement {
    sid       = "DescribeOnlyPrivateReleaseLogGroups"
    actions   = ["logs:DescribeLogGroups"]
    resources = ["*"]
  }

  statement {
    sid       = "DescribeOnlyPrivateCluster"
    actions   = ["eks:DescribeCluster"]
    resources = [aws_eks_cluster.private.arn]
  }

  # ECR authorization tokens do not support a repository resource constraint.
  # The runner uses this only for the reviewed private AWS smoke path.
  statement {
    sid       = "AuthorizePrivateEcrSmokeOnly"
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
    resources = [var.private_release_runner_connection_arn]
  }

  # Describe APIs do not support resource-level restrictions.
  statement {
    sid = "DescribeOnlyCodeBuildVpcNetworkConfiguration"
    actions = [
      "ec2:DescribeDhcpOptions",
      "ec2:DescribeNetworkInterfaces",
      "ec2:DescribeSecurityGroups",
      "ec2:DescribeSubnets",
      "ec2:DescribeVpcs",
    ]
    resources = ["*"]
  }

  # Create/Delete are required for the VPC build attachment. AWS does not
  # expose a stable resource ARN for CreateNetworkInterface authorization.
  statement {
    sid       = "ManageOnlyCodeBuildVpcNetworkInterfaces"
    actions   = ["ec2:CreateNetworkInterface", "ec2:DeleteNetworkInterface"]
    resources = ["*"]
  }

  # Unlike network-interface creation, permission delegation supports an ENI
  # resource and service/subnet conditions. Keep the delegation confined to
  # ENIs for this runner's selected private subnets and CodeBuild service.
  statement {
    sid       = "DelegateOnlyCodeBuildVpcNetworkInterfacePermission"
    actions   = ["ec2:CreateNetworkInterfacePermission"]
    resources = ["arn:aws:ec2:${var.aws_region}:${var.aws_account_id}:network-interface/*"]

    condition {
      test     = "StringEquals"
      variable = "ec2:AuthorizedService"
      values   = ["codebuild.amazonaws.com"]
    }

    condition {
      test     = "ForAllValues:StringEquals"
      variable = "ec2:Subnet"
      values   = var.private_release_runner_subnet_ids
    }
  }
}

resource "aws_iam_role_policy" "private_release_runner" {
  count  = var.enable_private_release_runner ? 1 : 0
  name   = "${local.name_prefix}-private-release-runner"
  role   = aws_iam_role.private_release_runner[0].id
  policy = data.aws_iam_policy_document.private_release_runner[0].json
}

resource "aws_codebuild_project" "private_release_runner" {
  count         = var.enable_private_release_runner ? 1 : 0
  name          = "${local.name_prefix}-private-release"
  description   = "Repository-scoped ephemeral GitHub Actions release runner with private Vault access"
  service_role  = aws_iam_role.private_release_runner[0].arn
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
    subnets            = var.private_release_runner_subnet_ids
    security_group_ids = [aws_security_group.private_release_runner[0].id]
  }

  # AWS CodeBuild's GitHub Actions runner documentation requires a GITHUB
  # source for a repository-scoped WORKFLOW_JOB_QUEUED webhook. CodeBuild
  # replaces this buildspec while it starts each ephemeral runner job.
  source {
    type      = "GITHUB"
    location  = "https://github.com/${var.github_repository}"
    buildspec = "version: 0.2\nphases:\n  build:\n    commands:\n      - echo \"BuildSpec will be overloaded for GHA self-hosted runner builds.\"\n"

    auth {
      type     = "CODECONNECTIONS"
      resource = var.private_release_runner_connection_arn
    }
  }

  lifecycle {
    precondition {
      condition = (
        var.private_release_runner_connection_arn != "" &&
        can(regex("^arn:aws:codeconnections:${var.aws_region}:${var.aws_account_id}:connection/[0-9a-f-]{36}$", var.private_release_runner_connection_arn)) &&
        length(var.private_release_runner_subnet_ids) > 0 &&
        alltrue([for subnet_id in var.private_release_runner_subnet_ids : can(regex("^subnet-[a-z0-9]+$", subnet_id))])
      )
      error_message = "Enabled private release runner requires the approved same-account CodeConnections ARN and explicit current private subnet IDs."
    }
  }

  tags = local.common_tags

  depends_on = [aws_iam_role_policy.private_release_runner]
}

resource "aws_codebuild_webhook" "private_release_runner" {
  count        = var.enable_private_release_runner ? 1 : 0
  project_name = aws_codebuild_project.private_release_runner[0].name
  build_type   = "BUILD"

  # Event filtering starts an ephemeral runner but cannot itself distinguish
  # trusted tag jobs from queued PR jobs. GitHub Environment protection and
  # Vault claim validation remain the release-admission boundary to review.
  filter_group {
    filter {
      type    = "EVENT"
      pattern = "WORKFLOW_JOB_QUEUED"
    }
  }
}

output "private_release_runner_project_name" {
  description = "Repository-scoped private release runner project, or null while disabled."
  value       = try(aws_codebuild_project.private_release_runner[0].name, null)
}

output "release_signer_project_name" {
  description = "Private release signer project name, or null while the signer is disabled."
  value       = try(aws_codebuild_project.release_signer[0].name, null)
}
