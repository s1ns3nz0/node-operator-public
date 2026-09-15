terraform {
  required_version = ">= 1.5.0, < 2.0.0"

  # Recovery state is deliberately separate from every live workload state.
  # Supply the reviewed remote backend only with -backend-config=backend.hcl.
  backend "s3" {}

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.31.0, < 6.0.0"
    }
  }
}

provider "aws" {
  region              = var.aws_region
  allowed_account_ids = [var.aws_account_id]
  default_tags { tags = local.tags }
}

data "aws_ami" "ecs_al2023" {
  most_recent = false
  owners      = ["591542846629"]

  filter {
    name   = "image-id"
    values = [var.ami_id]
  }
  filter {
    name   = "architecture"
    values = ["x86_64"]
  }
  filter {
    name   = "root-device-type"
    values = ["ebs"]
  }
  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
  filter {
    name   = "state"
    values = ["available"]
  }
  filter {
    name   = "name"
    values = ["al2023-ami-ecs-hvm-*"]
  }
}

data "aws_prefix_list" "s3" {
  name = "com.amazonaws.${var.aws_region}.s3"
}

locals {
  name_prefix = "${var.name}-vault-recovery"
  tags = {
    ManagedBy        = "terraform"
    Project          = "node-operator"
    Deployment       = var.name
    DeploymentRegion = var.aws_region
    Purpose          = "vault-isolated-recovery"
    RecoveryExpiry   = var.recovery_expiry
    Isolation        = "dedicated-vpc-no-internet-or-peering"
  }
  repository_arns = [
    "arn:aws:ecr:${var.aws_region}:${var.aws_account_id}:repository/node-operator-baseline-gitops-vault",
    "arn:aws:ecr:${var.aws_region}:${var.aws_account_id}:repository/node-operator-baseline-vault-runtime-server",
  ]
  snapshot_object_arn = "arn:aws:s3:::${var.snapshot_bucket}/${var.snapshot_key}"
  starport_object_arn = "arn:aws:s3:::prod-${var.aws_region}-starport-layer-bucket/*"
  flow_log_group_name = "/aws/vpc/${local.name_prefix}/flow-logs"
  flow_log_group_arn  = "arn:aws:logs:${var.aws_region}:${var.aws_account_id}:log-group:${local.flow_log_group_name}"
}

resource "aws_vpc" "recovery" {
  cidr_block           = "10.91.0.0/24"
  enable_dns_hostnames = true
  enable_dns_support   = true
  tags                 = merge(local.tags, { Name = local.name_prefix })
}

# This resource adopts only the default group created alongside this new VPC;
# it has no relationship to any live or pre-existing default security group.
resource "aws_default_security_group" "recovery" {
  vpc_id  = aws_vpc.recovery.id
  ingress = []
  egress  = []
  tags    = merge(local.tags, { Name = "${local.name_prefix}-default-deny" })
}

resource "aws_kms_key" "flow_logs" {
  description             = "Isolated Vault recovery VPC flow log encryption"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "EnableAccountIamAdministration"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::${var.aws_account_id}:root" }
        Action    = "kms:*"
        Resource  = "*"
      },
      {
        Sid       = "EncryptOnlyRecoveryFlowLogs"
        Effect    = "Allow"
        Principal = { Service = "logs.${var.aws_region}.amazonaws.com" }
        Action    = ["kms:Encrypt", "kms:Decrypt", "kms:ReEncrypt*", "kms:GenerateDataKey*", "kms:DescribeKey"]
        Resource  = "*"
        Condition = { ArnEquals = { "kms:EncryptionContext:aws:logs:arn" = local.flow_log_group_arn } }
      },
    ]
  })
  tags = merge(local.tags, { Name = "${local.name_prefix}-flow-logs" })
}

resource "aws_cloudwatch_log_group" "flow_logs" {
  name              = local.flow_log_group_name
  retention_in_days = 365
  kms_key_id        = aws_kms_key.flow_logs.arn
  tags              = local.tags
}

data "aws_iam_policy_document" "flow_logs_assume_role" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["vpc-flow-logs.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [var.aws_account_id]
    }
    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = ["arn:aws:ec2:${var.aws_region}:${var.aws_account_id}:vpc-flow-log/*"]
    }
  }
}

resource "aws_iam_role" "flow_logs" {
  name               = "${local.name_prefix}-flow-logs"
  assume_role_policy = data.aws_iam_policy_document.flow_logs_assume_role.json
  tags               = local.tags
}

data "aws_iam_policy_document" "flow_logs" {
  statement {
    effect    = "Allow"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.flow_logs.arn}:*"]
  }
}

resource "aws_iam_role_policy" "flow_logs" {
  name   = "${local.name_prefix}-flow-logs"
  role   = aws_iam_role.flow_logs.id
  policy = data.aws_iam_policy_document.flow_logs.json
}

resource "aws_flow_log" "recovery" {
  vpc_id               = aws_vpc.recovery.id
  traffic_type         = "ALL"
  log_destination_type = "cloud-watch-logs"
  log_destination      = aws_cloudwatch_log_group.flow_logs.arn
  iam_role_arn         = aws_iam_role.flow_logs.arn
  depends_on           = [aws_iam_role_policy.flow_logs]
  tags                 = local.tags
}

resource "aws_subnet" "recovery" {
  vpc_id                  = aws_vpc.recovery.id
  cidr_block              = "10.91.0.0/25"
  availability_zone       = var.availability_zone
  map_public_ip_on_launch = false
  tags                    = merge(local.tags, { Name = "${local.name_prefix}-private" })
}

# A VPC route table always includes its implicit local route. This root creates
# no IGW, NAT, peering, transit attachment, or non-local route.
resource "aws_route_table" "recovery" {
  vpc_id = aws_vpc.recovery.id
  tags   = merge(local.tags, { Name = "${local.name_prefix}-private" })
}

resource "aws_route_table_association" "recovery" {
  subnet_id      = aws_subnet.recovery.id
  route_table_id = aws_route_table.recovery.id
}

resource "aws_security_group" "host" {
  name_prefix = "${local.name_prefix}-host-"
  description = "No-ingress recovery host; egress only to approved private endpoints and S3 prefix list."
  vpc_id      = aws_vpc.recovery.id
  # This direction is explicitly denied inline; standalone rules exclusively own host egress.
  ingress = []
  tags    = merge(local.tags, { Name = "${local.name_prefix}-host" })
}

resource "aws_security_group" "endpoints" {
  name_prefix = "${local.name_prefix}-endpoints-"
  description = "Private AWS endpoint ingress only from the isolated recovery host."
  vpc_id      = aws_vpc.recovery.id
  # This direction is explicitly denied inline; standalone rules exclusively own endpoint ingress.
  egress = []
  tags   = merge(local.tags, { Name = "${local.name_prefix}-endpoints" })
}

resource "aws_vpc_security_group_ingress_rule" "endpoint_https_from_host" {
  security_group_id            = aws_security_group.endpoints.id
  referenced_security_group_id = aws_security_group.host.id
  description                  = "HTTPS only from the isolated recovery host"
  from_port                    = 443
  to_port                      = 443
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "host_to_endpoints" {
  security_group_id            = aws_security_group.host.id
  referenced_security_group_id = aws_security_group.endpoints.id
  description                  = "HTTPS only to approved interface endpoints"
  from_port                    = 443
  to_port                      = 443
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "host_to_s3" {
  security_group_id = aws_security_group.host.id
  prefix_list_id    = data.aws_prefix_list.s3.id
  description       = "HTTPS only to the regional S3 managed prefix list"
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
}

data "aws_iam_policy_document" "ssm_endpoint" {
  statement {
    sid    = "OnlyRecoveryHost"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = [aws_iam_role.host.arn]
    }
    actions   = ["ssm:UpdateInstanceInformation"]
    resources = ["arn:aws:ec2:${var.aws_region}:${var.aws_account_id}:instance/*", "arn:aws:ssm:${var.aws_region}:${var.aws_account_id}:instance/*", "arn:aws:ssm:${var.aws_region}:${var.aws_account_id}:managed-instance/mi-*"]
    condition {
      test     = "StringEquals"
      variable = "aws:SourceVpc"
      values   = [aws_vpc.recovery.id]
    }
  }
}

data "aws_iam_policy_document" "ssmmessages_endpoint" {
  statement {
    sid    = "OnlyRecoveryHostSessionChannels"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = [aws_iam_role.host.arn]
    }
    actions   = ["ssmmessages:CreateControlChannel", "ssmmessages:CreateDataChannel", "ssmmessages:OpenControlChannel", "ssmmessages:OpenDataChannel"]
    resources = ["*"]
  }
}

data "aws_iam_policy_document" "ec2messages_endpoint" {
  statement {
    sid    = "OnlyRecoveryHostMessageChannel"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = [aws_iam_role.host.arn]
    }
    actions   = ["ec2messages:AcknowledgeMessage", "ec2messages:DeleteMessage", "ec2messages:FailMessage", "ec2messages:GetEndpoint", "ec2messages:GetMessages", "ec2messages:SendReply"]
    resources = ["*"]
  }
}

data "aws_iam_policy_document" "kms_endpoint" {
  statement {
    sid    = "OnlyRequiredRecoveryKmsOperations"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = [aws_iam_role.host.arn]
    }
    actions   = ["kms:Decrypt"]
    resources = [var.snapshot_kms_key_arn]
    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["s3.${var.aws_region}.amazonaws.com"]
    }
    condition {
      test     = "StringLike"
      variable = "kms:EncryptionContext:aws:s3:arn"
      values   = [local.snapshot_object_arn, "arn:aws:s3:::${var.snapshot_bucket}"]
    }
  }
  statement {
    sid    = "DescribeExactSnapshotKey"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = [aws_iam_role.host.arn]
    }
    actions   = ["kms:DescribeKey"]
    resources = [var.snapshot_kms_key_arn]
  }
  statement {
    sid    = "OnlyRequiredAutoUnsealKmsOperations"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = [aws_iam_role.host.arn]
    }
    actions   = ["kms:Encrypt", "kms:Decrypt", "kms:DescribeKey"]
    resources = [var.auto_unseal_kms_key_arn]
  }
}

data "aws_iam_policy_document" "ecr_endpoint" {
  statement {
    sid    = "TokenForRecoveryHostOnly"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = [aws_iam_role.host.arn]
    }
    actions   = ["ecr:GetAuthorizationToken"]
    resources = ["*"]
  }
  statement {
    sid    = "ReadOnlyApprovedRecoveryRepositories"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = [aws_iam_role.host.arn]
    }
    actions   = ["ecr:BatchCheckLayerAvailability", "ecr:BatchGetImage", "ecr:DescribeImages", "ecr:GetDownloadUrlForLayer"]
    resources = local.repository_arns
  }
}

data "aws_iam_policy_document" "s3_endpoint" {
  statement {
    sid    = "ReadOnlyExactSnapshotVersion"
    effect = "Allow"
    # Gateway endpoints require a wildcard Principal. The mandatory exact ARN
    # condition below retains the recovery-role boundary for assumed sessions.
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
    actions   = ["s3:GetObjectVersion"]
    resources = [local.snapshot_object_arn]
    condition {
      test     = "StringEquals"
      variable = "aws:PrincipalArn"
      values   = [aws_iam_role.host.arn]
    }
    condition {
      test     = "StringEquals"
      variable = "s3:VersionId"
      values   = [var.snapshot_version_id]
    }
  }
  statement {
    sid    = "ReadEcrLayerObjectsOnly"
    effect = "Allow"
    # ECR serves image layers through presigned S3 URLs. The request principal
    # at this gateway endpoint is therefore not the host role; resource scope
    # remains the documented regional ECR layer bucket only.
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
    actions   = ["s3:GetObject"]
    resources = [local.starport_object_arn]
  }
}

resource "aws_vpc_endpoint" "interface" {
  for_each = {
    ssm         = data.aws_iam_policy_document.ssm_endpoint.json
    ssmmessages = data.aws_iam_policy_document.ssmmessages_endpoint.json
    ec2messages = data.aws_iam_policy_document.ec2messages_endpoint.json
    kms         = data.aws_iam_policy_document.kms_endpoint.json
    "ecr.api"   = data.aws_iam_policy_document.ecr_endpoint.json
    "ecr.dkr"   = data.aws_iam_policy_document.ecr_endpoint.json
  }

  vpc_id              = aws_vpc.recovery.id
  service_name        = "com.amazonaws.${var.aws_region}.${each.key}"
  vpc_endpoint_type   = "Interface"
  private_dns_enabled = true
  subnet_ids          = [aws_subnet.recovery.id]
  security_group_ids  = [aws_security_group.endpoints.id]
  policy              = each.value
  tags                = merge(local.tags, { Name = "${local.name_prefix}-${replace(each.key, ".", "-")}" })
}

resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.recovery.id
  service_name      = "com.amazonaws.${var.aws_region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.recovery.id]
  policy            = data.aws_iam_policy_document.s3_endpoint.json
  tags              = merge(local.tags, { Name = "${local.name_prefix}-s3" })
}

data "aws_iam_policy_document" "host_assume_role" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "host" {
  name               = local.name_prefix
  assume_role_policy = data.aws_iam_policy_document.host_assume_role.json
  tags               = local.tags
}

data "aws_iam_policy_document" "host" {
  # This is intentionally not AmazonSSMManagedInstanceCore. It permits only
  # the managed-instance registration and channel/update operations needed by
  # the SSM agent, with no Parameter Store or secret-read permissions.
  statement {
    sid       = "SsmManagedInstanceChannels"
    effect    = "Allow"
    actions   = ["ssmmessages:CreateControlChannel", "ssmmessages:CreateDataChannel", "ssmmessages:OpenControlChannel", "ssmmessages:OpenDataChannel", "ec2messages:AcknowledgeMessage", "ec2messages:DeleteMessage", "ec2messages:FailMessage", "ec2messages:GetEndpoint", "ec2messages:GetMessages", "ec2messages:SendReply"]
    resources = ["*"]
  }
  statement {
    sid       = "SsmUpdateOnlyFromRecoveryVpc"
    effect    = "Allow"
    actions   = ["ssm:UpdateInstanceInformation"]
    resources = ["arn:aws:ec2:${var.aws_region}:${var.aws_account_id}:instance/*", "arn:aws:ssm:${var.aws_region}:${var.aws_account_id}:instance/*", "arn:aws:ssm:${var.aws_region}:${var.aws_account_id}:managed-instance/mi-*"]
    condition {
      test     = "StringEquals"
      variable = "aws:SourceVpc"
      values   = [aws_vpc.recovery.id]
    }
  }
  statement {
    sid       = "ReadExactSnapshotVersion"
    effect    = "Allow"
    actions   = ["s3:GetObjectVersion"]
    resources = [local.snapshot_object_arn]
    condition {
      test     = "StringEquals"
      variable = "s3:VersionId"
      values   = [var.snapshot_version_id]
    }
  }
  statement {
    sid       = "ReadEcrLayerObjectsOnly"
    effect    = "Allow"
    actions   = ["s3:GetObject"]
    resources = [local.starport_object_arn]
  }
  statement {
    sid       = "DecryptSnapshotOnlyThroughS3ForExactObject"
    effect    = "Allow"
    actions   = ["kms:Decrypt"]
    resources = [var.snapshot_kms_key_arn]
    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["s3.${var.aws_region}.amazonaws.com"]
    }
    condition {
      test     = "StringLike"
      variable = "kms:EncryptionContext:aws:s3:arn"
      # S3 Bucket Keys use the bucket ARN rather than the object ARN in this
      # encryption context. S3 access remains limited to the exact object and
      # exact version in the preceding S3 statement.
      values = [local.snapshot_object_arn, "arn:aws:s3:::${var.snapshot_bucket}"]
    }
  }
  statement {
    sid       = "DescribeExactSnapshotKey"
    effect    = "Allow"
    actions   = ["kms:DescribeKey"]
    resources = [var.snapshot_kms_key_arn]
  }
  statement {
    sid       = "AutoUnsealOnly"
    effect    = "Allow"
    actions   = ["kms:Encrypt", "kms:Decrypt", "kms:DescribeKey"]
    resources = [var.auto_unseal_kms_key_arn]
  }
  statement {
    sid       = "ReadOnlyApprovedRecoveryRepositories"
    effect    = "Allow"
    actions   = ["ecr:BatchCheckLayerAvailability", "ecr:BatchGetImage", "ecr:DescribeImages", "ecr:GetDownloadUrlForLayer"]
    resources = local.repository_arns
  }
  statement {
    sid       = "EcrAuthorizationToken"
    effect    = "Allow"
    actions   = ["ecr:GetAuthorizationToken"]
    resources = ["*"]
  }
  # Expiry is an authorization boundary, not merely an inventory tag. This
  # explicit deny also wins over any separately issued temporary KMS grant.
  statement {
    sid       = "DenySnapshotReadAfterRecoveryExpiry"
    effect    = "Deny"
    actions   = ["s3:GetObjectVersion"]
    resources = [local.snapshot_object_arn]
    condition {
      test     = "DateGreaterThanEquals"
      variable = "aws:CurrentTime"
      values   = [var.recovery_expiry]
    }
  }
  statement {
    sid       = "DenyKmsUseAfterRecoveryExpiry"
    effect    = "Deny"
    actions   = ["kms:Encrypt", "kms:Decrypt", "kms:DescribeKey"]
    resources = [var.snapshot_kms_key_arn, var.auto_unseal_kms_key_arn]
    condition {
      test     = "DateGreaterThanEquals"
      variable = "aws:CurrentTime"
      values   = [var.recovery_expiry]
    }
  }
}

resource "aws_iam_role_policy" "host" {
  name   = "${local.name_prefix}-least-privilege"
  role   = aws_iam_role.host.id
  policy = data.aws_iam_policy_document.host.json
}

resource "aws_iam_instance_profile" "host" {
  name = local.name_prefix
  role = aws_iam_role.host.name
}

resource "aws_instance" "host" {
  ami                         = data.aws_ami.ecs_al2023.id
  instance_type               = "t3.small"
  availability_zone           = var.availability_zone
  subnet_id                   = aws_subnet.recovery.id
  associate_public_ip_address = false
  iam_instance_profile        = aws_iam_instance_profile.host.name
  vpc_security_group_ids      = [aws_security_group.host.id]
  monitoring                  = false
  ebs_optimized               = true

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  root_block_device {
    delete_on_termination = true
    encrypted             = true
    volume_type           = "gp3"
    volume_size           = var.root_volume_size_gib
  }

  # No snapshot, credential, token, or recovery action is fetched or run here.
  user_data = <<-USERDATA
    #!/bin/bash
    set -eu
    systemctl mask --now ecs.service || true
    systemctl enable --now docker.service amazon-ssm-agent.service
    command -v docker aws curl amazon-ssm-agent >/dev/null
  USERDATA

  tags = merge(local.tags, { Name = "${local.name_prefix}-host" })

  depends_on = [aws_iam_role_policy.host, aws_vpc_endpoint.interface, aws_vpc_endpoint.s3]

  lifecycle {
    precondition {
      condition     = data.aws_ami.ecs_al2023.owner_id == "591542846629" && data.aws_ami.ecs_al2023.architecture == "x86_64" && can(regex("^al2023-ami-ecs-hvm-", lower(data.aws_ami.ecs_al2023.name)))
      error_message = "ami_id must resolve to an Amazon-owned x86_64 ECS AL2023 AMI."
    }
    precondition {
      condition     = can(regex("^arn:aws:kms:${var.aws_region}:${var.aws_account_id}:key/[A-Za-z0-9-]+$", var.snapshot_kms_key_arn)) && can(regex("^arn:aws:kms:${var.aws_region}:${var.aws_account_id}:key/[A-Za-z0-9-]+$", var.auto_unseal_kms_key_arn)) && var.auto_unseal_kms_key_arn != var.snapshot_kms_key_arn
      error_message = "Both KMS key ARNs must be distinct exact keys in the selected account and region."
    }
  }
}
