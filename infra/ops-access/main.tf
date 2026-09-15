terraform {
  required_version = ">= 1.5.0, < 2.0.0"
  # Every operations-access deployment uses an explicit, isolated S3 backend
  # supplied at init time.  Do not let a release invocation create local state.
  backend "s3" {}
  required_providers { aws = { source = "hashicorp/aws", version = ">= 5.31.0, < 6.0.0" } }
}

provider "aws" {
  region = var.aws_region
  default_tags {
    tags = { ManagedBy = "terraform", Project = "node-operator", Deployment = var.name, DeploymentRegion = var.aws_region, Purpose = "ops-access" }
  }
}

data "aws_ssm_parameter" "al2023" { name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64" }

locals {
  create_ssm_endpoints       = var.existing_ssm_endpoint_security_group_id == null
  endpoint_security_group_id = local.create_ssm_endpoints ? aws_security_group.endpoints[0].id : var.existing_ssm_endpoint_security_group_id
}

resource "aws_security_group" "host" {
  name_prefix = "${var.name}-ops-access-"
  description = "No-ingress temporary private EKS operations host."
  vpc_id      = var.vpc_id
  ingress     = []
  tags        = { ManagedBy = "terraform", Project = "node-operator", Purpose = "ops-access" }
}

resource "aws_security_group" "endpoints" {
  count       = local.create_ssm_endpoints ? 1 : 0
  name_prefix = "${var.name}-ops-access-endpoints-"
  description = "Private Session Manager endpoints for the temporary operations host."
  vpc_id      = var.vpc_id
  egress      = []
  tags        = { ManagedBy = "terraform", Project = "node-operator", Purpose = "ops-access" }
}

resource "aws_vpc_security_group_ingress_rule" "endpoints" {
  description                  = "HTTPS from the temporary operations host to SSM endpoints"
  count                        = local.create_ssm_endpoints || var.manage_existing_endpoint_ingress_rule ? 1 : 0
  security_group_id            = local.endpoint_security_group_id
  referenced_security_group_id = aws_security_group.host.id
  from_port                    = 443
  to_port                      = 443
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "to_endpoints" {
  description                  = "HTTPS to private Session Manager endpoints"
  security_group_id            = aws_security_group.host.id
  referenced_security_group_id = local.endpoint_security_group_id
  from_port                    = 443
  to_port                      = 443
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "to_cluster" {
  description                  = "HTTPS to the private EKS API"
  security_group_id            = aws_security_group.host.id
  referenced_security_group_id = var.cluster_security_group_id
  from_port                    = 443
  to_port                      = 443
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "cluster" {
  description                  = "Private EKS API access from the temporary operations host"
  count                        = var.manage_cluster_ingress_rule ? 1 : 0
  security_group_id            = var.cluster_security_group_id
  referenced_security_group_id = aws_security_group.host.id
  from_port                    = 443
  to_port                      = 443
  ip_protocol                  = "tcp"
}

resource "aws_vpc_endpoint" "ssm" {
  for_each            = local.create_ssm_endpoints ? toset(["ssm", "ssmmessages", "ec2messages"]) : toset([])
  vpc_id              = var.vpc_id
  service_name        = "com.amazonaws.${var.aws_region}.${each.value}"
  vpc_endpoint_type   = "Interface"
  private_dns_enabled = true
  subnet_ids          = [var.subnet_id]
  # This resource exists only when we create the endpoints. Keep its direct
  # attachment visible to IaC graph analyzers as well as Terraform.
  security_group_ids = [aws_security_group.endpoints[0].id]
}

# The initial separately deployed host used uncounted ingress addresses.
# Retain those exact rules when adopting the root's conditional ownership.
moved {
  from = aws_vpc_security_group_ingress_rule.endpoints
  to   = aws_vpc_security_group_ingress_rule.endpoints[0]
}

moved {
  from = aws_vpc_security_group_ingress_rule.cluster
  to   = aws_vpc_security_group_ingress_rule.cluster[0]
}

resource "aws_iam_role" "host" {
  name               = "${var.name}-ops-access"
  assume_role_policy = jsonencode({ Version = "2012-10-17", Statement = [{ Effect = "Allow", Principal = { Service = "ec2.amazonaws.com" }, Action = "sts:AssumeRole" }] })
}

resource "aws_iam_role_policy_attachment" "ssm" {
  role       = aws_iam_role.host.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "host" {
  name = "${var.name}-ops-access"
  role = aws_iam_role.host.name
}

resource "aws_instance" "host" {
  ami           = data.aws_ssm_parameter.al2023.value
  instance_type = "t3.micro"
  # Basic EC2 monitoring is sufficient for this SSM-only operations host.
  monitoring = false
  # New and resumed deployments use their own managed, hardened host.
  ebs_optimized                        = var.ebs_optimized
  subnet_id                            = var.subnet_id
  associate_public_ip_address          = false
  iam_instance_profile                 = aws_iam_instance_profile.host.name
  vpc_security_group_ids               = [aws_security_group.host.id]
  instance_initiated_shutdown_behavior = "terminate"
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }
  root_block_device {
    encrypted   = true
    volume_type = "gp3"
    volume_size = 8
    tags        = { ManagedBy = "terraform", Project = "node-operator", Deployment = var.name, DeploymentRegion = var.aws_region }
  }
  tags       = { ManagedBy = "terraform", Project = "node-operator", Purpose = "ops-access" }
  depends_on = [aws_iam_role_policy_attachment.ssm, aws_vpc_endpoint.ssm]

  lifecycle {
    precondition {
      condition     = var.ebs_optimized
      error_message = "EBS optimization must remain enabled for deployment-managed hosts."
    }
  }
}

output "instance_id" { value = aws_instance.host.id }
