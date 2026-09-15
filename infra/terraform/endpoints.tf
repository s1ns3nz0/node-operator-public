# These endpoints give private managed nodes the AWS control-plane paths needed
# during bootstrap without introducing a NAT gateway or public internet route.
# STS and CloudWatch Logs become required with either VPC-internal CodeBuild
# executor. The Argo CD executor additionally calls the EKS management API to
# obtain the private cluster endpoint. Neither executor has public egress. The
# Vault client-CA endpoint is pre-existing and intentionally retained outside
# this module's endpoint inventory until its state import can be reviewed.
locals {
  baseline_interface_endpoint_services = toset([
    "ec2",
    "ecr.api",
    "ecr.dkr",
    "eks-auth",
    "kms",
    # The validator observability collector is private-only and writes its
    # short-retention operational stream to CloudWatch Logs.
    "logs",
  ])

  required_interface_endpoint_services = setunion(
    local.baseline_interface_endpoint_services,
    (var.enable_release_signer || var.enable_argocd_bootstrap_runner || var.enable_vault_bootstrap_runner) ? toset(["logs", "sts"]) : toset([]),
    (var.enable_argocd_bootstrap_runner || var.enable_vault_bootstrap_runner) ? toset(["eks"]) : toset([]),
    var.enable_temporary_ssm_ops_host ? toset(["ssm", "ssmmessages", "ec2messages"]) : toset([]),
  )
}

resource "aws_security_group" "endpoints" {
  name_prefix = "${local.name_prefix}-endpoints-"
  description = "HTTPS access to required VPC interface endpoints from managed nodes only."
  vpc_id      = local.network_vpc_id

  # Security groups are stateful: response traffic for allowed node requests
  # does not need a separate outbound rule. An explicit empty value removes
  # AWS's default allow-all egress rule.
  egress = []

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-endpoints"
  })
}

resource "aws_vpc_security_group_ingress_rule" "endpoints_https_from_nodes" {
  description                  = "HTTPS from managed nodes to VPC interface endpoints"
  security_group_id            = aws_security_group.endpoints.id
  referenced_security_group_id = aws_security_group.nodes.id
  from_port                    = 443
  to_port                      = 443
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "endpoints_https_from_hoodi_nodes" {
  description                  = "HTTPS from Hoodi nodes to VPC interface endpoints"
  security_group_id            = aws_security_group.endpoints.id
  referenced_security_group_id = aws_security_group.hoodi_nodes.id
  from_port                    = 443
  to_port                      = 443
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "endpoints_https_from_release_signer" {
  count                        = var.enable_release_signer ? 1 : 0
  description                  = "HTTPS from private release signer to VPC interface endpoints"
  security_group_id            = aws_security_group.endpoints.id
  referenced_security_group_id = aws_security_group.release_signer[0].id
  from_port                    = 443
  to_port                      = 443
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "endpoints_https_from_argocd_bootstrap" {
  count                        = var.enable_argocd_bootstrap_runner ? 1 : 0
  description                  = "HTTPS from private Argo CD bootstrap executor to VPC interface endpoints"
  security_group_id            = aws_security_group.endpoints.id
  referenced_security_group_id = aws_security_group.argocd_bootstrap[0].id
  from_port                    = 443
  to_port                      = 443
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "endpoints_https_from_vault_bootstrap" {
  count                        = var.enable_vault_bootstrap_runner ? 1 : 0
  description                  = "HTTPS from private Vault bootstrap executor to VPC interface endpoints"
  security_group_id            = aws_security_group.endpoints.id
  referenced_security_group_id = aws_security_group.vault_bootstrap[0].id
  from_port                    = 443
  to_port                      = 443
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "endpoints_https_from_temporary_ssm_ops_host" {
  count                        = var.enable_temporary_ssm_ops_host ? 1 : 0
  description                  = "HTTPS from the temporary SSM operations host to interface endpoints"
  security_group_id            = aws_security_group.endpoints.id
  referenced_security_group_id = aws_security_group.temporary_ssm_ops_host[0].id
  from_port                    = 443
  to_port                      = 443
  ip_protocol                  = "tcp"
}

resource "aws_vpc_endpoint" "required_interface" {
  for_each = local.required_interface_endpoint_services

  vpc_id              = local.network_vpc_id
  service_name        = "com.amazonaws.${var.aws_region}.${each.value}"
  vpc_endpoint_type   = "Interface"
  private_dns_enabled = true
  subnet_ids          = local.system_subnet_ids
  security_group_ids  = [aws_security_group.endpoints.id]

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-${replace(each.value, ".", "-")}-endpoint"
  })
}

resource "aws_vpc_endpoint" "s3" {
  vpc_id            = local.network_vpc_id
  service_name      = "com.amazonaws.${var.aws_region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [local.system_route_table_id]

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-s3-endpoint"
  })
}
