# Private network boundary for the validator metrics collector. The collector
# is scheduled on the system node group, while the Prysm and Nethermind Pods
# are scheduled on the Hoodi node group. Security-group references keep the
# listener boundary independent of changing Pod or node IP addresses.
resource "aws_vpc_security_group_ingress_rule" "hoodi_nodes_prysm_metrics_from_nodes" {
  description                  = "Prysm metrics from system-pool validator collector nodes"
  security_group_id            = aws_security_group.hoodi_nodes.id
  referenced_security_group_id = aws_security_group.nodes.id
  from_port                    = 8080
  to_port                      = 8080
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "hoodi_nodes_nethermind_metrics_from_nodes" {
  description                  = "Nethermind metrics from system-pool validator collector nodes"
  security_group_id            = aws_security_group.hoodi_nodes.id
  referenced_security_group_id = aws_security_group.nodes.id
  from_port                    = 6060
  to_port                      = 6060
  ip_protocol                  = "tcp"
}

# The staged validator-client template has no nodeSelector. Its metrics Pod can
# therefore be scheduled on the Hoodi pool even though the collector runs on
# the system pool. The workload NetworkPolicy limits this further to the
# collector label; this rule preserves that selected private path at the node
# security-group layer.
resource "aws_vpc_security_group_ingress_rule" "hoodi_nodes_validator_client_metrics_from_nodes" {
  description                  = "Validator client metrics from system-pool validator collector nodes"
  security_group_id            = aws_security_group.hoodi_nodes.id
  referenced_security_group_id = aws_security_group.nodes.id
  from_port                    = 8081
  to_port                      = 8081
  ip_protocol                  = "tcp"
}

# Interface-endpoint ENI IDs are computed only after the endpoint is created.
# Deriving for_each from them would make the collection unknown on the first
# plan. The system-subnet indexes are stable from input instead, and each data
# source proves the ENI is both declared by the Logs endpoint and in that exact
# subnet. EC2 does not support a vpc-endpoint-id DescribeNetworkInterfaces
# filter, so use the endpoint's own ENI IDs rather than an invented filter.
locals {
  validator_metrics_logs_endpoint_subnets = {
    for index, subnet_id in local.system_subnet_ids : tostring(index) => subnet_id
  }
}

data "aws_network_interface" "validator_metrics_logs_endpoint" {
  for_each = local.validator_metrics_logs_endpoint_subnets

  filter {
    name   = "network-interface-id"
    values = tolist(aws_vpc_endpoint.required_interface["logs"].network_interface_ids)
  }

  filter {
    name   = "subnet-id"
    values = [each.value]
  }

  filter {
    name   = "interface-type"
    values = ["vpc_endpoint"]
  }
}

# The manifest/release layer consumes this output to render the collector's
# default-deny NetworkPolicy. It permits Logs only to these /32 addresses on
# 443, DNS on 53, Pod Identity on 169.254.170.23:80, and the separately
# selector-scoped Prysm/Nethermind metric paths. No CIDR-wide AWS egress is
# represented here.
output "validator_metrics_logs_endpoint_private_ips" {
  description = "CloudWatch Logs interface-endpoint ENI private IPs keyed by stable system-subnet index; use only as /32 collector egress destinations on TCP 443."
  value = {
    for index, eni in data.aws_network_interface.validator_metrics_logs_endpoint :
    index => eni.private_ip
  }
}

output "validator_metrics_logs_endpoint_bindings" {
  description = "CloudWatch Logs endpoint and subnet bindings for runtime verification with DescribeNetworkInterfaces before rendering collector NetworkPolicy /32 rules."
  value = {
    endpoint_id = aws_vpc_endpoint.required_interface["logs"].id
    subnet_ids  = local.validator_metrics_logs_endpoint_subnets
  }
}
