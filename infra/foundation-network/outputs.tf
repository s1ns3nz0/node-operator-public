output "network" {
  value = {
    vpc_id                = local.vpc_id
    vpc_cidr              = local.existing_mode ? data.aws_vpc.existing[0].cidr_block : aws_vpc.this[0].cidr_block
    system_subnet_ids     = local.private_subnet_ids
    hoodi_subnet_ids      = local.existing_mode ? [] : [aws_subnet.hoodi[0].id]
    system_route_table_id = local.private_route_table
    hoodi_route_table_id  = local.existing_mode ? null : aws_route_table.hoodi[0].id
    hoodi_nat_gateway_id  = aws_nat_gateway.hoodi.id
    hoodi_nat_public_ip   = aws_eip.hoodi_nat.public_ip
  }
}

output "existing_network_ownership" {
  description = "Baseline references are data only; existing mode manages only its reviewed public NAT edge after separately approved imports."
  value = local.existing_mode ? {
    mode = "existing"
    referenced = {
      vpc_id                 = data.aws_vpc.existing[0].id
      private_subnet_ids     = [for subnet in data.aws_subnet.existing_private : subnet.id]
      private_route_table_id = data.aws_route_table.existing_private[0].id
    }
    managed_import_addresses = [
      "aws_subnet.nat",
      "aws_eip.hoodi_nat",
      "aws_internet_gateway.nat",
      "aws_route_table.public",
      "aws_route_table_association.public",
      "aws_nat_gateway.hoodi",
    ]
  } : null
}
