# Pod ENIs inherit these node-pool security groups. NetworkPolicies retain
# workload-selector restrictions; these rules only permit the required paths
# between pools, without public/CIDR ingress or general cross-pool access.
resource "aws_vpc_security_group_ingress_rule" "hoodi_validator_signer_from_system" {
  description                  = "Private validator fence and identity probe to signer"
  security_group_id            = aws_security_group.hoodi_nodes.id
  referenced_security_group_id = aws_security_group.nodes.id
  from_port                    = 9000
  to_port                      = 9000
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "system_validator_db_from_hoodi" {
  description                  = "Private validator signer to retained slashing database"
  security_group_id            = aws_security_group.nodes.id
  referenced_security_group_id = aws_security_group.hoodi_nodes.id
  from_port                    = 5432
  to_port                      = 5432
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "hoodi_prysm_health_from_system" {
  description                  = "Private Prysm health from system-pool DAST"
  security_group_id            = aws_security_group.hoodi_nodes.id
  referenced_security_group_id = aws_security_group.nodes.id
  from_port                    = 3500
  to_port                      = 3500
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "hoodi_p2p_probe_from_system" {
  description                  = "Private Nethermind P2P reachability from system-pool proxy"
  security_group_id            = aws_security_group.hoodi_nodes.id
  referenced_security_group_id = aws_security_group.nodes.id
  from_port                    = 30303
  to_port                      = 30303
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "hoodi_vault_ha_from_system" {
  description                  = "Vault HA cluster traffic from system to Hoodi pool"
  security_group_id            = aws_security_group.hoodi_nodes.id
  referenced_security_group_id = aws_security_group.nodes.id
  from_port                    = 8201
  to_port                      = 8201
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "system_vault_ha_from_hoodi" {
  description                  = "Vault HA cluster traffic from Hoodi to system pool"
  security_group_id            = aws_security_group.nodes.id
  referenced_security_group_id = aws_security_group.hoodi_nodes.id
  from_port                    = 8201
  to_port                      = 8201
  ip_protocol                  = "tcp"
}
