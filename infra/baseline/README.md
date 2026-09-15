# Replacement baseline contract

This root is the successor to `infra/terraform`. It must consume the
`foundation_network` object and must not declare an `aws_vpc`, `aws_subnet`,
`aws_internet_gateway`, `aws_nat_gateway`, or an externally supplied NAT ID.

System EKS resources use `system_subnet_ids`; Hoodi execution and consensus
node groups use `hoodi_subnet_ids`. VPC endpoints use the system subnet and
route-table outputs. The eventual state migration is reviewed separately.
