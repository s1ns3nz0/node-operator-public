locals {
  existing_mode  = var.network_mode == "existing"
  existing_ready = local.existing_mode && var.existing_network != null
  tags           = { ManagedBy = "terraform", Project = "node-operator", Deployment = var.name, DeploymentRegion = var.aws_region, Purpose = "zero-resource-foundation-network" }
}

# Baseline-owned objects are data only in existing mode.
data "aws_vpc" "existing" {
  count = local.existing_ready ? 1 : 0
  id    = try(var.existing_network.vpc_id, null)
}
data "aws_subnet" "existing_private" {
  for_each = local.existing_ready ? { for subnet in var.existing_network.private_subnets : subnet.id => subnet } : {}
  id       = each.value.id
}
data "aws_route_table" "existing_private" {
  count          = local.existing_ready ? 1 : 0
  route_table_id = try(var.existing_network.private_route_table_id, null)
}
data "aws_subnet" "existing_nat_public" {
  count = local.existing_ready ? 1 : 0
  id    = try(var.existing_network.nat_public_subnet_id, null)
}

resource "aws_vpc" "this" {
  count                = local.existing_mode ? 0 : 1
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true
  tags                 = merge(local.tags, { Name = "${var.name}-vpc" })
  lifecycle { prevent_destroy = true }
}

locals {
  vpc_id              = local.existing_ready ? data.aws_vpc.existing[0].id : (local.existing_mode ? null : aws_vpc.this[0].id)
  nat_subnet_cidr     = local.existing_ready ? var.existing_network.nat_public_subnet_cidr : (local.existing_mode ? null : var.public_subnet_cidr)
  nat_subnet_az       = local.existing_ready ? var.existing_network.nat_public_subnet_az : (local.existing_mode ? null : var.availability_zones[0])
  private_subnet_ids  = local.existing_ready ? [for subnet in data.aws_subnet.existing_private : subnet.id] : (local.existing_mode ? [] : aws_subnet.system[*].id)
  private_route_table = local.existing_ready ? data.aws_route_table.existing_private[0].id : (local.existing_mode ? null : aws_route_table.system[0].id)
}

# In existing mode exactly these six public-edge addresses are managed.
resource "aws_internet_gateway" "nat" {
  vpc_id = local.vpc_id
  tags   = merge(local.tags, { Name = "${var.name}-hoodi-nat-igw" })
}
resource "aws_subnet" "system" {
  count                   = local.existing_mode ? 0 : length(var.availability_zones)
  vpc_id                  = local.vpc_id
  availability_zone       = var.availability_zones[count.index]
  cidr_block              = var.system_subnet_cidrs[count.index]
  map_public_ip_on_launch = false
  tags                    = merge(local.tags, { Name = "${var.name}-private-${count.index + 1}", "kubernetes.io/role/internal-elb" = "1", "kubernetes.io/cluster/${var.name}" = "shared" })
  lifecycle { prevent_destroy = true }
}
resource "aws_subnet" "hoodi" {
  count                   = local.existing_mode ? 0 : 1
  vpc_id                  = local.vpc_id
  availability_zone       = var.availability_zones[0]
  cidr_block              = var.hoodi_subnet_cidrs
  map_public_ip_on_launch = false
  tags                    = merge(local.tags, { Name = "${var.name}-hoodi-private", "kubernetes.io/role/internal-elb" = "1", "kubernetes.io/cluster/${var.name}" = "shared" })
  lifecycle { prevent_destroy = true }
}
resource "aws_subnet" "nat" {
  vpc_id                  = local.vpc_id
  availability_zone       = local.nat_subnet_az
  cidr_block              = local.nat_subnet_cidr
  map_public_ip_on_launch = false
  tags                    = merge(local.tags, { Name = "${var.name}-hoodi-nat" })
  lifecycle {
    precondition {
      condition     = local.existing_mode ? var.existing_network != null : true
      error_message = "network_mode=existing requires existing_network; do not switch an applied fresh state into existing mode."
    }
    precondition {
      condition = local.existing_ready ? (
        data.aws_vpc.existing[0].cidr_block == var.existing_network.vpc_cidr &&
        data.aws_subnet.existing_nat_public[0].vpc_id == data.aws_vpc.existing[0].id &&
        data.aws_subnet.existing_nat_public[0].cidr_block == var.existing_network.nat_public_subnet_cidr &&
        data.aws_subnet.existing_nat_public[0].availability_zone == var.existing_network.nat_public_subnet_az &&
        length(distinct([for configured in var.existing_network.private_subnets : configured.id])) == length(var.existing_network.private_subnets) &&
        alltrue([for id, subnet in data.aws_subnet.existing_private : subnet.vpc_id == data.aws_vpc.existing[0].id && subnet.cidr_block == var.existing_network.private_subnets[index([for configured in var.existing_network.private_subnets : configured.id], id)].cidr]) &&
        data.aws_route_table.existing_private[0].vpc_id == data.aws_vpc.existing[0].id
      ) : !local.existing_mode
      error_message = "Existing inputs must have unique private subnet IDs and resolve to the declared VPC, CIDRs, private route table, and NAT public-subnet AZ."
    }
  }
}
resource "aws_eip" "hoodi_nat" {
  domain = "vpc"
  tags   = merge(local.tags, { Name = "${var.name}-hoodi-nat" })
}
resource "aws_route_table" "public" {
  vpc_id = local.vpc_id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.nat.id
  }
  tags = merge(local.tags, { Name = "${var.name}-nat-public" })
}
resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.nat.id
  route_table_id = aws_route_table.public.id
}
resource "aws_nat_gateway" "hoodi" {
  allocation_id     = aws_eip.hoodi_nat.id
  subnet_id         = aws_subnet.nat.id
  connectivity_type = "public"
  depends_on        = [aws_internet_gateway.nat]
  tags              = merge(local.tags, { Name = "${var.name}-hoodi-nat" })
}
resource "aws_route_table" "system" {
  count  = local.existing_mode ? 0 : 1
  vpc_id = local.vpc_id
  tags   = merge(local.tags, { Name = "${var.name}-system-private" })
  lifecycle { prevent_destroy = true }
}
resource "aws_route_table_association" "system" {
  count          = local.existing_mode ? 0 : length(aws_subnet.system)
  subnet_id      = aws_subnet.system[count.index].id
  route_table_id = aws_route_table.system[0].id
  lifecycle { prevent_destroy = true }
}
resource "aws_route_table" "hoodi" {
  count  = local.existing_mode ? 0 : 1
  vpc_id = local.vpc_id
  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.hoodi.id
  }
  tags = merge(local.tags, { Name = "${var.name}-private" })
  lifecycle { prevent_destroy = true }
}
resource "aws_route_table_association" "hoodi" {
  count          = local.existing_mode ? 0 : 1
  subnet_id      = aws_subnet.hoodi[0].id
  route_table_id = aws_route_table.hoodi[0].id
  lifecycle { prevent_destroy = true }
}
