variable "aws_region" {
  type    = string
  default = "ap-northeast-2"

  validation {
    condition     = can(regex("^[a-z]{2}-[a-z0-9-]+-[0-9]+$", var.aws_region))
    error_message = "aws_region must be a valid AWS commercial region identifier."
  }
}
variable "name" {
  type    = string
  default = "node-operator"

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{1,18}[a-z0-9]$", var.name))
    error_message = "name must be a 3-20 character DNS-compatible identifier so derived baseline resource names remain valid."
  }
}

variable "network_mode" {
  description = "fresh creates the complete foundation network; existing manages only the reviewed public NAT edge."
  type        = string
  default     = "fresh"

  validation {
    condition     = contains(["fresh", "existing"], var.network_mode)
    error_message = "network_mode must be either fresh or existing."
  }
}

variable "existing_network" {
  description = "Existing-mode identifiers and CIDRs. These have no account-specific defaults and require review before import or apply."
  type = object({
    vpc_id                 = string
    vpc_cidr               = string
    private_subnets        = list(object({ id = string, cidr = string }))
    private_route_table_id = string
    nat_public_subnet_id   = string
    nat_public_subnet_cidr = string
    nat_public_subnet_az   = string
  })
  default = null

  validation {
    condition = var.existing_network == null ? true : (
      can(cidrnetmask(var.existing_network.vpc_cidr)) &&
      can(cidrnetmask(var.existing_network.nat_public_subnet_cidr)) &&
      length(var.existing_network.private_subnets) > 0 &&
      length(distinct([for subnet in var.existing_network.private_subnets : subnet.id])) == length(var.existing_network.private_subnets) &&
      alltrue([for subnet in var.existing_network.private_subnets : can(cidrnetmask(subnet.cidr)) && length(subnet.id) > 0]) &&
      length(var.existing_network.vpc_id) > 0 &&
      length(var.existing_network.private_route_table_id) > 0 &&
      length(var.existing_network.nat_public_subnet_id) > 0 &&
      length(var.existing_network.nat_public_subnet_az) > 0
    )
    error_message = "existing_network requires VPC/CIDR, private subnet CIDRs, a private route table, and NAT public-subnet details."
  }
}
variable "vpc_cidr" {
  type    = string
  default = "10.80.0.0/16"
}
variable "availability_zones" {
  type    = list(string)
  default = ["ap-northeast-2a", "ap-northeast-2c"]

  validation {
    condition     = length(var.availability_zones) == 2 && length(distinct(var.availability_zones)) == 2 && alltrue([for zone in var.availability_zones : can(regex("^[a-z]{2}-[a-z0-9-]+-[0-9]+[a-z]$", zone))])
    error_message = "availability_zones must contain exactly two distinct zones in aws_region."
  }
}
variable "system_subnet_cidrs" {
  type    = list(string)
  default = ["10.80.0.0/20", "10.80.16.0/20"]
}
variable "hoodi_subnet_cidrs" {
  type    = string
  default = "10.80.32.0/20"
}
variable "public_subnet_cidr" {
  type    = string
  default = "10.80.64.0/24"
}
