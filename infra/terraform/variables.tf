variable "aws_region" {
  description = "The approved deployment region for the private EKS baseline."
  type        = string
  default     = "ap-northeast-2"

  validation {
    condition     = can(regex("^[a-z]{2}-[a-z0-9-]+-[0-9]+$", var.aws_region))
    error_message = "aws_region must be a valid AWS commercial region identifier."
  }
}

variable "aws_account_id" {
  description = "Non-secret AWS account ID used only to scope resource policies."
  type        = string

  validation {
    condition     = can(regex("^[0-9]{12}$", var.aws_account_id))
    error_message = "aws_account_id must be a 12-digit AWS account ID."
  }
}

variable "audit_replica_region" {
  description = "Dedicated disaster-recovery Region for the immutable audit-log replica."
  type        = string
  default     = "ap-northeast-1"

  validation {
    condition     = can(regex("^[a-z]{2}-[a-z0-9-]+-[0-9]+$", var.audit_replica_region))
    error_message = "audit_replica_region must be a valid AWS commercial region identifier."
  }
}

variable "manage_config_recorder" {
  description = "Create and own the account-regional AWS Config recorder. Set false when the account already has its single recorder."
  type        = bool
  default     = true
}

variable "name" {
  description = "Short, DNS-compatible name used to namespace baseline resources."
  type        = string
  default     = "node-operator"

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{1,18}[a-z0-9]$", var.name))
    error_message = "name must be 3-20 lowercase letters, digits, and hyphens, beginning and ending with a letter or digit so derived IAM and S3 names remain valid."
  }
}

variable "vpc_cidr" {
  description = "The reserved VPC CIDR. This baseline intentionally does not accept arbitrary network ranges."
  type        = string
  default     = "10.80.0.0/16"

  validation {
    condition     = var.vpc_cidr == "10.80.0.0/16"
    error_message = "vpc_cidr must be the approved 10.80.0.0/16 range."
  }
}

variable "network_source" {
  description = "Network ownership mode. legacy preserves the existing baseline-owned VPC; foundation consumes the separately managed zero-resource foundation output."
  type        = string
  default     = "legacy"

  validation {
    condition     = contains(["legacy", "foundation"], var.network_source)
    error_message = "network_source must be either legacy or foundation."
  }
}

variable "foundation_network" {
  description = "Non-secret output of the foundation-network root when network_source is foundation."
  type = object({
    vpc_id                = string
    vpc_cidr              = string
    system_subnet_ids     = list(string)
    system_route_table_id = string
    hoodi_subnet_ids      = list(string)
    hoodi_route_table_id  = string
    hoodi_nat_gateway_id  = string
    hoodi_nat_public_ip   = string
  })
  default  = null
  nullable = true

  validation {
    condition = var.foundation_network == null ? true : (
      can(regex("^vpc-[0-9a-f]+$", var.foundation_network.vpc_id)) &&
      can(cidrnetmask(var.foundation_network.vpc_cidr)) &&
      length(var.foundation_network.system_subnet_ids) >= 2 &&
      length(var.foundation_network.hoodi_subnet_ids) >= 1 &&
      can(regex("^rtb-[0-9a-f]+$", var.foundation_network.system_route_table_id)) &&
      can(regex("^rtb-[0-9a-f]+$", var.foundation_network.hoodi_route_table_id)) &&
      can(regex("^nat-[0-9a-f]+$", var.foundation_network.hoodi_nat_gateway_id))
      && can(cidrhost("${var.foundation_network.hoodi_nat_public_ip}/32", 0))
    )
    error_message = "foundation_network must contain reviewed VPC, subnet, route-table, and NAT identifiers."
  }
}

variable "availability_zones" {
  description = "Exactly two approved availability zones in aws_region for private worker subnets."
  type        = list(string)
  default     = ["ap-northeast-2a", "ap-northeast-2c"]

  validation {
    condition     = length(var.availability_zones) == 2 && length(distinct(var.availability_zones)) == 2 && alltrue([for zone in var.availability_zones : can(regex("^[a-z]{2}-[a-z0-9-]+-[0-9]+[a-z]$", zone))])
    error_message = "availability_zones must contain exactly two distinct zones in aws_region."
  }
}

variable "private_subnet_cidrs" {
  description = "Two non-public worker subnet CIDRs, one per approved availability zone."
  type        = list(string)
  default     = ["10.80.0.0/20", "10.80.16.0/20"]

  validation {
    condition     = join(",", var.private_subnet_cidrs) == "10.80.0.0/20,10.80.16.0/20"
    error_message = "private_subnet_cidrs must be [10.80.0.0/20, 10.80.16.0/20]."
  }
}

variable "kubernetes_version" {
  description = "EKS Kubernetes minor version. Pin deliberately in the build change that applies this baseline."
  type        = string
  default     = "1.35"

  validation {
    condition     = can(regex("^1\\.[0-9]+$", var.kubernetes_version))
    error_message = "kubernetes_version must be a Kubernetes minor version, such as 1.35."
  }
}

variable "enable_temporary_ssm_ops_host" {
  description = "Create one temporary private SSM tunnel host for local access to the private EKS API."
  type        = bool
  default     = false
}

variable "temporary_ssm_ops_host_termination_at" {
  description = "Optional future KST wall-clock timestamp (YYYY-MM-DDTHH:MM:SS) for one-time termination of the temporary SSM host; empty requires an explicit manual stop or destroy."
  type        = string
  default     = ""

  validation {
    condition     = var.temporary_ssm_ops_host_termination_at == "" || can(regex("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}$", var.temporary_ssm_ops_host_termination_at))
    error_message = "temporary_ssm_ops_host_termination_at must be empty or a KST wall-clock timestamp such as 2026-09-06T22:00:00."
  }
}

variable "system_node_min_size" {
  description = "Minimum system-pool capacity. Three nodes are required for the reviewed Vault HA anti-affinity placement."
  type        = number
  default     = 3

  validation {
    condition     = var.system_node_min_size == 3
    error_message = "system_node_min_size must remain three for reviewed Vault HA placement."
  }
}

variable "system_node_desired_size" {
  description = "Initial system-pool capacity. Three nodes place the reviewed Vault HA replicas."
  type        = number
  default     = 3

  validation {
    condition     = var.system_node_desired_size == 3
    error_message = "system_node_desired_size must remain three for reviewed Vault HA placement."
  }
}

variable "system_node_max_size" {
  description = "Maximum system-pool capacity."
  type        = number
  default     = 3

  validation {
    condition     = var.system_node_max_size == 3
    error_message = "system_node_max_size must remain 3 for this baseline."
  }
}

variable "consensus_node_min_size" {
  description = "Consensus-pool stop floor. Desired capacity starts at one but operations may stop this pool at zero."
  type        = number
  default     = 0

  validation {
    condition     = var.consensus_node_min_size == 0
    error_message = "consensus_node_min_size must remain zero so an explicit stop does not drift."
  }
}

variable "consensus_node_desired_size" {
  description = "Initial consensus-pool capacity."
  type        = number
  default     = 1

  validation {
    condition     = var.consensus_node_desired_size == 1
    error_message = "consensus_node_desired_size must remain one for the initial paired-node deployment."
  }
}

variable "consensus_node_max_size" {
  description = "Maximum consensus-pool capacity."
  type        = number
  default     = 1

  validation {
    condition     = var.consensus_node_max_size == 1
    error_message = "consensus_node_max_size must remain one."
  }
}

variable "execution_node_min_size" {
  description = "Execution-pool stop floor. Desired capacity starts at one but operations may stop this pool at zero."
  type        = number
  default     = 0

  validation {
    condition     = var.execution_node_min_size == 0
    error_message = "execution_node_min_size must remain zero so an explicit stop does not drift."
  }
}

variable "execution_node_desired_size" {
  description = "Initial execution-pool capacity."
  type        = number
  default     = 1

  validation {
    condition     = var.execution_node_desired_size == 1
    error_message = "execution_node_desired_size must remain one for the initial paired-node deployment."
  }
}

variable "execution_node_max_size" {
  description = "Maximum execution-pool capacity."
  type        = number
  default     = 1

  validation {
    condition     = var.execution_node_max_size == 1
    error_message = "execution_node_max_size must remain one."
  }
}

variable "hoodi_nat_gateway_id" {
  description = "Existing approved NAT gateway used only by the dedicated Hoodi pools. Leave null for offline validation."
  type        = string
  default     = null

  validation {
    condition     = var.hoodi_nat_gateway_id == null || can(regex("^nat-[0-9a-f]+$", var.hoodi_nat_gateway_id))
    error_message = "hoodi_nat_gateway_id must be an existing NAT gateway ID such as nat-0123abcd."
  }
}

variable "node_root_volume_size" {
  description = "Encrypted gp3 root-volume size in GiB for each managed node."
  type        = number
  default     = 80

  validation {
    condition     = var.node_root_volume_size >= 40 && var.node_root_volume_size <= 200
    error_message = "node_root_volume_size must be between 40 and 200 GiB."
  }
}

variable "tags" {
  description = "Additional non-secret tags; security ownership tags cannot be overridden."
  type        = map(string)
  default     = {}
}

variable "offline_validation" {
  description = "Use synthetic provider settings for network-isolated validation only. Never enable for apply."
  type        = bool
  default     = false
}

variable "enable_ssm_ops_host" {
  description = "Create one temporary, private SSM tunnel host. Disabled by default and not a general-purpose bastion."
  type        = bool
  default     = false
}

variable "ssm_ops_host_termination_at" {
  description = "Optional one-time termination time for the SSM ops host, in Asia/Seoul local time as YYYY-MM-DDTHH:MM:SS. An explicit future time is required because Terraform cannot safely infer today's date or recover a missed one-time schedule."
  type        = string
  default     = ""

  validation {
    condition     = var.ssm_ops_host_termination_at == "" || can(regex("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}$", var.ssm_ops_host_termination_at))
    error_message = "ssm_ops_host_termination_at must be empty or Asia/Seoul local time formatted as YYYY-MM-DDTHH:MM:SS."
  }
}
