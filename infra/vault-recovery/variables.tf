variable "aws_region" {
  type    = string
  default = "ap-northeast-2"
  validation {
    condition     = var.aws_region == "ap-northeast-2"
    error_message = "aws_region must be pinned to ap-northeast-2."
  }
}

variable "aws_account_id" {
  type = string
  validation {
    condition     = can(regex("^[0-9]{12}$", var.aws_account_id))
    error_message = "aws_account_id must be a 12-digit AWS account ID."
  }
}

variable "name" {
  type    = string
  default = "node-operator-baseline"
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{1,38}[a-z0-9]$", var.name))
    error_message = "name must be a DNS-compatible identifier."
  }
}

variable "availability_zone" {
  type = string
  validation {
    condition     = can(regex("^ap-northeast-2[a-d]$", var.availability_zone))
    error_message = "availability_zone must be an ap-northeast-2 availability zone."
  }
}

variable "ami_id" {
  description = "Explicit, reviewed Amazon ECS-optimized AL2023 x86_64 AMI ID; this root never selects latest."
  type        = string
  validation {
    condition     = can(regex("^ami-[0-9a-f]{8,17}$", var.ami_id))
    error_message = "ami_id must be an explicit AMI ID."
  }
}

variable "snapshot_bucket" {
  type = string
  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$", var.snapshot_bucket)) && !can(regex("\\.\\.", var.snapshot_bucket))
    error_message = "snapshot_bucket must be a valid explicit S3 bucket name."
  }
}

variable "snapshot_key" {
  type = string
  validation {
    condition     = length(var.snapshot_key) > 0 && !startswith(var.snapshot_key, "/") && !can(regex("(^|/)\\.\\.?(/|$)", var.snapshot_key)) && !strcontains(var.snapshot_key, "*") && !strcontains(var.snapshot_key, "?")
    error_message = "snapshot_key must be a non-empty normalized object key without IAM wildcards."
  }
}

variable "snapshot_version_id" {
  type = string
  validation {
    condition     = length(var.snapshot_version_id) > 0 && lower(var.snapshot_version_id) != "null"
    error_message = "snapshot_version_id must be the exact approved object version, not null."
  }
}

variable "snapshot_checksum_sha256" {
  description = "Expected SHA-256 for the separately reviewed recovery ceremony; provisioner does not download or validate the payload."
  type        = string
  validation {
    condition     = can(regex("^[A-Fa-f0-9]{64}$", var.snapshot_checksum_sha256))
    error_message = "snapshot_checksum_sha256 must be a SHA-256 hex digest."
  }
}

variable "snapshot_kms_key_arn" {
  type = string
  validation {
    condition     = can(regex("^arn:aws:kms:ap-northeast-2:[0-9]{12}:key/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", var.snapshot_kms_key_arn))
    error_message = "snapshot_kms_key_arn must be an exact KMS key ARN in ap-northeast-2."
  }
}

variable "auto_unseal_kms_key_arn" {
  type = string
  validation {
    condition     = can(regex("^arn:aws:kms:ap-northeast-2:[0-9]{12}:key/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", var.auto_unseal_kms_key_arn))
    error_message = "auto_unseal_kms_key_arn must be an exact KMS key ARN in ap-northeast-2."
  }
}

variable "recovery_expiry" {
  description = "Explicit RFC3339 expiry tag approved for this temporary recovery environment."
  type        = string
  validation {
    condition     = can(regex("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$", var.recovery_expiry))
    error_message = "recovery_expiry must be an explicit UTC RFC3339 timestamp."
  }
}

variable "root_volume_size_gib" {
  type    = number
  default = 30
  validation {
    condition     = var.root_volume_size_gib >= 30 && floor(var.root_volume_size_gib) == var.root_volume_size_gib
    error_message = "root_volume_size_gib must be a whole number of at least 30 GiB."
  }
}
