variable "aws_region" {
  type    = string
  default = "ap-northeast-2"

  validation {
    condition     = can(regex("^[a-z]{2}-[a-z0-9-]+-[0-9]+$", var.aws_region))
    error_message = "aws_region must be a valid AWS commercial region identifier."
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
  default = "node-operator"

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{1,18}[a-z0-9]$", var.name))
    error_message = "name must be a 3-20 character DNS-compatible identifier so derived IAM and S3 resource names remain valid."
  }
}

variable "state_bucket_name" {
  description = "Optional existing state bucket name. Leave null for the generated name used by new deployments."
  type        = string
  default     = null
  nullable    = true

  validation {
    condition = var.state_bucket_name == null ? true : (
      length(var.state_bucket_name) >= 3 &&
      length(var.state_bucket_name) <= 63 &&
      can(regex("^[a-z0-9][a-z0-9.-]*[a-z0-9]$", var.state_bucket_name)) &&
      !can(regex("\\.\\.", var.state_bucket_name))
    )
    error_message = "state_bucket_name must be null or a 3-63 character lowercase S3 bucket name without adjacent periods."
  }
}

variable "baseline_state_key" {
  description = "Terraform state object key exported for the baseline module."
  type        = string
  default     = "node-operator/baseline/terraform.tfstate"

  validation {
    condition     = can(regex("^node-operator/[a-z0-9][a-z0-9-]{0,62}/terraform\\.tfstate$", var.baseline_state_key))
    error_message = "baseline_state_key must be node-operator/<environment>/terraform.tfstate using lowercase letters, digits, and hyphens."
  }
}

variable "backend_principal_arns" {
  description = "Exact same-account IAM role ARNs permitted to use the state CMK through S3 and the regional DynamoDB lock table, without granting key administration."
  type        = set(string)
  default     = []

  validation {
    condition = alltrue([
      for principal_arn in var.backend_principal_arns :
      can(regex("^arn:aws:iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_/-]+$", principal_arn))
    ])
    error_message = "backend_principal_arns must contain only exact IAM role ARNs; wildcards and non-role principals are not allowed."
  }
}
