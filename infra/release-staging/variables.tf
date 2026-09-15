variable "aws_region" {
  description = "AWS Region for the temporary release staging resources."
  type        = string
  default     = "ap-northeast-2"

  validation {
    condition     = var.aws_region == "ap-northeast-2"
    error_message = "aws_region must be pinned to ap-northeast-2 (Seoul)."
  }
}

variable "aws_account_id" {
  description = "The reviewed AWS account that may create this temporary deployment."
  type        = string

  validation {
    condition     = can(regex("^[0-9]{12}$", var.aws_account_id))
    error_message = "aws_account_id must be an explicit 12-digit AWS account ID."
  }
}

variable "deployment_name" {
  description = "Explicit globally unique, DNS-compatible deployment name used in both bucket names."
  type        = string

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{2,42}[a-z0-9]$", var.deployment_name)) && !can(regex("--", var.deployment_name))
    error_message = "deployment_name must be an explicit 4-44 character lowercase DNS-compatible name without adjacent hyphens."
  }
}

variable "github_repository" {
  description = "GitHub repository trusted by the existing GitHub Actions OIDC provider, in owner/repository form."
  type        = string

  validation {
    condition     = can(regex("^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$", var.github_repository))
    error_message = "github_repository must be an explicit owner/repository value."
  }
}

variable "github_oidc_provider_arn" {
  description = "Existing shared GitHub Actions OIDC provider ARN. This root never creates or deletes it."
  type        = string

  validation {
    condition     = can(regex("^arn:aws:iam::[0-9]{12}:oidc-provider/token\\.actions\\.githubusercontent\\.com$", var.github_oidc_provider_arn))
    error_message = "github_oidc_provider_arn must be the exact existing token.actions.githubusercontent.com provider ARN."
  }
}

variable "object_prefix" {
  description = "Exact normalized OCI object prefix readable by the evidence role, such as oci/<revision>/."
  type        = string

  validation {
    condition     = can(regex("^[A-Za-z0-9][A-Za-z0-9._/-]*/$", var.object_prefix)) && !can(regex("(^|/)\\.\\.?(/|$)", var.object_prefix)) && !strcontains(var.object_prefix, "*") && !strcontains(var.object_prefix, "?") && !startswith(var.object_prefix, "/")
    error_message = "object_prefix must be a normalized non-empty prefix ending in / and must not contain dot segments or IAM wildcards."
  }
}

variable "allowed_uploader_principal_arn" {
  description = "Exact IAM principal ARN permitted to upload OCI release bytes to the staging bucket."
  type        = string

  validation {
    condition     = can(regex("^arn:aws:iam::[0-9]{12}:(role|user)/[A-Za-z0-9+=,.@_/-]+$", var.allowed_uploader_principal_arn))
    error_message = "allowed_uploader_principal_arn must be an explicit IAM role or user ARN."
  }
}
