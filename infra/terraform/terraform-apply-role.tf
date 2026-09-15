# The optional selected role is an explicit KMS-policy principal only. It does
# not create, assume, or grant IAM permissions to a role.
variable "terraform_apply_role_arn" {
  description = "Optional exact same-account IAM role ARN selected by installer input for lifecycle-only KMS policy binding. Empty omits the principal; this input does not prove the active Terraform identity."
  type        = string
  default     = null
  nullable    = true

  validation {
    condition = var.terraform_apply_role_arn == null || var.terraform_apply_role_arn == "" || can(regex(
      "^arn:aws:iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_/-]{1,64}$",
      var.terraform_apply_role_arn,
    ))
    error_message = "terraform_apply_role_arn must be empty or an exact IAM role ARN."
  }
}
