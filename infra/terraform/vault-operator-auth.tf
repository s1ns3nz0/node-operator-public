# Opt-in support for unique-ID-bound operator authentication. This does not
# configure a Vault auth mount or create credentials; the human ceremony does.
variable "vault_operator_user_arn" {
  type        = string
  default     = ""
  description = "Exact operator IAM user ARN for Vault unique-ID resolution; empty disables the additional read-only policy."
  validation {
    condition     = var.vault_operator_user_arn == "" || can(regex("^arn:aws:iam::[0-9]{12}:user/[A-Za-z0-9+=,.@_-]+$", var.vault_operator_user_arn))
    error_message = "Use one exact pathless IAM user ARN; wildcards, roles and account-wide grants are prohibited."
  }
}

resource "aws_iam_role_policy" "vault_operator_identity_lookup" {
  count = var.vault_operator_user_arn == "" ? 0 : 1
  name  = "${local.name_prefix}-vault-operator-identity-lookup"
  role  = aws_iam_role.vault.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["iam:GetUser"]
      Resource = var.vault_operator_user_arn
    }]
  })
  lifecycle {
    precondition {
      condition     = startswith(var.vault_operator_user_arn, "arn:aws:iam::${var.aws_account_id}:user/")
      error_message = "The operator user must belong to this deployment's AWS account."
    }
  }
}
