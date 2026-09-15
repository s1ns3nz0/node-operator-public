data "aws_iam_policy_document" "kms_administrator_assume_role" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${var.aws_account_id}:root"]
    }
  }
}

resource "aws_iam_role" "kms_administrator" {
  name               = "${local.name_prefix}-kms-administrator"
  assume_role_policy = data.aws_iam_policy_document.kms_administrator_assume_role.json

  tags = local.common_tags

  lifecycle {
    # Terraform 1.5 variable validation cannot bind this ARN to another
    # variable. Keep the account check on an existing KMS dependency rather
    # than introducing a standalone resource into the pre-EKS closure.
    precondition {
      condition     = var.terraform_apply_role_arn == null || var.terraform_apply_role_arn == "" || can(regex("^arn:aws:iam::${var.aws_account_id}:role/[A-Za-z0-9+=,.@_/-]{1,64}$", var.terraform_apply_role_arn))
      error_message = "terraform_apply_role_arn must be empty or an IAM role in aws_account_id."
    }
  }
}

data "aws_iam_policy_document" "kms_key_administrator" {
  # Retain the standard account-root delegation that KMS requires when a key
  # is created. It delegates only to IAM policies in this account; it does not
  # grant a workload direct cryptographic access to the key.
  statement {
    sid    = "EnableAccountIAMPolicyDelegation"
    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${var.aws_account_id}:root"]
    }

    actions   = ["kms:*"]
    resources = ["*"]
  }

  statement {
    sid    = "AllowDedicatedKMSAdministrator"
    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = [aws_iam_role.kms_administrator.arn]
    }

    actions   = ["kms:*"]
    resources = ["*"]
  }

  # This conditional statement never invents a fixed role principal. The
  # selected ARN receives lifecycle management only, never cryptographic use,
  # grants, or wildcard KMS administration.
  dynamic "statement" {
    for_each = var.terraform_apply_role_arn == null || var.terraform_apply_role_arn == "" ? [] : [var.terraform_apply_role_arn]
    content {
      sid    = "AllowSelectedTerraformApplyKeyLifecycleManagement"
      effect = "Allow"

      principals {
        type        = "AWS"
        identifiers = [statement.value]
      }

      actions = [
        "kms:CancelKeyDeletion",
        "kms:CreateAlias",
        "kms:DeleteAlias",
        "kms:DescribeKey",
        "kms:EnableKeyRotation",
        "kms:GetKeyPolicy",
        "kms:GetKeyRotationStatus",
        "kms:ListAliases",
        "kms:ListResourceTags",
        "kms:PutKeyPolicy",
        "kms:ScheduleKeyDeletion",
        "kms:TagResource",
      ]
      resources = ["*"]
    }
  }
}

data "aws_iam_policy_document" "audit_key" {
  source_policy_documents = [data.aws_iam_policy_document.kms_key_administrator.json]

  statement {
    sid    = "AllowCloudTrailToEncryptAuditLogs"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    actions   = ["kms:GenerateDataKey*", "kms:Decrypt", "kms:DescribeKey"]
    resources = ["*"]

    condition {
      test     = "StringLike"
      variable = "kms:EncryptionContext:aws:cloudtrail:arn"
      values   = ["arn:aws:cloudtrail:${var.aws_region}:${var.aws_account_id}:trail/*"]
    }
  }

  statement {
    sid    = "AllowAuditReplicationRoleToDecryptSourceObjects"
    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = [aws_iam_role.audit_replication.arn]
    }

    actions   = ["kms:Decrypt", "kms:DescribeKey"]
    resources = ["*"]

    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["s3.${var.aws_region}.amazonaws.com"]
    }
  }

  statement {
    sid    = "AllowCloudWatchLogsToUseAuditKey"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["logs.${var.aws_region}.amazonaws.com"]
    }

    actions   = ["kms:Encrypt*", "kms:Decrypt*", "kms:ReEncrypt*", "kms:GenerateDataKey*", "kms:Describe*"]
    resources = ["*"]

    condition {
      test     = "ArnLike"
      variable = "kms:EncryptionContext:aws:logs:arn"
      values   = ["arn:aws:logs:${var.aws_region}:${var.aws_account_id}:log-group:*"]
    }
  }
}

data "aws_iam_policy_document" "ebs_key" {
  source_policy_documents = [data.aws_iam_policy_document.kms_key_administrator.json]

  statement {
    sid    = "AllowAutoScalingToUseEbsKey"
    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${var.aws_account_id}:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling"]
    }

    actions   = ["kms:Decrypt", "kms:DescribeKey", "kms:Encrypt", "kms:GenerateDataKey*", "kms:ReEncrypt*"]
    resources = ["*"]
  }

  statement {
    sid    = "AllowAutoScalingToGrantEbsKeyUse"
    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${var.aws_account_id}:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling"]
    }

    actions   = ["kms:CreateGrant"]
    resources = ["*"]

    condition {
      test     = "Bool"
      variable = "kms:GrantIsForAWSResource"
      values   = ["true"]
    }
  }

  statement {
    sid    = "AllowEBSCSIPodIdentity"
    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = [aws_iam_role.ebs_csi.arn]
    }

    actions = [
      "kms:Decrypt",
      "kms:DescribeKey",
      "kms:Encrypt",
      "kms:GenerateDataKeyWithoutPlaintext",
      "kms:ReEncrypt*",
    ]
    resources = ["*"]
  }

  statement {
    sid    = "AllowEBSCSIPodIdentityAWSResourceGrants"
    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = [aws_iam_role.ebs_csi.arn]
    }

    actions   = ["kms:CreateGrant"]
    resources = ["*"]

    condition {
      test     = "Bool"
      variable = "kms:GrantIsForAWSResource"
      values   = ["true"]
    }
  }
}

data "aws_iam_policy_document" "vault_key" {
  source_policy_documents = [data.aws_iam_policy_document.kms_key_administrator.json]

  statement {
    sid    = "AllowVaultPodIdentity"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = [aws_iam_role.vault.arn]
    }
    actions   = ["kms:Decrypt", "kms:DescribeKey", "kms:Encrypt", "kms:CreateGrant"]
    resources = ["*"]
    condition {
      test     = "Bool"
      variable = "kms:GrantIsForAWSResource"
      values   = ["true"]
    }
  }
}

resource "aws_kms_key" "ebs" {
  description             = "Managed-node and EBS CSI volume encryption key"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  policy                  = data.aws_iam_policy_document.ebs_key.json

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-ebs"
  })
}

resource "aws_kms_alias" "ebs" {
  name          = "alias/${local.name_prefix}-ebs"
  target_key_id = aws_kms_key.ebs.key_id
}

resource "aws_kms_key" "audit" {
  description             = "CloudTrail and EKS control-plane audit-log encryption key"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  policy                  = data.aws_iam_policy_document.audit_key.json

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-audit"
  })
}

resource "aws_kms_alias" "audit" {
  name          = "alias/${local.name_prefix}-audit"
  target_key_id = aws_kms_key.audit.key_id
}

resource "aws_kms_key" "vault" {
  description             = "Vault auto-unseal key; never used for workload secret payloads"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  policy                  = data.aws_iam_policy_document.vault_key.json

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-vault-unseal"
  })
}

resource "aws_kms_alias" "vault" {
  name          = "alias/${local.name_prefix}-vault-unseal"
  target_key_id = aws_kms_key.vault.key_id
}
