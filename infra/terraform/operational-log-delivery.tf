# Exact configured destinations for operational-log presence checks.  This is
# inventory, not evidence that a service has emitted or delivered an event.
locals {
  operational_log_delivery_cloudwatch = [
    { id = "vpc-flow-logs", group = aws_cloudwatch_log_group.vpc_flow_logs.name, stream_prefix = "" },
    # AWS documents these rotating EKS control-plane stream prefixes.
    { id = "eks-api", group = aws_cloudwatch_log_group.eks_control_plane.name, stream_prefix = "kube-apiserver-" },
    { id = "eks-audit", group = aws_cloudwatch_log_group.eks_control_plane.name, stream_prefix = "kube-apiserver-audit-" },
    { id = "eks-authenticator", group = aws_cloudwatch_log_group.eks_control_plane.name, stream_prefix = "authenticator-" },
    { id = "eks-controller-manager", group = aws_cloudwatch_log_group.eks_control_plane.name, stream_prefix = "kube-controller-manager-" },
    { id = "eks-scheduler", group = aws_cloudwatch_log_group.eks_control_plane.name, stream_prefix = "kube-scheduler-" },
    { id = "cloudtrail-cloudwatch", group = aws_cloudwatch_log_group.cloudtrail.name, stream_prefix = "" },
    { id = "validator-workloads", group = aws_cloudwatch_log_group.validator_workloads.name, stream_prefix = "fluent-bit-" },
    # This is the configured Vault-security group. A payload correlation is
    # still required to prove that the relay emitted and was delivered.
    { id = "vault-security-cloudwatch", group = aws_cloudwatch_log_group.validator_security.name, stream_prefix = "fluent-bit-" },
  ]

  operational_log_delivery_s3 = concat([
    { id = "validator-archive", bucket = aws_s3_bucket.validator_audit.id, prefix = "validator/", region = var.aws_region },
    { id = "cloudtrail-s3", bucket = aws_s3_bucket.audit.id, prefix = "AWSLogs/${var.aws_account_id}/CloudTrail/${var.aws_region}/", region = var.aws_region },
    # These are destination prefixes.  Vault snapshots may not normally emit
    # access logs, but their configured destination is retained in inventory.
    { id = "audit-access-audit", bucket = aws_s3_bucket.audit_access_logs.id, prefix = "audit/", region = var.aws_region },
    { id = "audit-access-validator-audit", bucket = aws_s3_bucket.audit_access_logs.id, prefix = "validator-audit/", region = var.aws_region },
    { id = "audit-access-vault-snapshot", bucket = aws_s3_bucket.audit_access_logs.id, prefix = "vault-snapshot/", region = var.aws_region },
    { id = "cloudtrail-replica", bucket = aws_s3_bucket.audit_replica.id, prefix = "AWSLogs/${var.aws_account_id}/CloudTrail/${var.aws_region}/", region = var.audit_replica_region },
    { id = "audit-replica-access-audit", bucket = aws_s3_bucket.audit_replica_access_logs.id, prefix = "audit/", region = var.audit_replica_region },
    { id = "audit-replica-access-validator-audit", bucket = aws_s3_bucket.audit_replica_access_logs.id, prefix = "validator-audit/", region = var.audit_replica_region },
    { id = "audit-replica-access-vault-snapshot", bucket = aws_s3_bucket.audit_replica_access_logs.id, prefix = "vault-snapshot/", region = var.audit_replica_region },
    ], var.manage_config_recorder ? [
    { id = "config", bucket = aws_s3_bucket.audit.id, prefix = "AWSLogs/${var.aws_account_id}/Config/", region = var.aws_region },
    { id = "config-replica", bucket = aws_s3_bucket.audit_replica.id, prefix = "AWSLogs/${var.aws_account_id}/Config/", region = var.audit_replica_region },
  ] : [])
}

output "operational_log_delivery" {
  description = "Configured operational-log destinations only; not live-delivery or effective-permission proof."
  value = {
    schema_version  = 1
    account_id      = var.aws_account_id
    region          = var.aws_region
    deployment_name = var.name
    # Lets the consumer distinguish an intentionally unmanaged Config
    # recorder from an incomplete operational destination inventory.
    manage_config_recorder = var.manage_config_recorder
    cloudwatch             = local.operational_log_delivery_cloudwatch
    s3                     = local.operational_log_delivery_s3
  }
}

# S3 additions permit listing only, not object bodies or new KMS decryption.
# FilterLogEvents necessarily permits reading events in these exact groups;
# IAM cannot limit it to metadata fields. The verifier's fixed CLI projection
# removes message bodies inside the reader Pod before returning any output.
data "aws_iam_policy_document" "validator_audit_reader_operational_delivery" {
  statement {
    sid       = "FilterOnlyConfiguredOperationalLogGroups"
    actions   = ["logs:FilterLogEvents"]
    resources = [for item in local.operational_log_delivery_cloudwatch : "arn:aws:logs:${var.aws_region}:${var.aws_account_id}:log-group:${item.group}:*"]
  }

  statement {
    sid       = "ListOnlyValidatorArchive"
    actions   = ["s3:ListBucket"]
    resources = [aws_s3_bucket.validator_audit.arn]
    condition {
      test     = "StringLike"
      variable = "s3:prefix"
      values   = ["validator/*"]
    }
  }

  statement {
    sid       = "ListOnlyPrimaryTrailAndConfig"
    actions   = ["s3:ListBucket"]
    resources = [aws_s3_bucket.audit.arn]
    condition {
      test     = "StringLike"
      variable = "s3:prefix"
      values = concat([
        "AWSLogs/${var.aws_account_id}/CloudTrail/${var.aws_region}/*",
      ], var.manage_config_recorder ? ["AWSLogs/${var.aws_account_id}/Config/*"] : [])
    }
  }

  statement {
    sid       = "ListOnlyPrimaryAccessLogPrefixes"
    actions   = ["s3:ListBucket"]
    resources = [aws_s3_bucket.audit_access_logs.arn]
    condition {
      test     = "StringLike"
      variable = "s3:prefix"
      values   = ["audit/*", "validator-audit/*", "vault-snapshot/*"]
    }
  }

  statement {
    sid       = "ListOnlyReplicaTrailAndConfig"
    actions   = ["s3:ListBucket"]
    resources = [aws_s3_bucket.audit_replica.arn]
    condition {
      test     = "StringLike"
      variable = "s3:prefix"
      values = concat([
        "AWSLogs/${var.aws_account_id}/CloudTrail/${var.aws_region}/*",
      ], var.manage_config_recorder ? ["AWSLogs/${var.aws_account_id}/Config/*"] : [])
    }
  }

  statement {
    sid       = "ListOnlyReplicaAccessLogPrefixes"
    actions   = ["s3:ListBucket"]
    resources = [aws_s3_bucket.audit_replica_access_logs.arn]
    condition {
      test     = "StringLike"
      variable = "s3:prefix"
      values   = ["audit/*", "validator-audit/*", "vault-snapshot/*"]
    }
  }
}

resource "aws_iam_role_policy" "validator_audit_reader_operational_delivery" {
  name   = "${local.name_prefix}-validator-audit-reader-operational-delivery"
  role   = aws_iam_role.validator_audit_reader.id
  policy = data.aws_iam_policy_document.validator_audit_reader_operational_delivery.json
}
