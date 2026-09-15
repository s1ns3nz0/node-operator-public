# Live replication for access-log objects only.  Rules preserve the canonical
# object keys; the Tokyo buckets' own audit-replica/ and
# release-artifacts-replica/ delivery prefixes therefore remain separate.

data "aws_iam_policy_document" "audit_access_log_replication_assume_role" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["s3.amazonaws.com"]
    }

  }
}

resource "aws_iam_role" "audit_access_log_replication" {
  name               = "${local.name_prefix}-audit-access-log-replication"
  assume_role_policy = data.aws_iam_policy_document.audit_access_log_replication_assume_role.json

  tags = local.common_tags
}

data "aws_iam_policy_document" "audit_access_log_replication" {
  statement {
    sid       = "ReadAuditAccessLogReplicationConfiguration"
    actions   = ["s3:GetReplicationConfiguration", "s3:ListBucket"]
    resources = [aws_s3_bucket.audit_access_logs.arn]
  }

  statement {
    sid = "ReadOnlyAuditAccessLogVersions"
    actions = [
      "s3:GetObjectVersionAcl",
      "s3:GetObjectVersionForReplication",
      "s3:GetObjectVersionTagging",
    ]
    resources = [
      "${aws_s3_bucket.audit_access_logs.arn}/audit/*",
      "${aws_s3_bucket.audit_access_logs.arn}/validator-audit/*",
      "${aws_s3_bucket.audit_access_logs.arn}/vault-snapshot/*",
    ]
  }

  statement {
    sid     = "WriteOnlyAuditAccessLogReplicas"
    actions = ["s3:ReplicateObject", "s3:ReplicateTags"]
    resources = [
      "${aws_s3_bucket.audit_replica_access_logs.arn}/audit/*",
      "${aws_s3_bucket.audit_replica_access_logs.arn}/validator-audit/*",
      "${aws_s3_bucket.audit_replica_access_logs.arn}/vault-snapshot/*",
    ]
  }
}

resource "aws_iam_role_policy" "audit_access_log_replication" {
  name   = "${local.name_prefix}-audit-access-log-replication"
  role   = aws_iam_role.audit_access_log_replication.id
  policy = data.aws_iam_policy_document.audit_access_log_replication.json
}

resource "aws_s3_bucket_replication_configuration" "audit_access_logs" {
  bucket = aws_s3_bucket.audit_access_logs.id
  role   = aws_iam_role.audit_access_log_replication.arn

  rule {
    id       = "replicate-audit-access-logs-to-tokyo"
    status   = "Enabled"
    priority = 1

    filter { prefix = "audit/" }

    delete_marker_replication { status = "Disabled" }

    destination {
      bucket        = aws_s3_bucket.audit_replica_access_logs.arn
      storage_class = "STANDARD"
    }
  }

  rule {
    id       = "replicate-validator-audit-access-logs-to-tokyo"
    status   = "Enabled"
    priority = 2

    filter { prefix = "validator-audit/" }

    delete_marker_replication { status = "Disabled" }

    destination {
      bucket        = aws_s3_bucket.audit_replica_access_logs.arn
      storage_class = "STANDARD"
    }
  }

  rule {
    id       = "replicate-vault-snapshot-access-logs-to-tokyo"
    status   = "Enabled"
    priority = 3

    filter { prefix = "vault-snapshot/" }

    delete_marker_replication { status = "Disabled" }

    destination {
      bucket        = aws_s3_bucket.audit_replica_access_logs.arn
      storage_class = "STANDARD"
    }
  }

  depends_on = [
    aws_s3_bucket_versioning.audit_access_logs,
    aws_s3_bucket_versioning.audit_replica_access_logs,
    aws_iam_role_policy.audit_access_log_replication,
  ]
}

data "aws_iam_policy_document" "release_access_log_replication_assume_role" {
  count = var.enable_release_signer ? 1 : 0

  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["s3.amazonaws.com"]
    }

  }
}

resource "aws_iam_role" "release_access_log_replication" {
  count              = var.enable_release_signer ? 1 : 0
  name               = "${local.name_prefix}-release-access-log-replication"
  assume_role_policy = data.aws_iam_policy_document.release_access_log_replication_assume_role[0].json

  tags = local.common_tags
}

data "aws_iam_policy_document" "release_access_log_replication" {
  count = var.enable_release_signer ? 1 : 0

  statement {
    sid       = "ReadReleaseAccessLogReplicationConfiguration"
    actions   = ["s3:GetReplicationConfiguration", "s3:ListBucket"]
    resources = [aws_s3_bucket.release_artifacts_access_logs[0].arn]
  }

  statement {
    sid = "ReadOnlyReleaseAccessLogVersions"
    actions = [
      "s3:GetObjectVersionAcl",
      "s3:GetObjectVersionForReplication",
      "s3:GetObjectVersionTagging",
    ]
    resources = ["${aws_s3_bucket.release_artifacts_access_logs[0].arn}/release-artifacts/*"]
  }

  statement {
    sid       = "WriteOnlyReleaseAccessLogReplicas"
    actions   = ["s3:ReplicateObject", "s3:ReplicateTags"]
    resources = ["${aws_s3_bucket.release_artifacts_replica_access_logs[0].arn}/release-artifacts/*"]
  }
}

resource "aws_iam_role_policy" "release_access_log_replication" {
  count  = var.enable_release_signer ? 1 : 0
  name   = "${local.name_prefix}-release-access-log-replication"
  role   = aws_iam_role.release_access_log_replication[0].id
  policy = data.aws_iam_policy_document.release_access_log_replication[0].json
}

resource "aws_s3_bucket_replication_configuration" "release_artifacts_access_logs" {
  count  = var.enable_release_signer ? 1 : 0
  bucket = aws_s3_bucket.release_artifacts_access_logs[0].id
  role   = aws_iam_role.release_access_log_replication[0].arn

  rule {
    id       = "replicate-release-access-logs-to-tokyo"
    status   = "Enabled"
    priority = 1

    filter { prefix = "release-artifacts/" }

    delete_marker_replication { status = "Disabled" }

    destination {
      bucket        = aws_s3_bucket.release_artifacts_replica_access_logs[0].arn
      storage_class = "STANDARD"
    }
  }

  depends_on = [
    aws_s3_bucket_versioning.release_artifacts_access_logs,
    aws_s3_bucket_versioning.release_artifacts_replica_access_logs,
    aws_iam_role_policy.release_access_log_replication,
  ]
}
