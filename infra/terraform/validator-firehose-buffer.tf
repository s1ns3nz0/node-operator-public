# Firehose validates these caller permissions on PutRecord/PutRecordBatch.
# A separate CMK prevents buffer encryption from widening access to the archive.
data "aws_iam_policy_document" "validator_firehose_buffer" {
  source_policy_documents = [data.aws_iam_policy_document.kms_key_administrator.json]
  statement {
    sid = "AllowOnlyCloudWatchSubscriptionProducer"
    principals {
      type        = "AWS"
      identifiers = [aws_iam_role.validator_cloudwatch_subscription.arn]
    }
    actions   = ["kms:GenerateDataKey", "kms:Decrypt"]
    resources = ["*"]
  }
}

resource "aws_kms_key" "validator_firehose_buffer" {
  description             = "Dedicated validator audit Firehose buffer encryption"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  policy                  = data.aws_iam_policy_document.validator_firehose_buffer.json
  tags                    = local.common_tags
}

# Install producer KMS permissions before enabling stream encryption. Keeping
# this policy independent of the stream ARN avoids a dependency cycle and a
# window where CloudWatch Logs cannot deliver to the newly encrypted stream.
data "aws_iam_policy_document" "validator_firehose_buffer_producer" {
  statement {
    sid       = "EncryptOnlyFirehoseBuffer"
    actions   = ["kms:GenerateDataKey", "kms:Decrypt"]
    resources = [aws_kms_key.validator_firehose_buffer.arn]
  }
}

resource "aws_iam_role_policy" "validator_firehose_buffer" {
  name   = "${local.name_prefix}-validator-firehose-buffer"
  role   = aws_iam_role.validator_cloudwatch_subscription.id
  policy = data.aws_iam_policy_document.validator_firehose_buffer_producer.json
}

resource "aws_s3_bucket_notification" "validator_audit" {
  bucket      = aws_s3_bucket.validator_audit.id
  eventbridge = true
}
