# Private Prometheus/EMF collector foundation. This owns the CloudWatch Logs
# destination and the workload identity only; collector image selection,
# manifests, metric allowlists, and dashboards are separately admitted work.
# AWS documents EKS Pod Identity request tags for the namespace and service
# account binding used below:
# https://docs.aws.amazon.com/eks/latest/userguide/pod-id-role.html
locals {
  validator_metrics_namespace       = "validator-observability"
  validator_metrics_service_account = "validator-metrics-collector"
}

resource "aws_cloudwatch_log_group" "validator_metrics" {
  name              = "/aws/eks/${var.name}/validator-metrics"
  retention_in_days = 365
  kms_key_id        = aws_kms_key.validator_audit.arn
  tags              = local.common_tags
}

# Pod Identity uses the EKS service principal and must be allowed to tag its
# session. The conditions bind this otherwise reusable service principal to the
# account, cluster, namespace, and service account that own this collector.
data "aws_iam_policy_document" "validator_metrics_collector_assume_role" {
  statement {
    sid     = "AllowBoundEksPodIdentityCollector"
    actions = ["sts:AssumeRole", "sts:TagSession"]

    principals {
      type        = "Service"
      identifiers = ["pods.eks.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:RequestTag/eks-cluster-arn"
      values   = ["arn:aws:eks:${var.aws_region}:${var.aws_account_id}:cluster/${var.name}"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:RequestTag/kubernetes-namespace"
      values   = [local.validator_metrics_namespace]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:RequestTag/kubernetes-service-account"
      values   = [local.validator_metrics_service_account]
    }
  }
}

resource "aws_iam_role" "validator_metrics_collector" {
  name               = "${local.name_prefix}-validator-metrics-collector"
  assume_role_policy = data.aws_iam_policy_document.validator_metrics_collector_assume_role.json
  tags               = local.common_tags
}

# EMF is delivered through CloudWatch Logs. Terraform creates and retains the
# group, so this workload deliberately cannot create groups or alter retention.
data "aws_iam_policy_document" "validator_metrics_collector" {
  statement {
    sid       = "WriteOnlyValidatorMetricsEmf"
    actions   = ["logs:CreateLogStream", "logs:DescribeLogStreams", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.validator_metrics.arn}:*"]
  }
}

resource "aws_iam_role_policy" "validator_metrics_collector" {
  name   = "${local.name_prefix}-validator-metrics-collector"
  role   = aws_iam_role.validator_metrics_collector.id
  policy = data.aws_iam_policy_document.validator_metrics_collector.json
}

resource "aws_eks_pod_identity_association" "validator_metrics_collector" {
  # Bind this fresh-deploy association to the created cluster resource so its
  # API call cannot race ahead of EKS cluster creation in a zero-resource apply.
  cluster_name    = aws_eks_cluster.private.name
  namespace       = local.validator_metrics_namespace
  service_account = local.validator_metrics_service_account
  role_arn        = aws_iam_role.validator_metrics_collector.arn
}

output "validator_metrics_collector_role_arn" {
  description = "Pod-Identity role ARN for the private validator EMF collector; it grants only scoped CloudWatch Logs writes."
  value       = aws_iam_role.validator_metrics_collector.arn
}

output "validator_metrics_log_group_name" {
  description = "Encrypted CloudWatch Logs group that receives validator EMF payloads."
  value       = aws_cloudwatch_log_group.validator_metrics.name
}

output "validator_metrics_region" {
  description = "Region of the validator metrics CloudWatch Logs destination."
  value       = var.aws_region
}

output "validator_metrics_namespace" {
  description = "Kubernetes namespace bound to the validator metrics collector Pod Identity association."
  value       = local.validator_metrics_namespace
}

output "validator_metrics_service_account" {
  description = "Kubernetes service account bound to the validator metrics collector Pod Identity association."
  value       = local.validator_metrics_service_account
}
