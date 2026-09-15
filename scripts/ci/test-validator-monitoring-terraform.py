#!/usr/bin/env python3
# Check objective: Validate the validator CloudWatch EMF Terraform foundation.
"""Offline source contract for the bounded validator CloudWatch EMF foundation.

This test intentionally validates declarative scope, not a Terraform plan or
live CloudWatch delivery. No cloud credentials, apply, or publication is used.
"""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[2]
SOURCE = (ROOT / "infra/terraform/validator-monitoring.tf").read_text()
VALIDATOR_OBSERVABILITY_SOURCE = (ROOT / "infra/terraform/validator-observability.tf").read_text()


def block(kind, resource_type, name, source=SOURCE):
    """Return one simple named HCL block, accounting for nested blocks."""
    match = re.search(rf'{re.escape(kind)} "{re.escape(resource_type)}" "{re.escape(name)}" \{{', source)
    if not match:
        raise AssertionError(f"missing {kind} {resource_type} {name}")
    depth = 0
    for index in range(match.end() - 1, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[match.start():index + 1]
    raise AssertionError(f"unterminated {kind} {resource_type} {name}")


def assert_validator_audit_cloudwatch_grant(source):
    """Assert the actual KMS key policy that encrypts validator EMF logs."""
    policy = block("data", "aws_iam_policy_document", "validator_audit_key", source)
    key = block("resource", "aws_kms_key", "validator_audit", source)
    assert 'policy                  = data.aws_iam_policy_document.validator_audit_key.json' in key
    assert 'sid    = "AllowCloudWatchLogsToEncryptValidatorLogGroups"' in policy
    assert 'identifiers = ["logs.${var.aws_region}.amazonaws.com"]' in policy
    assert 'variable = "kms:EncryptionContext:aws:logs:arn"' in policy
    assert 'values   = ["arn:aws:logs:${var.aws_region}:${var.aws_account_id}:log-group:/aws/eks/${var.name}/validator-*"]' in policy


class ValidatorMonitoringTerraformTest(unittest.TestCase):
    def test_log_collector_and_reader_have_separate_bound_identities(self):
        for policy_name, association_name, service_account in (
            ("validator_collector_assume_role", "validator_log_collector", "validator-log-collector"),
            ("validator_audit_reader_assume_role", "validator_audit_reader", "validator-audit-reader"),
        ):
            trust = block("data", "aws_iam_policy_document", policy_name, VALIDATOR_OBSERVABILITY_SOURCE)
            self.assertEqual(trust.count('test     = "StringEquals"'), 3)
            for variable, value in (
                ("eks-cluster-arn", "arn:aws:eks:${var.aws_region}:${var.aws_account_id}:cluster/${var.name}"),
                ("kubernetes-namespace", "validator-observability"),
                ("kubernetes-service-account", service_account),
            ):
                self.assertRegex(trust, re.escape(f'variable = "aws:RequestTag/{variable}"') + r'\s+' + re.escape(f'values   = ["{value}"]'))
            association = block("resource", "aws_eks_pod_identity_association", association_name, VALIDATOR_OBSERVABILITY_SOURCE)
            self.assertIn("cluster_name    = aws_eks_cluster.private.name", association)
            self.assertIn(f'service_account = "{service_account}"', association)

    def test_fluent_bit_can_only_write_the_three_owned_groups(self):
        policy = block("data", "aws_iam_policy_document", "validator_log_collector", VALIDATOR_OBSERVABILITY_SOURCE)
        self.assertEqual(re.findall(r'"(logs:[^"]+)"', policy),
                         ["logs:CreateLogStream", "logs:DescribeLogStreams", "logs:PutLogEvents"])
        self.assertEqual(re.findall(r'"\$\{aws_cloudwatch_log_group\.([^}]+)\}:\*"', policy),
                         ["validator_workloads.arn", "validator_security.arn", "validator_metrics.arn"])
        self.assertNotIn('"*"', policy)

    def test_encrypted_metrics_group_has_exact_name_and_retention(self):
        group = block("resource", "aws_cloudwatch_log_group", "validator_metrics")
        self.assertIn('name              = "/aws/eks/${var.name}/validator-metrics"', group)
        self.assertIn("retention_in_days = 365", group)
        self.assertIn("kms_key_id        = aws_kms_key.validator_audit.arn", group)
        self.assertIn("tags              = local.common_tags", group)

    def test_pod_identity_trust_is_bound_to_expected_eks_context(self):
        trust = block("data", "aws_iam_policy_document", "validator_metrics_collector_assume_role")
        self.assertIn('identifiers = ["pods.eks.amazonaws.com"]', trust)
        self.assertIn('actions = ["sts:AssumeRole", "sts:TagSession"]', trust)
        for condition, value in (
            ("aws:RequestTag/eks-cluster-arn", "arn:aws:eks:${var.aws_region}:${var.aws_account_id}:cluster/${var.name}"),
            ("aws:RequestTag/kubernetes-namespace", "local.validator_metrics_namespace"),
            ("aws:RequestTag/kubernetes-service-account", "local.validator_metrics_service_account"),
        ):
            self.assertIn(f'variable = "{condition}"', trust)
            self.assertIn(value, trust)
        self.assertNotIn('identifiers = ["*"]', trust)
        self.assertNotIn("aws:SourceArn", trust)
        self.assertNotIn("aws:SourceAccount", trust)

    def test_existing_validator_audit_key_allows_cloudwatch_log_group_encryption(self):
        assert_validator_audit_cloudwatch_grant(VALIDATOR_OBSERVABILITY_SOURCE)

    def test_validator_audit_grant_negative_mutations_fail(self):
        for mutated in (
            VALIDATOR_OBSERVABILITY_SOURCE.replace(
                "AllowCloudWatchLogsToEncryptValidatorLogGroups",
                "RemovedCloudWatchLogsGrant",
                1,
            ),
            VALIDATOR_OBSERVABILITY_SOURCE.replace(
                "/aws/eks/${var.name}/validator-*",
                "/aws/eks/${var.name}/validator-workloads",
                1,
            ),
        ):
            with self.assertRaises(AssertionError):
                assert_validator_audit_cloudwatch_grant(mutated)

    def test_logs_policy_is_write_only_and_group_scoped(self):
        policy = block("data", "aws_iam_policy_document", "validator_metrics_collector")
        self.assertIn('actions   = ["logs:CreateLogStream", "logs:DescribeLogStreams", "logs:PutLogEvents"]', policy)
        self.assertIn('resources = ["${aws_cloudwatch_log_group.validator_metrics.arn}:*"]', policy)
        self.assertNotIn('"logs:CreateLogGroup"', policy)
        self.assertNotIn("PutMetricData", policy)
        self.assertNotRegex(policy, r'"(?:s3|secretsmanager|kms|ssm):')
        self.assertNotIn('"*"', policy)

    def test_association_depends_on_created_cluster_and_has_exact_binding(self):
        association = block("resource", "aws_eks_pod_identity_association", "validator_metrics_collector")
        self.assertIn("cluster_name    = aws_eks_cluster.private.name", association)
        self.assertNotIn("cluster_name    = var.name", association)
        self.assertIn("namespace       = local.validator_metrics_namespace", association)
        self.assertIn("service_account = local.validator_metrics_service_account", association)
        self.assertIn("role_arn        = aws_iam_role.validator_metrics_collector.arn", association)
        self.assertIn('validator_metrics_namespace       = "validator-observability"', SOURCE)
        self.assertIn('validator_metrics_service_account = "validator-metrics-collector"', SOURCE)
        for output in (
            "validator_metrics_collector_role_arn",
            "validator_metrics_log_group_name",
            "validator_metrics_region",
            "validator_metrics_namespace",
            "validator_metrics_service_account",
        ):
            self.assertIn(f'output "{output}"', SOURCE)
        self.assertNotRegex(SOURCE, r'(?i)(access_key|secret_key|password)')


if __name__ == "__main__":
    unittest.main()
