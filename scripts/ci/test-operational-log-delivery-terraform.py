#!/usr/bin/env python3
# Check objective: Validate declarative operational-log delivery inventory scope.
"""Structural scope check for the declarative operational-log inventory.

This is intentionally a source-level Terraform contract test: it does not
claim a provider plan or live service delivery verification.
"""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[2]
SOURCE = (ROOT / "infra/terraform/operational-log-delivery.tf").read_text()

_CW_GROUPS = {
    "vpc_flow_logs": "/aws/vpc/{deployment}-baseline/flow-logs",
    "eks_control_plane": "/aws/eks/{deployment}/cluster",
    "cloudtrail": "/aws/cloudtrail/{deployment}-baseline-audit",
    "validator_workloads": "/aws/eks/{deployment}/validator-workloads",
    "validator_security": "/aws/eks/{deployment}/validator-security",
}
_BUCKETS = {
    "validator_audit": "node-validator-audit-123",
    "audit": "node-audit-123",
    "audit_access_logs": "node-audit-access-123",
    "audit_replica": "node-audit-replica-123",
    "audit_replica_access_logs": "node-audit-replica-access-123",
}
_CONFIG_IDS = {"config", "config-replica"}


def _fixture_contract_from_source(source, account, region, deployment, manage_config_recorder):
    """Build a synthetic contract from descriptor literals, not Terraform evaluation."""
    if not isinstance(account, str) or not isinstance(region, str) or not isinstance(deployment, str):
        raise ValueError("fixture identity must be text")
    if type(manage_config_recorder) is not bool:
        raise ValueError("fixture Config selector must be boolean")
    replica_region = "ap-northeast-1" if region != "ap-northeast-1" else "ap-northeast-2"
    cloudwatch = []
    for source_id, group_ref, stream_prefix in re.findall(
            r'\{ id = "([a-z0-9-]+)", group = aws_cloudwatch_log_group\.([a-z_]+)\.name, stream_prefix = "([^"]*)" \}', source):
        try:
            group = _CW_GROUPS[group_ref].format(deployment=deployment)
        except KeyError as error:
            raise AssertionError(f"unmatched CloudWatch descriptor reference: {group_ref}") from error
        cloudwatch.append({"id": source_id, "group": group, "stream_prefix": stream_prefix})
    s3 = []
    for source_id, bucket_ref, prefix, region_ref in re.findall(
            r'\{ id = "([a-z0-9-]+)", bucket = aws_s3_bucket\.([a-z_]+)\.id, prefix = "([^"]+)", region = (var\.aws_region|var\.audit_replica_region) \}', source):
        try:
            bucket = _BUCKETS[bucket_ref]
        except KeyError as error:
            raise AssertionError(f"unmatched S3 descriptor reference: {bucket_ref}") from error
        prefix = prefix.replace("${var.aws_account_id}", account).replace("${var.aws_region}", region)
        if source_id not in _CONFIG_IDS or manage_config_recorder:
            literal_region = region if region_ref == "var.aws_region" else replica_region
            s3.append({"id": source_id, "bucket": bucket, "prefix": prefix, "region": literal_region})
    if {item["id"] for item in cloudwatch} != {
        "vpc-flow-logs", "eks-api", "eks-audit", "eks-authenticator", "eks-controller-manager", "eks-scheduler",
        "cloudtrail-cloudwatch", "validator-workloads", "vault-security-cloudwatch",
    }:
        raise AssertionError("CloudWatch descriptor inventory is incomplete")
    expected_s3 = {
        "validator-archive", "cloudtrail-s3", "audit-access-audit", "audit-access-validator-audit",
        "audit-access-vault-snapshot", "cloudtrail-replica", "audit-replica-access-audit",
        "audit-replica-access-validator-audit", "audit-replica-access-vault-snapshot",
    } | (_CONFIG_IDS if manage_config_recorder else set())
    if {item["id"] for item in s3} != expected_s3:
        raise AssertionError("S3 descriptor inventory is incomplete")
    return {
        "schema_version": 1,
        "account_id": account,
        "region": region,
        "deployment_name": deployment,
        "manage_config_recorder": manage_config_recorder,
        "cloudwatch": cloudwatch,
        "s3": s3,
    }


def fixture_contract(account="123456789012", region="ap-northeast-2", deployment="hoodi-node", manage_config_recorder=False):
    """Return the bounded HCL-literal substitution fixture used by consumers."""
    return _fixture_contract_from_source(SOURCE, account, region, deployment, manage_config_recorder)


class OperationalLogDeliveryTerraformTest(unittest.TestCase):
    def test_inventory_has_fixed_schema_and_all_owned_destinations(self):
        self.assertIn('output "operational_log_delivery"', SOURCE)
        for field in ("schema_version  = 1", "account_id      = var.aws_account_id", "region          = var.aws_region", "deployment_name = var.name", "manage_config_recorder = var.manage_config_recorder", "cloudwatch", "s3"):
            self.assertIn(field, SOURCE)
        ids = re.findall(r'\{ id = "([a-z0-9-]+)", (?:group|bucket) =', SOURCE)
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(set(ids), {
            "vpc-flow-logs", "eks-api", "eks-audit", "eks-authenticator", "eks-controller-manager", "eks-scheduler", "cloudtrail-cloudwatch", "validator-workloads", "vault-security-cloudwatch",
            "validator-archive", "cloudtrail-s3", "audit-access-audit", "audit-access-validator-audit", "audit-access-vault-snapshot", "cloudtrail-replica", "audit-replica-access-audit", "audit-replica-access-validator-audit", "audit-replica-access-vault-snapshot", "config", "config-replica",
        })
        for prefix in ("kube-apiserver-", "kube-apiserver-audit-", "authenticator-", "kube-controller-manager-", "kube-scheduler-", "fluent-bit-"):
            self.assertIn(f'stream_prefix = "{prefix}"', SOURCE)
        self.assertIn('prefix = "AWSLogs/${var.aws_account_id}/CloudTrail/${var.aws_region}/"', SOURCE)
        self.assertIn('var.manage_config_recorder ? [', SOURCE)

    def test_fixture_contract_uses_all_descriptor_rows_and_conditional_config(self):
        without_config = fixture_contract()
        with_config = fixture_contract(manage_config_recorder=True)
        self.assertFalse(without_config["manage_config_recorder"])
        self.assertTrue(with_config["manage_config_recorder"])
        self.assertEqual(len(without_config["cloudwatch"]), 9)
        self.assertEqual(len(without_config["s3"]), 9)
        self.assertEqual(len(with_config["s3"]), 11)
        self.assertEqual({item["id"] for item in with_config["s3"]} - {item["id"] for item in without_config["s3"]}, _CONFIG_IDS)
        self.assertEqual(without_config["s3"][1]["prefix"], "AWSLogs/123456789012/CloudTrail/ap-northeast-2/")
        self.assertEqual(next(item["region"] for item in without_config["s3"] if item["id"] == "cloudtrail-replica"), "ap-northeast-1")
        self.assertEqual(next(item["region"] for item in fixture_contract(region="ap-northeast-1")["s3"] if item["id"] == "cloudtrail-replica"), "ap-northeast-2")

    def test_fixture_contract_rejects_unmatched_descriptor_reference(self):
        malformed = SOURCE.replace("aws_s3_bucket.audit.id", "aws_s3_bucket.unknown.id", 1)
        with self.assertRaisesRegex(AssertionError, "unmatched S3 descriptor reference"):
            _fixture_contract_from_source(malformed, "123456789012", "ap-northeast-2", "hoodi-node", False)

    def test_reader_policy_is_metadata_only_and_exactly_scoped(self):
        policy = SOURCE.split('data "aws_iam_policy_document" "validator_audit_reader_operational_delivery" {', 1)[1].split('resource "aws_iam_role_policy" "validator_audit_reader_operational_delivery"', 1)[0]
        self.assertIn('"logs:FilterLogEvents"', policy)
        self.assertIn('"s3:ListBucket"', policy)
        self.assertNotRegex(policy, r'"s3:GetObject|"kms:')
        self.assertNotIn('"*"', policy)
        for bucket in ("validator_audit", "audit", "audit_access_logs", "audit_replica", "audit_replica_access_logs"):
            self.assertIn(f'aws_s3_bucket.{bucket}.arn', policy)
        self.assertIn('variable = "s3:prefix"', policy)
        self.assertIn('role   = aws_iam_role.validator_audit_reader.id', SOURCE)


if __name__ == "__main__":
    unittest.main()
