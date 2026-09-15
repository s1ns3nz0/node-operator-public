#!/usr/bin/env python3
# Check objective: Reject Vault recovery isolation and IAM boundary regressions without AWS calls.
"""Parse recovery HCL and reject isolation/IAM regressions; no AWS calls.

Uses python-hcl2 supplied by the pinned security-scanner image. Terraform's
separate offline validation checks provider schema and expression correctness.
This is not a substitute for reviewing the refresh-backed saved apply plan.
"""
import copy
from pathlib import Path
import unittest

import hcl2

ROOT = Path(__file__).resolve().parents[2]


def normalize_scanner_hcl(value):
    # Checkov's parser fork wraps each attribute in an occurrence list. Keep
    # nested block lists intact; Terraform separately rejects duplicate attrs.
    block_keys = {"resource", "data", "provider", "terraform", "statement", "condition",
                  "principals", "filter", "metadata_options", "root_block_device",
                  "lifecycle", "precondition", "validation", "backend", "required_providers"}
    if isinstance(value, dict):
        result = {}
        for key, item in value.items():
            if key.startswith("__"):
                continue
            if key not in block_keys and isinstance(item, list) and len(item) == 1:
                item = item[0]
            result[key] = normalize_scanner_hcl(item)
        return result
    if isinstance(value, list):
        return [normalize_scanner_hcl(item) for item in value]
    return value


def blocks(document, kind):
    result = {}
    for entry in document.get(kind, []):
        for resource_type, names in entry.items():
            for name, value in names.items():
                key = (resource_type, name)
                assert key not in result, "duplicate block"
                result[key] = value
    return result


def check(document):
    resources = blocks(document, "resource")
    allowed_types = {"aws_vpc", "aws_subnet", "aws_route_table", "aws_route_table_association",
                     "aws_security_group", "aws_vpc_security_group_ingress_rule",
                     "aws_vpc_security_group_egress_rule", "aws_vpc_endpoint", "aws_iam_role",
                     "aws_iam_role_policy", "aws_iam_instance_profile", "aws_instance",
                     "aws_default_security_group", "aws_flow_log", "aws_cloudwatch_log_group", "aws_kms_key"}
    assert all(kind in allowed_types for kind, _ in resources), "unexpected infrastructure ownership"
    assert resources["aws_vpc", "recovery"]["cidr_block"] == "10.91.0.0/24"
    assert resources["aws_subnet", "recovery"]["map_public_ip_on_launch"] is False
    assert "route" not in resources["aws_route_table", "recovery"], "unexpected route"
    default_sg = resources["aws_default_security_group", "recovery"]
    assert default_sg["vpc_id"] == "${aws_vpc.recovery.id}"
    assert default_sg["ingress"] == [] and default_sg["egress"] == []
    assert resources["aws_flow_log", "recovery"]["traffic_type"] == "ALL"
    assert resources["aws_flow_log", "recovery"]["vpc_id"] == "${aws_vpc.recovery.id}"
    log_group = resources["aws_cloudwatch_log_group", "flow_logs"]
    assert log_group["retention_in_days"] == 365
    assert log_group["kms_key_id"] == "${aws_kms_key.flow_logs.arn}"
    assert [name for kind, name in resources if kind == "aws_kms_key"] == ["flow_logs"]
    assert resources["aws_kms_key", "flow_logs"]["enable_key_rotation"] is True
    host = resources["aws_instance", "host"]
    assert host["associate_public_ip_address"] is False
    assert host["monitoring"] is False
    assert host["metadata_options"][0]["http_tokens"] == "required"
    assert host["metadata_options"][0]["http_put_response_hop_limit"] == 1
    assert host["root_block_device"][0]["encrypted"] is True
    assert "key_name" not in host
    host_sg = resources["aws_security_group", "host"]
    assert host_sg["ingress"] == []
    assert "egress" not in host_sg, "standalone rules exclusively own host egress"
    endpoint_sg = resources["aws_security_group", "endpoints"]
    assert endpoint_sg["egress"] == []
    assert "ingress" not in endpoint_sg, "standalone rules exclusively own endpoint ingress"
    ingress = [value for (kind, _), value in resources.items() if kind == "aws_vpc_security_group_ingress_rule"]
    assert len(ingress) == 1
    assert ingress[0]["referenced_security_group_id"] == "${aws_security_group.host.id}"
    assert ingress[0]["security_group_id"] == "${aws_security_group.endpoints.id}"
    egress = [value for (kind, _), value in resources.items() if kind == "aws_vpc_security_group_egress_rule"]
    assert len(egress) == 2
    for rule in ingress + egress:
        assert rule["from_port"] == 443 and rule["to_port"] == 443 and rule["ip_protocol"] == "tcp"
        assert "cidr_ipv4" not in rule and "cidr_ipv6" not in rule
    data = blocks(document, "data")
    s3_statements = data["aws_iam_policy_document", "s3_endpoint"]["statement"]
    assert len(s3_statements) == 2
    assert {s["sid"] for s in s3_statements} == {"ReadEcrLayerObjectsOnly", "ReadOnlyExactSnapshotVersion"}
    for statement in s3_statements:
        assert statement["effect"] == "Allow"
        assert statement["principals"] == [{"type": "AWS", "identifiers": ["*"]}]
        if statement["sid"] == "ReadEcrLayerObjectsOnly":
            assert statement["actions"] == ["s3:GetObject"]
            assert statement["resources"] == ["${local.starport_object_arn}"]
        else:
            assert statement["actions"] == ["s3:GetObjectVersion"]
            assert statement["resources"] == ["${local.snapshot_object_arn}"]
            assert len(statement["condition"]) == 2
            conditions = {c["variable"]: c for c in statement["condition"]}
            assert conditions == {
                "aws:PrincipalArn": {"test": "StringEquals", "variable": "aws:PrincipalArn",
                                     "values": ["${aws_iam_role.host.arn}"]},
                "s3:VersionId": {"test": "StringEquals", "variable": "s3:VersionId",
                                 "values": ["${var.snapshot_version_id}"]},
            }
    assert data["aws_ami", "ecs_al2023"]["owners"] == ["591542846629"]
    policy = data["aws_iam_policy_document", "host"]["statement"]
    approved_actions = {"ssm:UpdateInstanceInformation", "ssmmessages:CreateControlChannel",
        "ssmmessages:CreateDataChannel", "ssmmessages:OpenControlChannel", "ssmmessages:OpenDataChannel",
        "ec2messages:AcknowledgeMessage", "ec2messages:DeleteMessage", "ec2messages:FailMessage",
        "ec2messages:GetEndpoint", "ec2messages:GetMessages", "ec2messages:SendReply",
        "s3:GetObjectVersion", "s3:GetObject", "kms:Decrypt", "kms:DescribeKey", "kms:Encrypt",
        "ecr:BatchCheckLayerAvailability", "ecr:BatchGetImage", "ecr:DescribeImages",
        "ecr:GetDownloadUrlForLayer", "ecr:GetAuthorizationToken"}
    for statement in policy:
        if statement.get("effect") == "Allow":
            assert set(statement["actions"]) <= approved_actions, "unapproved workload action"
    by_sid = {s["sid"]: s for s in policy}
    snapshot = by_sid["ReadExactSnapshotVersion"]
    assert snapshot["actions"] == ["s3:GetObjectVersion"]
    assert snapshot["resources"] == ["${local.snapshot_object_arn}"]
    assert snapshot["condition"] == [{"test": "StringEquals", "variable": "s3:VersionId",
                                       "values": ["${var.snapshot_version_id}"]}]
    assert by_sid["AutoUnsealOnly"]["resources"] == ["${var.auto_unseal_kms_key_arn}"]
    decrypt = by_sid["DecryptSnapshotOnlyThroughS3ForExactObject"]
    assert decrypt["resources"] == ["${var.snapshot_kms_key_arn}"]
    assert any(c["variable"] == "kms:ViaService" and c["test"] == "StringEquals"
               and c["values"] == ["s3.${var.aws_region}.amazonaws.com"] for c in decrypt["condition"])
    for sid in ("DenySnapshotReadAfterRecoveryExpiry", "DenyKmsUseAfterRecoveryExpiry"):
        assert by_sid[sid]["effect"] == "Deny"
        assert by_sid[sid]["condition"] == [{"test": "DateGreaterThanEquals", "variable": "aws:CurrentTime",
                                             "values": ["${var.recovery_expiry}"]}]


class BoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with (ROOT / "infra/vault-recovery/main.tf").open() as stream:
            cls.document = hcl2.load(stream)
        if isinstance(blocks(cls.document, "resource")["aws_vpc", "recovery"]["cidr_block"], list):
            cls.document = normalize_scanner_hcl(cls.document)

    def test_current_module(self):
        check(self.document)

    def test_dangerous_mutations_rejected(self):
        mutations = [
            lambda d: d["resource"].append({"aws_internet_gateway": {"unsafe": {}}}),
            lambda d: blocks(d, "resource")["aws_instance", "host"].update(associate_public_ip_address=True),
            lambda d: blocks(d, "resource")["aws_route_table", "recovery"].update(route=[{"cidr_block": "0.0.0.0/0"}]),
            lambda d: blocks(d, "data")["aws_iam_policy_document", "host"]["statement"].append({"sid": "Unsafe", "effect": "Allow", "actions": ["kms:CreateGrant"], "resources": ["*"]}),
            lambda d: blocks(d, "data")["aws_iam_policy_document", "host"]["statement"].append({"sid": "Unsafe", "effect": "Allow", "actions": ["ssm:GetParameter"], "resources": ["*"]}),
            lambda d: blocks(d, "data")["aws_ami", "ecs_al2023"].update(owners=["amazon"]),
            lambda d: blocks(d, "resource")["aws_default_security_group", "recovery"].update(egress=[{}]),
            lambda d: blocks(d, "resource")["aws_security_group", "host"].update(egress=[]),
            lambda d: blocks(d, "resource")["aws_security_group", "endpoints"].update(ingress=[]),
            lambda d: blocks(d, "resource")["aws_flow_log", "recovery"].update(traffic_type="REJECT"),
            lambda d: blocks(d, "resource")["aws_cloudwatch_log_group", "flow_logs"].update(retention_in_days=30),
        ]
        for index, mutation in enumerate(mutations):
            with self.subTest(index=index):
                modified = copy.deepcopy(self.document)
                mutation(modified)
                with self.assertRaises(AssertionError):
                    check(modified)

    def test_gateway_snapshot_mutations_rejected(self):
        mutations = [
            lambda s: s.update(principals=[{"type": "AWS", "identifiers": ["${aws_iam_role.host.arn}"]}]),
            lambda s: s.update(condition=[]),
            lambda s: s["condition"][0].update(values=["*"]),
            lambda s: s["condition"][0].update(test="StringEqualsIfExists"),
            lambda s: s["condition"][1].update(values=["*"]),
            lambda s: s.update(resources=["*"]),
            lambda s: s.update(actions=["s3:GetObject"]),
        ]
        for index, mutation in enumerate(mutations):
            with self.subTest(index=index):
                modified = copy.deepcopy(self.document)
                statements = blocks(modified, "data")["aws_iam_policy_document", "s3_endpoint"]["statement"]
                snapshot = next(s for s in statements if s["sid"] == "ReadOnlyExactSnapshotVersion")
                mutation(snapshot)
                with self.assertRaises(AssertionError):
                    check(modified)


if __name__ == "__main__":
    unittest.main()
