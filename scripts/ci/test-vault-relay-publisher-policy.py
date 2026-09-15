#!/usr/bin/env python3
# Check objective: Enforce the restricted Vault audit-relay publisher IAM source contract.
"""Strict source contract, not an HCL parser or proof of live IAM permissions."""
import re
from pathlib import Path


def validate(source):
    block = re.search(
        r'data "aws_iam_policy_document" "github_vault_audit_relay_publisher" \{\n(.*?)\n\}',
        source, re.S,
    )
    assert block, "publisher policy block missing"
    statements = re.findall(r"statement \{\s*actions\s*=\s*\[([^\n]+)\]\s*resources\s*=\s*\[([^\n]+)\]\s*\}", block[1])
    assert len(statements) == 2, "expected exactly two simple policy statements"
    assert block[1].count("statement {") == 2, "unexpected additional statement"
    assert statements[0][0].strip() == '"ecr:GetAuthorizationToken"'
    assert statements[0][1].strip() == '"*"'
    expected = {
        "ecr:BatchCheckLayerAvailability", "ecr:BatchGetImage",
        "ecr:CompleteLayerUpload", "ecr:DescribeImages",
        "ecr:GetDownloadUrlForLayer", "ecr:InitiateLayerUpload",
        "ecr:PutImage", "ecr:UploadLayerPart",
    }
    actions = re.findall(r'"([^"]+)"', statements[1][0])
    assert len(actions) == len(expected) and set(actions) == expected, "publisher action drift"
    assert statements[1][1].strip() == "aws_ecr_repository.vault_audit_relay[0].arn", "repository scope drift"


source = (Path(__file__).resolve().parents[2] / "infra/terraform/vault-audit-relay-ecr.tf").read_text()
validate(source)
for bad in (
    source.replace('"ecr:GetDownloadUrlForLayer", ', ''),
    source.replace('"ecr:GetDownloadUrlForLayer"', '"ecr:*"'),
    source.replace('resources = [aws_ecr_repository.vault_audit_relay[0].arn]', 'resources = ["*"]'),
):
    try:
        validate(bad)
    except AssertionError:
        continue
    raise AssertionError("unsafe or incomplete publisher policy passed")
print("PASS: relay publisher action and repository scope; three negative mutations rejected")
