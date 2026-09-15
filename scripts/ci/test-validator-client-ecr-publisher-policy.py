#!/usr/bin/env python3
# Check objective: Validate protected validator-client publisher read scope.
"""Offline source contract for the protected validator-client publisher read scope.

This checks the Terraform declaration only; it is not proof of a deployed IAM
policy or an ECR publication.
"""
from __future__ import annotations

from pathlib import Path
import re


SOURCE = (Path(__file__).resolve().parents[2] / "infra/terraform/validator-client-ecr-mirror.tf").read_text(encoding="utf-8")
EXPECTED = "resources = [aws_ecr_repository.validator_client[0].arn, aws_ecr_repository.validator_signing_fence[0].arn, aws_ecr_repository.validator_signer_identity_probe[0].arn]"


def validate(source: str) -> None:
    statements = re.findall(r"statement\s*\{([\s\S]*?)\n  \}", source)
    matches = [statement for statement in statements if '"ecr:GetDownloadUrlForLayer"' in statement]
    assert len(matches) == 1, "layer-download authority must have exactly one statement"
    statement = matches[0]
    assert re.search(r'actions\s*=\s*\["ecr:GetDownloadUrlForLayer"\]', statement), "layer-download statement must grant exactly one action"
    assert EXPECTED in statement, "layer-download authority must name exactly Prysm, Fence, and signer-probe repositories"
    assert 'resources = ["*"]' not in statement and "ecr:*" not in statement, "layer-download authority must not be wildcarded"


validate(SOURCE)
for invalid in (
    SOURCE.replace(EXPECTED, 'resources = [aws_ecr_repository.validator_signing_fence[0].arn]'),
    SOURCE.replace(EXPECTED, 'resources = [aws_ecr_repository.validator_client[0].arn, aws_ecr_repository.validator_signing_fence[0].arn]'),
    SOURCE.replace(EXPECTED, 'resources = [aws_ecr_repository.validator_client[0].arn, aws_ecr_repository.validator_signing_fence[0].arn, aws_ecr_repository.unrelated[0].arn]'),
    SOURCE.replace('actions   = ["ecr:GetDownloadUrlForLayer"]', 'actions   = ["ecr:GetDownloadUrlForLayer", "ecr:DeleteRepository"]'),
    SOURCE.replace(EXPECTED, 'resources = ["*"]'),
):
    try:
        validate(invalid)
    except AssertionError:
        continue
    raise SystemExit("unsafe validator-client publisher policy unexpectedly accepted")

print("PASS: validator-client publisher layer-read scope is source-bound to Prysm, Fence, and signer probe only.")
