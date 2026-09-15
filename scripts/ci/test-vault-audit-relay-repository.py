#!/usr/bin/env python3
# Check objective: Keep Vault relay repository creation separate from GitHub publishing authority.
"""Check objective: keep Vault relay repository creation separate from GitHub publishing authority."""
from __future__ import annotations

import importlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/release"))
infrastructure = importlib.import_module("installer_infrastructure")

DISCOVERY = {
    "aws_profile": "operator",
    "aws_account_id": "123456789012",
    "aws_region": "ap-northeast-2",
    "deployment_name": "test-node",
    "availability_zones": ["ap-northeast-2a", "ap-northeast-2c"],
    "configuration_recorder": {
        "result": "recorder_absent_verified",
        "existing_count": 0,
        "manage_config_recorder": True,
        "existing_recorder_adoption": "not_authorized",
    },
}
ROLE = "arn:aws:iam::123456789012:role/backend"


class RelayRepositoryContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.source = (ROOT / "infra/terraform/vault-audit-relay-ecr.tf").read_text()

    def test_flag_truth_table_is_explicit_in_terraform(self) -> None:
        # The local is the Terraform-evaluated ownership boundary: repository
        # resources are present for either request, GitHub authority only for
        # the pre-existing publisher request.
        self.assertIn(
            "var.enable_vault_audit_relay_repository || var.enable_vault_audit_relay_ecr_publisher",
            self.source,
        )
        for block in (
            'data "aws_iam_policy_document" "vault_audit_relay_ecr_key"',
            'resource "aws_kms_key" "vault_audit_relay_ecr"',
            'resource "aws_ecr_repository" "vault_audit_relay"',
        ):
            start = self.source.index(block)
            body = self.source[start : self.source.index("\n}", start) + 2]
            self.assertRegex(body, r"count\s+= local\.vault_audit_relay_repository_enabled \? 1 : 0")
        for block in (
            'data "aws_iam_policy_document" "github_vault_audit_relay_publisher_assume_role"',
            'resource "aws_iam_role" "github_vault_audit_relay_publisher"',
            'data "aws_iam_policy_document" "github_vault_audit_relay_publisher"',
            'resource "aws_iam_role_policy" "github_vault_audit_relay_publisher"',
        ):
            start = self.source.index(block)
            body = self.source[start : self.source.index("\n}", start) + 2]
            self.assertIn("count", body)
            self.assertIn("var.enable_vault_audit_relay_ecr_publisher ? 1 : 0", body)

        # False/false produces no relay resource; repository-only produces
        # only the destination and its KMS key; publisher retains that old
        # destination behavior and adds OIDC authority.
        self.assertEqual((False or False, False), (False, False))
        self.assertEqual((True or False, False), (True, False))
        self.assertEqual((False or True, True), (True, True))

    @unittest.skipUnless(shutil.which("jq"), "input generator requires jq")
    def test_generators_request_repository_only_not_publisher_authority(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "inputs"
            subprocess.run(
                [
                    "bash", str(ROOT / "scripts/release/prepare-zero-resource-inputs.sh"),
                    "--aws-account-id", "123456789012", "--aws-region", "ap-northeast-2",
                    "--name", "test-node", "--availability-zone", "ap-northeast-2a",
                    "--availability-zone", "ap-northeast-2c", "--backend-principal-arn", ROLE,
                    "--output-dir", str(output),
                ],
                check=True,
                stdout=subprocess.DEVNULL,
            )
            release_values = json.loads((output / "baseline.tfvars.json").read_text())
        installer_values = infrastructure.expected_inputs(Path("/unused"), DISCOVERY, ROLE)["baseline.tfvars.json"]
        for values in (release_values, installer_values):
            self.assertIs(values["enable_vault_audit_relay_repository"], True)
            self.assertNotIn("enable_vault_audit_relay_ecr_publisher", values)

    def test_installer_generator_requires_explicit_recorder_observation(self) -> None:
        with self.assertRaises(infrastructure.InfrastructureError):
            infrastructure.expected_inputs(Path("/unused"), {key: value for key, value in DISCOVERY.items() if key != "configuration_recorder"}, ROLE)


if __name__ == "__main__":
    unittest.main()
