#!/usr/bin/env python3
"""Offline structural checks for the disabled private release runner."""
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
SOURCE = (ROOT / "infra/terraform/private-release-runner.tf").read_text()


class PrivateReleaseRunnerContractTests(unittest.TestCase):
    def test_disabled_repository_scoped_github_runner(self):
        for required in (
            'variable "enable_private_release_runner"', 'default     = false',
            'name          = "${local.name_prefix}-private-release"',
            'type      = "GITHUB"', 'location  = "https://github.com/${var.github_repository}"',
            'type     = "CODECONNECTIONS"', 'WORKFLOW_JOB_QUEUED',
            'private_release_runner_connection_arn',
            'private_release_runner_subnet_ids',
            'aws:SourceAccount',
            'arn:aws:codebuild:${var.aws_region}:${var.aws_account_id}:project/${local.name_prefix}-private-release',
            'depends_on = [aws_iam_role_policy.private_release_runner]',
        ):
            self.assertIn(required, SOURCE)
        self.assertNotIn('ghcr.io', SOURCE)
        self.assertNotIn('keyless', SOURCE)

    def test_historical_managed_runtime_and_private_boundary(self):
        for required in (
            'image                       = "aws/codebuild/standard:7.0"',
            'compute_type                = "BUILD_GENERAL1_MEDIUM"',
            'type                        = "LINUX_CONTAINER"',
            'privileged_mode             = true',
            'image_pull_credentials_type = "CODEBUILD"',
            'from_port   = 8200', 'cidr_blocks = [local.network_vpc_cidr]',
            'existing private-subnet NAT route', 'kms_key_id        = aws_kms_key.private_release_runner_logs[0].arn',
            'log-group:/aws/codebuild/${local.name_prefix}-private-release"]',
        ):
            self.assertIn(required, SOURCE)
        self.assertNotIn('ingress {', SOURCE)
        self.assertNotIn('log-group:/aws/codebuild/${local.name_prefix}-private-release:*', SOURCE)

    def test_role_is_bounded_to_runner_operations(self):
        for required in (
            'WriteOnlyEncryptedPrivateReleaseLogs', 'DescribeOnlyPrivateCluster',
            'AuthorizePrivateEcrSmokeOnly', 'UseOnlyApprovedGitHubConnection',
            'ManageOnlyCodeBuildVpcNetworkInterfaces',
            'DescribeOnlyCodeBuildVpcNetworkConfiguration',
            'DelegateOnlyCodeBuildVpcNetworkInterfacePermission',
            'ec2:AuthorizedService', 'codebuild.amazonaws.com',
            'arn:aws:ec2:${var.aws_region}:${var.aws_account_id}:network-interface/*',
        ):
            self.assertIn(required, SOURCE)
        self.assertNotIn('"secretsmanager:GetSecretValue"', SOURCE)
        self.assertNotIn('"s3:GetObject"', SOURCE)

    def test_webhook_filter_is_not_misrepresented_as_release_admission(self):
        self.assertIn('WORKFLOW_JOB_QUEUED', SOURCE)
        self.assertIn('cannot itself distinguish\n  # trusted tag jobs from queued PR jobs', SOURCE)
        self.assertIn('Vault claim validation remain the release-admission boundary', SOURCE)


if __name__ == "__main__":
    unittest.main()
