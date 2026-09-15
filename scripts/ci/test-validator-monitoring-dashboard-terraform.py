#!/usr/bin/env python3
"""Offline Terraform contract for the optional validator CloudWatch dashboard.

The populated branch renders the actual local dashboard generator, then plans
the copied root module with synthetic credentials. It never refreshes or
applies. CI explicitly runs Terraform in the digest-pinned offline container;
the default remains a direct host Terraform invocation for local use.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / "infra/terraform"
SOURCE = (MODULE / "validator-monitoring-dashboard.tf").read_text()
GENERATOR = ROOT / "scripts/release/validator_monitoring_dashboard.py"
DEPLOYMENT = "node-operator"
REGION = "ap-northeast-2"
VALIDATOR_SET = "hoodi-a"
PUBLIC_KEY = "0x" + "a" * 96
TERRAFORM_MODE = "VALIDATOR_DASHBOARD_TERRAFORM_MODE"
TERRAFORM_IMAGE = "TERRAFORM_IMAGE"


def _container_image() -> str:
    image = os.environ.get(TERRAFORM_IMAGE, "")
    if not re.fullmatch(r".+@sha256:[0-9a-f]{64}", image):
        raise ValueError("container Terraform requires a digest-pinned TERRAFORM_IMAGE")
    return image


def _ignore_local_terraform_artifacts(directory: str, names: list[str]) -> set[str]:
    """Exclude local execution state without excluding checked-in fixtures or lockfile."""
    ignored = {
        name for name in names
        if name == ".terraform"
        or name.endswith((".tfstate", ".tfstate.backup", ".tfplan"))
    }
    if Path(directory) == MODULE:
        ignored.update(name for name in names if name.endswith((".tfvars", ".tfvars.json")))
    return ignored


class ValidatorMonitoringDashboardTerraformTest(unittest.TestCase):
    def test_source_keeps_body_optional_and_region_bound(self):
        self.assertIn('variable "validator_monitoring_dashboard_body"', SOURCE)
        self.assertIn("type        = string", SOURCE)
        self.assertIn("default     = null", SOURCE)
        self.assertIn("nullable    = true", SOURCE)
        self.assertIn("startswith(jsonencode(jsondecode(var.validator_monitoring_dashboard_body).widgets), \"[\")", SOURCE)
        self.assertIn('resource "aws_cloudwatch_dashboard" "validator"', SOURCE)
        self.assertIn("count = var.validator_monitoring_dashboard_body == null ? 0 : 1", SOURCE)
        self.assertIn('dashboard_name = "${var.name}-validator"', SOURCE)
        self.assertIn("dashboard_body = var.validator_monitoring_dashboard_body", SOURCE)
        self.assertIn("try(widget.properties.region, \"\") == var.aws_region", SOURCE)
        self.assertNotIn("validator_set", SOURCE)
        self.assertNotRegex(SOURCE, r"(?m)^\s*(?:aws_iam_|data \"aws_iam_)")

    def test_null_and_generated_dashboard_branches_plan_offline(self):
        body = self._render_dashboard_body()
        with tempfile.TemporaryDirectory(prefix="validator-monitoring-dashboard.") as temporary:
            temporary_path = Path(temporary)
            workspace = temporary_path / "terraform-source"
            self._copy_root_module(workspace)
            extra = workspace / "validator-monitoring-dashboard.tfvars.json"
            extra.write_text(json.dumps({"validator_monitoring_dashboard_body": json.dumps(body)}))
            invalid = workspace / "invalid-dashboard.tfvars.json"
            invalid.write_text(json.dumps({"validator_monitoring_dashboard_body": "{"}))
            empty = workspace / "empty-dashboard.tfvars.json"
            empty.write_text(json.dumps({"validator_monitoring_dashboard_body": json.dumps({"widgets": []})}))
            wrong_region = workspace / "wrong-region-dashboard.tfvars.json"
            wrong_region.write_text(json.dumps({"validator_monitoring_dashboard_body": json.dumps(self._render_dashboard_body("us-east-1"))}))
            baseline = "fixtures/offline-baseline.tfvars"
            self.assertTrue((workspace / baseline).is_file())
            self.assertFalse((workspace / "terraform.tfvars").exists())

            self._terraform(workspace, "fmt", "-check", "-recursive")
            self._terraform(workspace, "init", "-backend=false", "-input=false", "-get=false", "-lockfile=readonly")
            self._terraform(workspace, "validate")
            # Keep plans in the copied module so a container needs no mount of
            # the host temporary directory beyond that isolated workspace.
            null_plan = Path("null.tfplan")
            filled_plan = Path("filled.tfplan")
            self._terraform(workspace, "plan", "-refresh=false", "-input=false", f"-var-file={baseline}", f"-out={null_plan}")
            self._terraform(
                workspace,
                "plan",
                "-refresh=false",
                "-input=false",
                f"-var-file={baseline}",
                f"-var-file={extra.name}",
                f"-out={filled_plan}",
            )
            null_json = self._show_plan(workspace, null_plan)
            filled_json = self._show_plan(workspace, filled_plan)
            self._assert_plan_rejected(workspace, baseline, invalid.name, ("validator_monitoring_dashboard_body must be null", "widgets array"))
            self._assert_plan_rejected(workspace, baseline, empty.name, ("validator_monitoring_dashboard_body must be null", "widgets array"))
            self._assert_plan_rejected(workspace, baseline, wrong_region.name, ("Every metric and log widget", "var.aws_region"))

        null_addresses = {change["address"] for change in null_json["resource_changes"]}
        self.assertNotIn("aws_cloudwatch_dashboard.validator[0]", null_addresses)
        self.assertIsNone(null_json["planned_values"]["outputs"]["validator_monitoring_dashboard_name"]["value"])
        changes = {change["address"]: change["change"]["actions"] for change in filled_json["resource_changes"]}
        # Inspect Terraform's resolved IAM JSON, not merely source substrings.
        # This proves the offline plan's bindings, not live STS authorization.
        resources = {item["address"]: item.get("values", {}) for item in filled_json["planned_values"]["root_module"]["resources"]}
        configured = {item["address"]: item for item in filled_json["configuration"]["root_module"]["resources"]}
        for role, service_account in (
            ("validator_log_collector", "validator-log-collector"),
            ("validator_audit_reader", "validator-audit-reader"),
            ("validator_metrics_collector", "validator-metrics-collector"),
        ):
            trust = json.loads(resources[f"aws_iam_role.{role}"]["assume_role_policy"])
            self.assertEqual(len(trust["Statement"]), 1)
            statement = trust["Statement"][0]
            self.assertEqual(statement["Principal"], {"Service": "pods.eks.amazonaws.com"})
            self.assertEqual(set(statement["Action"]), {"sts:AssumeRole", "sts:TagSession"})
            self.assertEqual(statement["Condition"], {"StringEquals": {
                "aws:RequestTag/eks-cluster-arn": f"arn:aws:eks:{REGION}:123456789012:cluster/{DEPLOYMENT}",
                "aws:RequestTag/kubernetes-namespace": "validator-observability",
                "aws:RequestTag/kubernetes-service-account": service_account,
            }})
            association = configured[f"aws_eks_pod_identity_association.{role}"]
            self.assertIn("aws_eks_cluster.private.name", association["expressions"]["cluster_name"]["references"])
        self.assertEqual(changes["aws_cloudwatch_dashboard.validator[0]"], ["create"])
        dashboard = next(
            item for item in filled_json["planned_values"]["root_module"]["resources"]
            if item["address"] == "aws_cloudwatch_dashboard.validator[0]"
        )
        self.assertEqual(dashboard["values"]["dashboard_name"], f"{DEPLOYMENT}-validator")
        planned_body = json.loads(dashboard["values"]["dashboard_body"])
        self.assertEqual(planned_body["widgets"], body["widgets"])
        self.assertEqual(filled_json["planned_values"]["outputs"]["validator_monitoring_dashboard_name"]["value"], f"{DEPLOYMENT}-validator")
        self.assertNotIn(PUBLIC_KEY, dashboard["values"]["dashboard_body"])
        for widget in planned_body["widgets"]:
            if widget["type"] in {"metric", "log"}:
                self.assertEqual(widget["properties"]["region"], REGION)

    def _render_dashboard_body(self, region: str = REGION):
        result = subprocess.run(
            [
                "python3", str(GENERATOR), "--deployment", DEPLOYMENT,
                "--region", region, "--validator-set", VALIDATOR_SET,
                "--public-key", PUBLIC_KEY,
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return json.loads(result.stdout)

    def _copy_root_module(self, workspace: Path):
        shutil.copytree(MODULE, workspace, ignore=_ignore_local_terraform_artifacts)
        (workspace / "backend.tf").unlink()
        for name in (
            "argocd-private-values.example.yaml",
            "cert-manager-values.example.yaml",
            "vault-tls-internal-ca.example.yaml",
        ):
            source = ROOT / "docs/gitops" / name
            destination = workspace / name
            if not destination.exists() and source.is_file():
                shutil.copy2(source, destination)

    def _terraform(self, workspace: Path, *arguments: str):
        result = self._terraform_result(workspace, *arguments)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def _assert_plan_rejected(self, workspace: Path, baseline: str, extra: str, messages: tuple[str, ...]):
        result = self._terraform_result(
            workspace,
            "plan",
            "-refresh=false",
            "-input=false",
            "-target=aws_cloudwatch_dashboard.validator",
            f"-var-file={baseline}",
            f"-var-file={extra}",
        )
        self.assertNotEqual(result.returncode, 0, "invalid dashboard input unexpectedly planned")
        diagnostics = result.stdout + result.stderr
        for message in messages:
            self.assertIn(message, diagnostics)
        self.assertNotIn("Invalid function argument", diagnostics)

    def _terraform_environment(self, workspace: Path):
        environment = dict(os.environ)
        for name in (
            "AWS_SESSION_TOKEN", "AWS_SECURITY_TOKEN", "AWS_PROFILE", "AWS_DEFAULT_PROFILE",
            "AWS_ROLE_ARN", "AWS_WEB_IDENTITY_TOKEN_FILE",
            "AWS_CONTAINER_CREDENTIALS_FULL_URI", "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
        ):
            environment.pop(name, None)
        for name in tuple(environment):
            if name == "TF_CLI_ARGS" or name.startswith("TF_CLI_ARGS_") or name.startswith("TF_VAR_"):
                environment.pop(name)
        environment.update({
            "AWS_ACCESS_KEY_ID": "offline",
            "AWS_SECRET_ACCESS_KEY": "offline",
            "AWS_EC2_METADATA_DISABLED": "true",
            "TF_DATA_DIR": str(workspace.parent / "terraform-data"),
        })
        return environment

    def _terraform_result(self, workspace: Path, *arguments: str):
        mode = os.environ.get(TERRAFORM_MODE, "host")
        if mode == "container":
            command = [
                "docker", "run", "--rm", "--platform", "linux/amd64",
                "--pull", "never", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                "--user", f"{os.getuid()}:{os.getgid()}", "--network", "none",
                "--volume", f"{workspace.resolve()}:/workspace:rw",
                "--workdir", "/workspace",
                "--env", "AWS_ACCESS_KEY_ID=offline",
                "--env", "AWS_SECRET_ACCESS_KEY=offline",
                "--env", "AWS_EC2_METADATA_DISABLED=true",
                "--env", "TF_DATA_DIR=/workspace/.terraform-data",
                _container_image(), "terraform", "-chdir=/workspace", *arguments,
            ]
            environment = None
        elif mode == "host":
            command = ["terraform", f"-chdir={workspace}", *arguments]
            environment = self._terraform_environment(workspace)
        else:
            raise ValueError(f"unsupported {TERRAFORM_MODE}: {mode}")
        return subprocess.run(
            command,
            cwd=ROOT,
            env=environment,
            capture_output=True,
            text=True,
            timeout=60,
        )

    def _show_plan(self, workspace: Path, plan: Path):
        result = self._terraform_result(workspace, "show", "-json", str(plan))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return json.loads(result.stdout)


class ContainerInvocationContractTest(unittest.TestCase):
    def test_workspace_copy_excludes_local_state_and_auto_vars_but_keeps_lockfile_and_fixture(self):
        ignored = _ignore_local_terraform_artifacts(str(MODULE), [
            ".terraform", ".terraform.lock.hcl", "terraform.tfvars", "terraform.tfvars.json",
            "developer.auto.tfvars", "developer.auto.tfvars.json", "production.tfvars", "terraform.tfstate",
            "terraform.tfstate.backup", "saved.tfplan", "fixtures",
        ])
        self.assertEqual(ignored, {
            ".terraform", "terraform.tfvars", "terraform.tfvars.json", "developer.auto.tfvars",
            "developer.auto.tfvars.json", "production.tfvars", "terraform.tfstate", "terraform.tfstate.backup", "saved.tfplan",
        })
        self.assertEqual(_ignore_local_terraform_artifacts(str(MODULE / "fixtures"), ["offline-baseline.tfvars", "nested.tfstate"]), {"nested.tfstate"})

    def test_workspace_copy_keeps_reviewed_fixture_but_excludes_root_and_nested_local_artifacts(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "source"
            destination = Path(temporary) / "destination"
            (source / "fixtures").mkdir(parents=True)
            (source / "nested").mkdir()
            (source / ".terraform").mkdir()
            (source / ".terraform.lock.hcl").write_text("lock")
            (source / "terraform.tfvars").write_text("local")
            (source / "fixtures" / "offline-baseline.tfvars").write_text("reviewed")
            (source / "nested" / "terraform.tfstate").write_text("state")
            (source / "nested" / "saved.tfplan").write_text("plan")
            with mock.patch(f"{__name__}.MODULE", source):
                shutil.copytree(source, destination, ignore=_ignore_local_terraform_artifacts)
            self.assertTrue((destination / ".terraform.lock.hcl").is_file())
            self.assertTrue((destination / "fixtures" / "offline-baseline.tfvars").is_file())
            self.assertFalse((destination / ".terraform").exists())
            self.assertFalse((destination / "terraform.tfvars").exists())
            self.assertFalse((destination / "nested" / "terraform.tfstate").exists())
            self.assertFalse((destination / "nested" / "saved.tfplan").exists())

    def test_container_mode_mounts_only_copied_workspace_with_synthetic_credentials(self):
        test = ValidatorMonitoringDashboardTerraformTest("test_source_keeps_body_optional_and_region_bound")
        workspace = Path("/tmp/validator-dashboard-contract/terraform-source")
        image = "example.invalid/terraform@sha256:" + "a" * 64
        with mock.patch.dict(os.environ, {
            TERRAFORM_MODE: "container",
            TERRAFORM_IMAGE: image,
            "AWS_PROFILE": "must-not-reach-container",
            "AWS_WEB_IDENTITY_TOKEN_FILE": "/tmp/must-not-reach-container",
        }, clear=False), mock.patch("subprocess.run", return_value=subprocess.CompletedProcess([], 0, "", "")) as run:
            test._terraform_result(workspace, "validate")

        command = run.call_args.args[0]
        self.assertEqual(command[:3], ["docker", "run", "--rm"])
        self.assertEqual(command[command.index("--network") + 1], "none")
        self.assertEqual(command[command.index("--pull") + 1], "never")
        self.assertEqual(command[command.index("--cap-drop") + 1], "ALL")
        self.assertEqual(command[command.index("--security-opt") + 1], "no-new-privileges")
        self.assertIn(f"{workspace.resolve()}:/workspace:rw", command)
        self.assertNotIn(str(ROOT), " ".join(command))
        self.assertNotIn("--privileged", command)
        self.assertNotIn("AWS_PROFILE=must-not-reach-container", command)
        self.assertNotIn("AWS_WEB_IDENTITY_TOKEN_FILE=/tmp/must-not-reach-container", command)
        self.assertIn("AWS_ACCESS_KEY_ID=offline", command)
        self.assertIn("AWS_SECRET_ACCESS_KEY=offline", command)
        self.assertIn("AWS_EC2_METADATA_DISABLED=true", command)
        self.assertIn("TF_DATA_DIR=/workspace/.terraform-data", command)
        self.assertEqual(command[-4:], [image, "terraform", "-chdir=/workspace", "validate"])


if __name__ == "__main__":
    unittest.main()
