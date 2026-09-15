# Check objective: Exercise isolated installer ops-access plan/apply execution without cloud writes.
"""Mock the bounded execution adapter's immutable-bundle and state contracts."""
from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from contextlib import ExitStack
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/release"))
import installer_ops_execution as execution

DISCOVERY = {"aws_account_id": "123456789012", "aws_region": "ap-northeast-1", "deployment_name": "test-node", "principal_arn": "arn:aws:iam::123456789012:role/Operator"}


class OpsExecutionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name); os.chmod(self.base, 0o700)
        self.state = self.base / "state"; self.state.mkdir(mode=0o700)
        self.bundle = self.base / "bundle"
        (self.bundle / "source/infra/ops-access").mkdir(parents=True)
        (self.bundle / "source/scripts/ci").mkdir(parents=True)
        (self.bundle / "source/release").mkdir(parents=True)
        self.write(self.bundle / "source/infra/ops-access/main.tf", "resource {}\n", 0o644)
        self.write(self.bundle / "source/scripts/ci/check-ops-access-ssm-retention-plan.sh", "#!/usr/bin/env bash\nexit 0\n", 0o755)
        self.write(self.bundle / "source/scripts/release/node-operator-ops-access.sh", "#!/usr/bin/env bash\n", 0o755)
        self.write(self.bundle / "source/release/hoodi-release-contract.json", json.dumps({"bootstrap": {"interactive_ops_access_schema": 1}}), 0o600)
        self.inputs = self.state / "ops-access-inputs/ops-access-inputs.json"; self.inputs.parent.mkdir(mode=0o700)
        self.write(self.inputs, "{}", 0o600)
        self.backend = {"bucket": "test-node-tfstate-123456789012-apne1", "key": "node-operator/ops-access/terraform.tfstate", "region": "ap-northeast-1", "dynamodb_table": "test-node-terraform-lock", "kms_key_id": "arn:aws:kms:ap-northeast-1:123456789012:key/abcd"}
        self.handoff = self.state / "terraform-work/ops-access-handoff.json"
        self.write(self.handoff, json.dumps({"backend": self.backend}), 0o600)
        self.output = {"schema_version": 1, "aws_region": "ap-northeast-1", "cluster_name": "test-node", "ssm_ops_instance_id": "i-0123456789abcdef0"}
        self.calls = []

    def tearDown(self): self.temp.cleanup()

    @staticmethod
    def write(path: Path, text: str, mode: int):
        path.parent.mkdir(parents=True, exist_ok=True); path.write_text(text); os.chmod(path, mode)

    def fake_run(self, args, **kwargs):
        self.calls.append((args, kwargs))
        plan = Path(args[args.index("--plan-file") + 1])
        if args[2] == "plan":
            self.write(plan, "reviewed", 0o600)
            cache = Path(args[args.index("--root") + 1]) / "infra/ops-access/.terraform"; cache.mkdir()
            self.write(cache / "terraform.tfstate", json.dumps({"backend": {"type": "s3", "config": {**self.backend, "encrypt": True}}}), 0o600)
        else:
            session = Path(args[args.index("--session-handoff") + 1])
            self.write(session, json.dumps(self.output), 0o600)
        return SimpleNamespace(returncode=0)

    def patches(self):
        stack = ExitStack()
        stack.enter_context(patch.object(execution, "prepare_ops_access", lambda *_: self.inputs))
        stack.enter_context(patch.object(execution, "aws_read", lambda *_: {"Account": DISCOVERY["aws_account_id"], "Arn": DISCOVERY["principal_arn"]}))
        stack.enter_context(patch.object(execution.subprocess, "run", self.fake_run))
        return stack

    def test_plan_copies_only_private_work_and_strips_environment(self):
        with self.patches(), patch.dict(os.environ, {"TF_CLI_CONFIG_FILE": "/bad", "TF_VAR_x": "bad", "AWS_ACCESS_KEY_ID": "bad", "BASH_ENV": "/bad", "GITHUB_TOKEN": "keep"}, clear=False):
            digest = execution.plan_ops_access(self.bundle, self.state, DISCOVERY, "operator")
        self.assertRegex(digest, r"^[0-9a-f]{64}$")
        self.assertEqual((self.bundle / "source/infra/ops-access/main.tf").read_text(), "resource {}\n")
        self.assertEqual((self.state / "ops-access-work/infra/ops-access/main.tf").read_text(), "resource {}\n")
        self.assertFalse((self.bundle / "source/infra/ops-access/.terraform").exists())
        self.assertEqual(self.calls[0][0][self.calls[0][0].index("--root") + 1], str(self.state / "ops-access-work"))
        env = self.calls[0][1]["env"]
        for key in ("TF_CLI_CONFIG_FILE", "TF_VAR_x", "AWS_ACCESS_KEY_ID", "BASH_ENV"): self.assertNotIn(key, env)
        self.assertEqual(env["GITHUB_TOKEN"], "keep"); self.assertEqual(env["AWS_PROFILE"], "operator")

    def test_existing_plan_is_never_overwritten_and_bad_hash_never_runs(self):
        with self.patches(): digest = execution.plan_ops_access(self.bundle, self.state, DISCOVERY, "operator")
        with self.patches():
            with self.assertRaises(execution.OpsExecutionError): execution.plan_ops_access(self.bundle, self.state, DISCOVERY, "operator")
        count = len(self.calls)
        with self.patches():
            with self.assertRaises(execution.OpsExecutionError): execution.apply_ops_access(self.bundle, self.state, DISCOVERY, "operator", "0" * 64)
        self.assertEqual(len(self.calls), count)
        self.assertRegex(digest, r"^[0-9a-f]{64}$")

    def test_apply_returns_only_exact_private_handoff(self):
        with self.patches(): digest = execution.plan_ops_access(self.bundle, self.state, DISCOVERY, "operator")
        with self.patches(): result = execution.apply_ops_access(self.bundle, self.state, DISCOVERY, "operator", digest)
        self.assertEqual(result["ssm_ops_instance_id"], "i-0123456789abcdef0")
        self.assertEqual((self.state / "private-eks-session.json").stat().st_mode & 0o777, 0o600)

    def test_initialized_cache_requires_the_handoff_backend_before_subprocess(self):
        with self.patches(): digest = execution.plan_ops_access(self.bundle, self.state, DISCOVERY, "operator")
        metadata = self.state / "ops-access-work/infra/ops-access/.terraform/terraform.tfstate"
        correct = {"backend": {"type": "s3", "config": {**self.backend, "encrypt": True}}}
        count = len(self.calls)
        for changed in ({"key": "wrong"}, {"dynamodb_table": "wrong"}, {"kms_key_id": "wrong"}, {"encrypt": False}, {"endpoint": "https://wrong"}, {"workspace_key_prefix": "custom"}):
            self.write(metadata, json.dumps({"backend": {"type": "s3", "config": {**self.backend, "encrypt": True, **changed}}}), 0o600)
            with self.patches():
                with self.assertRaises(execution.OpsExecutionError): execution.apply_ops_access(self.bundle, self.state, DISCOVERY, "operator", digest)
        self.write(metadata, json.dumps({"backend": {"type": "other", "config": {**self.backend, "encrypt": True}}}), 0o600)
        with self.patches():
            with self.assertRaises(execution.OpsExecutionError): execution.apply_ops_access(self.bundle, self.state, DISCOVERY, "operator", digest)
        self.assertEqual(len(self.calls), count)
        self.write(metadata, json.dumps(correct), 0o600)
        with self.patches(): execution.apply_ops_access(self.bundle, self.state, DISCOVERY, "operator", digest)

    def test_initialized_cache_missing_metadata_and_existing_handoff_block_apply(self):
        with self.patches(): digest = execution.plan_ops_access(self.bundle, self.state, DISCOVERY, "operator")
        metadata = self.state / "ops-access-work/infra/ops-access/.terraform/terraform.tfstate"; metadata.unlink()
        count = len(self.calls)
        with self.patches():
            with self.assertRaises(execution.OpsExecutionError): execution.apply_ops_access(self.bundle, self.state, DISCOVERY, "operator", digest)
        self.assertEqual(len(self.calls), count)
        self.write(metadata, json.dumps({"backend": {"type": "s3", "config": {**self.backend, "encrypt": True}}}), 0o600)
        self.write(self.state / "private-eks-session.json", json.dumps(self.output), 0o600)
        with self.patches():
            with self.assertRaises(execution.OpsExecutionError): execution.apply_ops_access(self.bundle, self.state, DISCOVERY, "operator", digest)
        self.assertEqual(len(self.calls), count)

    def test_wrong_sts_and_boolean_capability_block_wrapper(self):
        with self.patches(), patch.object(execution, "aws_read", lambda *_: {"Account": DISCOVERY["aws_account_id"], "Arn": "arn:aws:iam::123456789012:role/Other"}):
            with self.assertRaises(execution.OpsExecutionError): execution.plan_ops_access(self.bundle, self.state, DISCOVERY, "operator")
        self.write(self.bundle / "source/release/hoodi-release-contract.json", json.dumps({"bootstrap": {"interactive_ops_access_schema": True}}), 0o600)
        with self.patches():
            with self.assertRaises(execution.OpsExecutionError): execution.plan_ops_access(self.bundle, self.state, DISCOVERY, "operator")

    def test_unexpected_or_typed_bad_handoff_is_rejected(self):
        with self.patches(): digest = execution.plan_ops_access(self.bundle, self.state, DISCOVERY, "operator")
        self.output = {**self.output, "unexpected": True}
        with self.patches():
            with self.assertRaises(execution.OpsExecutionError): execution.apply_ops_access(self.bundle, self.state, DISCOVERY, "operator", digest)
        (self.state / "private-eks-session.json").unlink()
        self.output = {"schema_version": True, "aws_region": "ap-northeast-1", "cluster_name": "test-node", "ssm_ops_instance_id": "i-0123456789abcdef0"}
        with self.patches():
            with self.assertRaises(execution.OpsExecutionError): execution.apply_ops_access(self.bundle, self.state, DISCOVERY, "operator", digest)

    def test_work_mutation_or_identity_mismatch_fails_before_wrapper(self):
        with self.patches(): execution.plan_ops_access(self.bundle, self.state, DISCOVERY, "operator")
        self.write(self.state / "ops-access-work/infra/ops-access/main.tf", "changed\n", 0o644)
        count = len(self.calls)
        with self.patches():
            with self.assertRaises(execution.OpsExecutionError): execution.apply_ops_access(self.bundle, self.state, DISCOVERY, "operator", "0" * 64)
        self.assertEqual(len(self.calls), count)


if __name__ == "__main__": unittest.main()
