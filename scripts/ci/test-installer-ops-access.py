# Check objective: Exercise bounded installer ops-access preparation without Terraform or cloud writes.
"""Exercise isolated installer ops-access preparation without Terraform or cloud writes."""
import importlib
import json
import os
from pathlib import Path
import shutil
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/release"))
ops = importlib.import_module("installer_ops_access")

DISCOVERY = {"aws_account_id": "123456789012", "aws_region": "ap-northeast-1", "deployment_name": "test-node"}


@unittest.skipUnless(shutil.which("jq"), "release preparation requires jq")
class OpsAccessPreparationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        self.state = self.root / "state"; self.state.mkdir(mode=0o700)
        self.work = self.state / "terraform-work"; self.work.mkdir(mode=0o700)
        self.bundle = self.root / "bundle"
        script_dir = self.bundle / "source/scripts/release"; script_dir.mkdir(parents=True)
        shutil.copyfile(ROOT / "scripts/release/prepare-ops-access-inputs.sh", script_dir / "prepare-ops-access-inputs.sh")
        self.handoff = self.work / "ops-access-handoff.json"
        self.write(self.handoff, {"schema_version": "v1", "aws_region": "ap-northeast-1", "aws_account_id": "123456789012", "cluster_name": "test-node", "vpc_id": "vpc-abc", "subnet_id": "subnet-abc", "backend": {"bucket": "test-node-tfstate-123456789012-apne1", "dynamodb_table": "test-node-terraform-lock", "kms_key_id": "arn:aws:kms:ap-northeast-1:123456789012:key/abcd", "region": "ap-northeast-1", "key": "node-operator/ops-access/terraform.tfstate"}})
        self.tools = self.root / "tools"; self.tools.mkdir()
        aws = self.tools / "aws"
        aws.write_text("#!/usr/bin/env bash\ncase \" $* \" in\n  *' sts get-caller-identity '*) printf '%s\\n' 123456789012 ;;\n  *' eks describe-cluster '*) printf '%s\\n' sg-abc ;;\n  *) exit 1 ;;\nesac\n")
        aws.chmod(0o700)

    def tearDown(self): self.temp.cleanup()

    def write(self, path, value):
        path.write_text(json.dumps(value)); path.chmod(0o600)

    def cluster(self, *, vpc="vpc-abc", subnets=None, account="123456789012"):
        return {"cluster": {"name": "test-node", "arn": f"arn:aws:eks:ap-northeast-1:{account}:cluster/test-node", "resourcesVpcConfig": {"vpcId": vpc, "subnetIds": subnets or ["subnet-abc"], "clusterSecurityGroupId": "sg-abc"}}}

    def prepare(self, cluster=None):
        env = {**dict.fromkeys(ops.AWS_CREDENTIAL_OVERRIDES, "unexpected"), "GITHUB_TOKEN": "sentinel"}
        with patch.dict(os.environ, env), patch.object(ops, "aws_read", return_value=cluster or self.cluster()) as read:
            return ops.prepare_ops_access(self.bundle, self.state, DISCOVERY, "operator"), read

    def test_real_script_prepares_private_bound_inputs_and_reuses(self):
        with patch.dict(os.environ, {"PATH": str(self.tools) + os.pathsep + os.environ["PATH"]}):
            result, read = self.prepare()
        self.assertEqual(read.call_args.args, ("operator", "ap-northeast-1", ["eks", "describe-cluster", "--name", "test-node"]))
        self.assertEqual(result, self.state / "ops-access-inputs/ops-access-inputs.json")
        self.assertEqual(result.stat().st_mode & 0o777, 0o600)
        self.assertEqual((result.parent / "ops-access.backend.hcl").stat().st_mode & 0o777, 0o600)
        with patch.object(ops.subprocess, "run") as run:
            self.prepare()
        run.assert_not_called()

    def test_cluster_mismatch_or_unsafe_handoff_never_runs_script(self):
        for value in (self.cluster(vpc="vpc-other"), self.cluster(subnets=["subnet-other"])):
            with patch.object(ops, "aws_read", return_value=value), patch.object(ops.subprocess, "run") as run, self.assertRaises(ops.OpsAccessError):
                ops.prepare_ops_access(self.bundle, self.state, DISCOVERY, "operator")
            run.assert_not_called()
        self.handoff.unlink(); self.handoff.symlink_to("/tmp/elsewhere")
        with patch.object(ops, "aws_read") as read, self.assertRaises(ops.OpsAccessError):
            ops.prepare_ops_access(self.bundle, self.state, DISCOVERY, "operator")
        read.assert_not_called()

    def test_child_environment_is_cleaned_without_touching_github_token(self):
        with patch.object(ops, "aws_read", return_value=self.cluster()), patch.object(ops.subprocess, "run", return_value=type("R", (), {"returncode": 1})()) as run:
            with patch.dict(os.environ, {**dict.fromkeys(ops.AWS_CREDENTIAL_OVERRIDES, "unsafe"), "GITHUB_TOKEN": "sentinel"}):
                with self.assertRaises(ops.OpsAccessError): ops.prepare_ops_access(self.bundle, self.state, DISCOVERY, "operator")
        environment = run.call_args.kwargs["env"]
        self.assertEqual(environment["GITHUB_TOKEN"], "sentinel")
        self.assertEqual(environment["AWS_PROFILE"], "operator")
        self.assertEqual(environment["AWS_EC2_METADATA_DISABLED"], "true")
        self.assertTrue(all(key not in environment for key in ops.AWS_CREDENTIAL_OVERRIDES))

    def test_malicious_table_hcl_symlink_and_oversize_are_rejected(self):
        handoff = json.loads(self.handoff.read_text())
        handoff["backend"]["dynamodb_table"] = 'valid"\nmalicious = true'
        self.write(self.handoff, handoff)
        with patch.object(ops, "aws_read") as read, self.assertRaises(ops.OpsAccessError):
            ops.prepare_ops_access(self.bundle, self.state, DISCOVERY, "operator")
        read.assert_not_called()

        self.write(self.handoff, {**handoff, "backend": {**handoff["backend"], "dynamodb_table": "test-node-terraform-lock"}})
        with patch.dict(os.environ, {"PATH": str(self.tools) + os.pathsep + os.environ["PATH"]}):
            self.prepare()
        hcl = self.state / "ops-access-inputs/ops-access.backend.hcl"
        hcl.unlink(); hcl.symlink_to("/tmp/elsewhere")
        with patch.object(ops, "aws_read", return_value=self.cluster()), patch.object(ops.subprocess, "run") as run, self.assertRaises(ops.OpsAccessError):
            ops.prepare_ops_access(self.bundle, self.state, DISCOVERY, "operator")
        run.assert_not_called()

        hcl.unlink(); hcl.write_text("x" * 65537); hcl.chmod(0o600)
        with patch.object(ops, "aws_read", return_value=self.cluster()), patch.object(ops.subprocess, "run") as run, self.assertRaises(ops.OpsAccessError):
            ops.prepare_ops_access(self.bundle, self.state, DISCOVERY, "operator")
        run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
