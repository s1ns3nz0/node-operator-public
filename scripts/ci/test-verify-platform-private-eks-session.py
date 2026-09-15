#!/usr/bin/env python3
# Check objective: Validate private EKS session verification without AWS access.
"""Exercise the public-layout private EKS verifier without AWS access."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/release"))
SPEC = importlib.util.spec_from_file_location("platform_session", ROOT / "scripts/release/verify-platform-private-eks-session.py")
assert SPEC and SPEC.loader
helper = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(helper)


class PlatformSessionTest(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(tempfile.mkdtemp()).resolve()
        self.addCleanup(shutil.rmtree, self.root, True)
        self.work = self.root / "deployment-work"
        self.work.mkdir(mode=0o700)
        self.baseline = self.root / "baseline.tfvars.json"
        self.session = self.root / "private-eks-session.json"
        self.handoff = self.work / "ops-access-handoff.json"
        self.baseline.write_text(json.dumps({"name": "node-op-001", "aws_account_id": "123456789012", "aws_region": "ap-northeast-2"}))
        self.session.write_text(json.dumps({"schema_version": 1, "aws_region": "ap-northeast-2", "cluster_name": "node-op-001", "ssm_ops_instance_id": "i-0123456789abcdef0"}))
        self.handoff.write_text(json.dumps({"schema_version": "v1", "aws_account_id": "123456789012", "aws_region": "ap-northeast-2", "cluster_name": "node-op-001", "vpc_id": "vpc-0123456789abcdef0", "subnet_id": "subnet-0123456789abcdef0"}))
        for path in (self.baseline, self.session, self.handoff):
            path.chmod(0o600)

    def verify(self) -> None:
        helper.verify(self.work, self.baseline, self.session, "123456789012", "ap-northeast-2", "chosen")

    def test_live_checks_follow_exact_public_layout(self) -> None:
        calls: list[object] = []
        def read(profile, region, args):
            calls.append((profile, region, args))
            return {"Account": "123456789012"}
        def live(discovery, profile, session, handoff):
            calls.append((discovery, profile, session, handoff))
        with patch.object(helper, "aws_read", read), patch.object(helper, "_live", live):
            self.verify()
        self.assertEqual(calls[0], ("chosen", "ap-northeast-2", ["sts", "get-caller-identity"]))
        self.assertEqual(calls[1][0], {"aws_account_id": "123456789012", "aws_region": "ap-northeast-2", "deployment_name": "node-op-001"})

    def test_bad_session_or_wrong_location_stops_before_aws(self) -> None:
        self.session.write_text(json.dumps({"schema_version": 1, "aws_region": "ap-northeast-2", "cluster_name": "other-node", "ssm_ops_instance_id": "i-0123456789abcdef0"}))
        with patch.object(helper, "aws_read") as read, patch.object(helper, "_live") as live:
            with self.assertRaises(helper.PlatformSessionError):
                self.verify()
        read.assert_not_called(); live.assert_not_called()
        self.session.write_text(json.dumps({"schema_version": 1, "aws_region": "ap-northeast-2", "cluster_name": "node-op-001", "ssm_ops_instance_id": "i-0123456789abcdef0"}))
        other = self.root / "other.json"; other.write_bytes(self.session.read_bytes())
        with patch.object(helper, "aws_read") as read:
            with self.assertRaises(helper.PlatformSessionError):
                helper.verify(self.work, self.baseline, other, "123456789012", "ap-northeast-2", "chosen")
        read.assert_not_called()

    def test_bad_ops_binding_and_sts_account_stop_before_live(self) -> None:
        self.handoff.write_text(json.dumps({"schema_version": "v1", "aws_account_id": "999999999999", "aws_region": "ap-northeast-2", "cluster_name": "node-op-001", "vpc_id": "vpc-0123456789abcdef0", "subnet_id": "subnet-0123456789abcdef0"}))
        with patch.object(helper, "aws_read") as read, patch.object(helper, "_live") as live:
            with self.assertRaises(helper.PlatformSessionError): self.verify()
        read.assert_not_called(); live.assert_not_called()
        self.handoff.write_text(json.dumps({"schema_version": "v1", "aws_account_id": "123456789012", "aws_region": "ap-northeast-2", "cluster_name": "node-op-001", "vpc_id": "vpc-0123456789abcdef0", "subnet_id": "subnet-0123456789abcdef0"}))
        with patch.object(helper, "aws_read", return_value={"Account": "999999999999"}), patch.object(helper, "_live") as live:
            with self.assertRaises(helper.PlatformSessionError): self.verify()
        live.assert_not_called()


if __name__ == "__main__":
    unittest.main()
