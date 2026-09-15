# Check objective: Exercise bounded private ops verification without cloud or SSM execution.
from __future__ import annotations

import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import call, patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/release"))
import installer_ops_verify as verify

DISCOVERY = {"aws_account_id": "123456789012", "aws_region": "ap-northeast-1", "deployment_name": "test-node", "principal_arn": "arn:aws:iam::123456789012:role/Operator"}


class Process:
    pid = 4321
    returncode = 0
    def __init__(self, output='{"kind":"Namespace","metadata":{"name":"kube-system"}}'): self.output = output
    def communicate(self, timeout=None): return self.output, ""


class VerifyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.base = Path(self.temp.name); os.chmod(self.base, 0o700)
        self.state = self.base / "state"; self.state.mkdir(mode=0o700)
        self.bundle = self.base / "bundle"; (self.bundle / "source/release").mkdir(parents=True); (self.bundle / "source/scripts/ops").mkdir(parents=True)
        self.write(self.bundle / "source/release/hoodi-release-contract.json", {"bootstrap": {"interactive_ops_verify_schema": 1}})
        self.write_text(self.bundle / "source/scripts/ops/with-private-eks.sh", "#!/usr/bin/env bash\n", 0o755)
        self.write(self.state / "private-eks-session.json", {"schema_version": 1, "aws_region": "ap-northeast-1", "cluster_name": "test-node", "ssm_ops_instance_id": "i-0123456789abcdef0"})
        self.write(self.state / "terraform-work/ops-access-handoff.json", {"schema_version": "v1", "aws_account_id": "123456789012", "aws_region": "ap-northeast-1", "cluster_name": "test-node", "vpc_id": "vpc-abc", "subnet_id": "subnet-abc"})
        os.chmod(self.state / "terraform-work", 0o700)
        self.calls = []

    def tearDown(self): self.temp.cleanup()
    @staticmethod
    def write_text(path, text, mode=0o600): path.parent.mkdir(parents=True, exist_ok=True); path.write_text(text); os.chmod(path, mode)
    def write(self, path, value): self.write_text(path, json.dumps(value))
    def aws(self, profile, region, args):
        self.calls.append(args)
        if args[0] == "sts": return {"Account": DISCOVERY["aws_account_id"], "Arn": DISCOVERY["principal_arn"]}
        if args[0] == "ssm": return {"InstanceInformationList": [{"InstanceId": "i-0123456789abcdef0", "PingStatus": "Online", "PlatformType": "Linux", "ResourceType": "EC2Instance"}]}
        if args[0] == "ec2": return {"Reservations": [{"Instances": [{"InstanceId": "i-0123456789abcdef0", "State": {"Name": "running"}, "VpcId": "vpc-abc", "SubnetId": "subnet-abc"}]}]}
        return {"cluster": {"name": "test-node", "arn": "arn:aws:eks:ap-northeast-1:123456789012:cluster/test-node", "resourcesVpcConfig": {"vpcId": "vpc-abc", "endpointPublicAccess": False, "endpointPrivateAccess": True}}}

    def test_valid_bounded_verification_and_clean_environment(self):
        process = Process()
        with patch.object(verify, "aws_read", self.aws), patch.object(verify, "_identity", lambda *_: None), patch.object(verify.subprocess, "Popen", return_value=process) as popen, patch.dict(os.environ, {"PRIVATE_EKS_SESSION": "bad", "KUBECONFIG": "bad", "AWS_ACCESS_KEY_ID": "bad", "GITHUB_TOKEN": "keep"}, clear=False):
            verify.verify_ops_access(self.bundle, self.state, DISCOVERY, "operator")
        args, kwargs = popen.call_args
        self.assertIn("--request-timeout=20s", args[0]); self.assertTrue(kwargs["start_new_session"])
        env = kwargs["env"]; self.assertEqual(env["AWS_PROFILE"], "operator"); self.assertEqual(env["EKS_CLUSTER_NAME"], "test-node")
        self.assertNotIn("PRIVATE_EKS_SESSION", env); self.assertNotIn("KUBECONFIG", env); self.assertNotIn("AWS_ACCESS_KEY_ID", env); self.assertEqual(env["GITHUB_TOKEN"], "keep")

    def test_offline_or_public_instance_never_starts_wrapper(self):
        def offline(*args): return {"InstanceInformationList": [{"InstanceId": "i-0123456789abcdef0", "PingStatus": "Offline", "PlatformType": "Linux", "ResourceType": "EC2Instance"}]} if args[2][0] == "ssm" else self.aws(*args)
        with patch.object(verify, "aws_read", offline), patch.object(verify, "_identity", lambda *_: None), patch.object(verify.subprocess, "Popen") as popen:
            with self.assertRaises(verify.OpsVerifyError): verify.verify_ops_access(self.bundle, self.state, DISCOVERY, "operator")
        popen.assert_not_called()

    def test_public_or_wrong_network_and_public_eks_never_start_wrapper(self):
        def altered(profile, region, args):
            value = self.aws(profile, region, args)
            if args[0] == "ec2":
                value["Reservations"][0]["Instances"][0]["PublicIpAddress"] = "198.51.100.1"
            return value
        with patch.object(verify, "aws_read", altered), patch.object(verify, "_identity", lambda *_: None), patch.object(verify.subprocess, "Popen") as popen:
            with self.assertRaises(verify.OpsVerifyError): verify.verify_ops_access(self.bundle, self.state, DISCOVERY, "operator")
        popen.assert_not_called()
        def public_eks(profile, region, args):
            value = self.aws(profile, region, args)
            if args[0] == "eks": value["cluster"]["resourcesVpcConfig"]["endpointPublicAccess"] = True
            return value
        with patch.object(verify, "aws_read", public_eks), patch.object(verify, "_identity", lambda *_: None), patch.object(verify.subprocess, "Popen") as popen:
            with self.assertRaises(verify.OpsVerifyError): verify.verify_ops_access(self.bundle, self.state, DISCOVERY, "operator")
        popen.assert_not_called()

    def test_bad_handoff_and_bad_namespace_are_rejected(self):
        self.write(self.state / "private-eks-session.json", {"schema_version": True, "aws_region": "ap-northeast-1", "cluster_name": "test-node", "ssm_ops_instance_id": "i-0123456789abcdef0"})
        with patch.object(verify, "aws_read", self.aws), patch.object(verify, "_identity", lambda *_: None), patch.object(verify.subprocess, "Popen") as popen:
            with self.assertRaises(verify.OpsVerifyError): verify.verify_ops_access(self.bundle, self.state, DISCOVERY, "operator")
        popen.assert_not_called()
        self.write(self.state / "private-eks-session.json", {"schema_version": 1, "aws_region": "ap-northeast-1", "cluster_name": "test-node", "ssm_ops_instance_id": "i-0123456789abcdef0"})
        with patch.object(verify, "aws_read", self.aws), patch.object(verify, "_identity", lambda *_: None), patch.object(verify.subprocess, "Popen", return_value=Process("{}")):
            with self.assertRaises(verify.OpsVerifyError): verify.verify_ops_access(self.bundle, self.state, DISCOVERY, "operator")

    def test_timeout_terminates_process_group(self):
        class Timed(Process):
            def __init__(self): self.calls = 0
            def communicate(self, timeout=None):
                self.calls += 1
                if self.calls == 1: raise verify.subprocess.TimeoutExpired("x", timeout)
                return "", ""
        process = Timed()
        with patch.object(verify, "aws_read", self.aws), patch.object(verify, "_identity", lambda *_: None), patch.object(verify.subprocess, "Popen", return_value=process), patch.object(verify.os, "killpg") as kill:
            with self.assertRaises(verify.OpsVerifyError): verify.verify_ops_access(self.bundle, self.state, DISCOVERY, "operator")
        kill.assert_called_once_with(4321, verify.signal.SIGTERM)

    def test_repeated_timeout_kills_group_and_keyboard_interrupt_cleans_up(self):
        class Stuck(Process):
            def communicate(self, timeout=None): raise verify.subprocess.TimeoutExpired("x", timeout)
        with patch.object(verify, "aws_read", self.aws), patch.object(verify, "_identity", lambda *_: None), patch.object(verify.subprocess, "Popen", return_value=Stuck()), patch.object(verify.os, "killpg") as kill:
            with self.assertRaises(verify.OpsVerifyError): verify.verify_ops_access(self.bundle, self.state, DISCOVERY, "operator")
        self.assertEqual(kill.call_args_list, [call(4321, verify.signal.SIGTERM), call(4321, verify.signal.SIGKILL)])
        class Interrupted(Process):
            def __init__(self): self.calls = 0
            def communicate(self, timeout=None):
                self.calls += 1
                if self.calls == 1: raise KeyboardInterrupt
                return "", ""
        with patch.object(verify, "aws_read", self.aws), patch.object(verify, "_identity", lambda *_: None), patch.object(verify.subprocess, "Popen", return_value=Interrupted()), patch.object(verify.os, "killpg") as kill:
            with self.assertRaises(KeyboardInterrupt): verify.verify_ops_access(self.bundle, self.state, DISCOVERY, "operator")
        kill.assert_called_once_with(4321, verify.signal.SIGTERM)

    def test_nonzero_cleanup_failure_and_malformed_metadata_never_pass(self):
        failed = Process(); failed.returncode = 1
        with patch.object(verify, "aws_read", self.aws), patch.object(verify, "_identity", lambda *_: None), patch.object(verify.subprocess, "Popen", return_value=failed):
            with self.assertRaises(verify.OpsVerifyError): verify.verify_ops_access(self.bundle, self.state, DISCOVERY, "operator")
        with patch.object(verify, "aws_read", self.aws), patch.object(verify, "_identity", lambda *_: None), patch.object(verify.subprocess, "Popen", return_value=Process('{"kind":"Namespace","metadata":[] }')):
            with self.assertRaises(verify.OpsVerifyError): verify.verify_ops_access(self.bundle, self.state, DISCOVERY, "operator")


if __name__ == "__main__": unittest.main()
