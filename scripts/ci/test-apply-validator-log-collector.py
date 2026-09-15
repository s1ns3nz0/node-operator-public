#!/usr/bin/env python3
# Check objective: Verify Fluent Bit installation gate ordering with mocks.
"""Mock-only gate ordering tests for interactive Fluent Bit installation."""
from __future__ import annotations
import importlib.util
import json
import hashlib
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/release"))
spec = importlib.util.spec_from_file_location("apply_collector", ROOT / "scripts/release/apply-validator-log-collector.py")
installer = importlib.util.module_from_spec(spec); assert spec.loader; spec.loader.exec_module(installer)
renderer_spec = importlib.util.spec_from_file_location("renderer", ROOT / "scripts/release/validator_log_collector.py")
renderer = importlib.util.module_from_spec(renderer_spec); assert renderer_spec.loader; renderer_spec.loader.exec_module(renderer)

ACCOUNT, REGION, DEPLOYMENT = "123456789012", "ap-northeast-2", "node-op-001"
DIGEST = "sha256:" + "a" * 64
IMAGE = f"{ACCOUNT}.dkr.ecr.{REGION}.amazonaws.com/node-op-001-baseline-validator-fluent-bit@{DIGEST}"


class ApplyCollector(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp()).resolve(); self.addCleanup(shutil.rmtree, self.root, True)
        self.bundle = self.root / "bundle"; self.source = self.bundle / "source"; self.state = self.root / "state"; self.work = self.state / "deployment-work"; self.inputs = self.state / "inputs"
        for path in (self.source / "scripts/ops", self.source / "scripts/release", self.source / "deploy/observability", self.state, self.work, self.inputs): path.mkdir(parents=True, exist_ok=True)
        self.state.chmod(0o700); self.work.chmod(0o700)
        shutil.copy2(ROOT / "deploy/observability/fluent-bit-config.yaml", self.source / "deploy/observability/fluent-bit-config.yaml")
        (self.source / "deploy/kyverno/policies").mkdir(parents=True)
        (self.source / "deploy/kyverno/policies/node-operator-project-workload-baseline.yaml").write_text("apiVersion: kyverno.io/v1\nkind: ClusterPolicy\n")
        (self.source / "scripts/ops/with-private-eks.sh").write_text("#!/usr/bin/env bash\n")
        for name in ("verify-platform-private-eks-session.py", "validator_log_collector.py", "validator_log_collector_policy.py"):
            shutil.copy2(ROOT / "scripts/release" / name, self.source / "scripts/release" / name)
        required = [
            "source/scripts/release/verify-platform-private-eks-session.py", "source/scripts/release/validator_log_collector.py", "source/scripts/release/validator_log_collector_policy.py",
            "source/deploy/observability/fluent-bit-config.yaml", "source/deploy/kyverno/policies/node-operator-project-workload-baseline.yaml", "source/scripts/ops/with-private-eks.sh",
        ]
        self.bundle.joinpath("bundle-manifest.json").write_text(json.dumps({"source_revision": "a" * 40, "entries": [{"path": name, "sha256": hashlib.sha256((self.bundle / name).read_bytes()).hexdigest()} for name in required]}))
        (self.work / "ops-access-handoff.json").write_text(json.dumps({"vpc_id": "vpc-0123456789abcdef0"}))
        self.calls = []; self.apply_payloads = []; self.session_data = {"ssm_ops_instance_id": "i-0123456789abcdef0", "cluster_name": DEPLOYMENT, "aws_region": REGION}; self.session_failure = None; self.policy_value = {"spec": {"validationFailureAction": "Enforce"}, "status": {"conditions": [{"type": "Ready", "status": "True"}]}}; self.fail = None; self.mutate = None

    def runner(self, command, **kwargs):
        self.calls.append(command)
        if self.fail and self.fail(command): return subprocess.CompletedProcess(command, 1, "", "denied")
        output = ""
        if command[:3] == ["aws", "ec2", "describe-vpc-endpoints"]:
            output = json.dumps({"VpcEndpoints": [{"VpcId": "vpc-0123456789abcdef0", "OwnerId": ACCOUNT, "ServiceName": f"com.amazonaws.{REGION}.logs", "VpcEndpointType": "Interface", "State": "available", "PrivateDnsEnabled": True, "SubnetIds": ["subnet-1"], "NetworkInterfaceIds": ["eni-1"]}]})
        elif command[:3] == ["aws", "ec2", "describe-network-interfaces"]:
            output = json.dumps({"NetworkInterfaces": [{"NetworkInterfaceId": "eni-1", "VpcId": "vpc-0123456789abcdef0", "OwnerId": ACCOUNT, "SubnetId": "subnet-1", "RequesterManaged": True, "InterfaceType": "vpc_endpoint", "PrivateIpAddress": "10.0.1.5"}]})
        elif "get" in command and "service" in command:
            output = json.dumps({"spec": {"clusterIP": "172.20.0.1"}})
        elif "create" in command and "--dry-run=client" in command:
            output = json.dumps({"apiVersion": "kyverno.io/v1", "kind": "ClusterPolicy", "metadata": {"name": "node-operator-project-workload-baseline"}, "spec": {"validationFailureAction": "Enforce"}})
        elif "get" in command and "clusterpolicy" in command: output = json.dumps(self.policy_value)
        result = subprocess.CompletedProcess(command, 0, output, "")
        if self.mutate: result = self.mutate(command, result)
        if "apply" in command and "-f" in command:
            self.apply_payloads.append((command, json.loads(Path(command[command.index("-f") + 1]).read_text())))
        return result

    def session(self):
        def verify(*args):
            if self.session_failure: raise self.session_failure
            return self.session_data
        return type("Session", (), {"verify": staticmethod(verify)})

    def receipt(self, image=IMAGE):
        return {"artifacts": [{"component": "validator-log-collector", "image_ref": image, "tag": "a" * 64, "manifest_digest": DIGEST}]}

    def invoke(self, receipt=None):
        receipt = self.receipt() if receipt is None else receipt
        policy = type("Policy", (), {"render": staticmethod(lambda value, image: value)})
        def load(_, path): return self.session() if path.name.startswith("verify-platform") else policy if path.name.startswith("validator_log_collector_policy") else renderer
        with patch.object(installer, "_module", load), patch.object(installer, "verify_full_mirror", return_value=receipt):
            installer.install(bundle_root=self.bundle, state_dir=self.state, work_dir=self.work, inputs_dir=self.inputs, session=self.state / "private-eks-session.json", baseline_config=self.inputs / "baseline.tfvars.json", account=ACCOUNT, region=REGION, deployment=DEPLOYMENT, validator_set="hoodi-example", profile="chosen", release_sha="a" * 40, runner=self.runner)

    def test_all_gates_precede_exact_apply_and_rollout(self):
        self.invoke()
        apply = next(i for i, call in enumerate(self.calls) if "apply" in call)
        rollout = next(i for i, call in enumerate(self.calls) if "rollout" in call)
        self.assertGreater(apply, 2); self.assertGreater(rollout, apply)
        self.assertIn("kubectl", self.calls[apply]); self.assertIn("-f", self.calls[apply])
        self.assertIn("daemonset/validator-log-collector", self.calls[rollout])
        self.assertEqual(self.apply_payloads[0][1]["kind"], "ClusterPolicy")
        self.assertIn("--dry-run=server", self.apply_payloads[0][0])
        self.assertEqual(self.apply_payloads[1][1]["kind"], "ClusterPolicy")
        self.assertEqual(self.apply_payloads[2][1]["kind"], "List")

    def test_foreign_endpoint_account_refuses_before_apply(self):
        original = self.runner
        def foreign(command, **kwargs):
            result = original(command, **kwargs)
            if command[:3] == ["aws", "ec2", "describe-vpc-endpoints"]:
                value = json.loads(result.stdout); value["VpcEndpoints"][0]["OwnerId"] = "999999999999"; return subprocess.CompletedProcess(command, 0, json.dumps(value), "")
            return result
        self.runner = foreign
        with self.assertRaises(installer.CollectorInstallError): self.invoke()
        self.assertFalse(any("apply" in call for call in self.calls))

    def test_foreign_image_refuses_before_live_queries_or_apply(self):
        with self.assertRaises(installer.CollectorInstallError): self.invoke(self.receipt("999999999999.dkr.ecr.ap-northeast-2.amazonaws.com/x@" + DIGEST))
        self.assertEqual(self.calls, [])

    def test_aws_endpoint_url_overrides_refuse_before_mirror_module_or_runner(self):
        cases = (
            ("AWS_ENDPOINT_URL", "http://override.invalid"),
            ("AWS_ENDPOINT_URL", ""),
            ("AWS_ENDPOINT_URL_S3", "http://override.invalid"),
            ("AWS_ENDPOINT_URL_S3", ""),
        )
        for name, value in cases:
            with self.subTest(name=name, value_is_empty=not value), self.assertRaises(installer.CollectorInstallError) as raised, patch.dict(installer.os.environ, {name: value}, clear=True), patch.object(installer, "verify_full_mirror") as mirror, patch.object(installer, "_module") as load:
                installer.install(bundle_root=self.bundle, state_dir=self.state, work_dir=self.work, inputs_dir=self.inputs, session=self.state / "private-eks-session.json", baseline_config=self.inputs / "baseline.tfvars.json", account=ACCOUNT, region=REGION, deployment=DEPLOYMENT, validator_set="hoodi-example", profile="chosen", release_sha="a" * 40, runner=self.runner)
            self.assertEqual(str(raised.exception), "AWS endpoint URL environment overrides are prohibited")
            mirror.assert_not_called()
            load.assert_not_called()
            self.assertEqual(self.calls, [])

    def test_tampered_or_symlinked_bundle_source_refuses_before_module_or_apply(self):
        target = self.source / "scripts/release/validator_log_collector.py"
        target.write_text("tampered")
        with patch.object(installer, "_module") as load:
            with self.assertRaises(installer.CollectorInstallError): self.invoke()
        load.assert_not_called(); self.assertEqual(self.calls, [])
        self.setUp(); target = self.source / "scripts/ops/with-private-eks.sh"; target.unlink(); target.symlink_to(self.root / "outside")
        with patch.object(installer, "_module") as load:
            with self.assertRaises(installer.CollectorInstallError): self.invoke()
        load.assert_not_called(); self.assertEqual(self.calls, [])

    def test_table_driven_live_gate_failures_never_real_apply(self):
        def endpoint(change):
            def alter(command, result):
                if command[:3] == ["aws", "ec2", "describe-vpc-endpoints"]:
                    value = json.loads(result.stdout); change(value["VpcEndpoints"][0]); return subprocess.CompletedProcess(command, 0, json.dumps(value), "")
                return result
            return alter
        def eni(change):
            def alter(command, result):
                if command[:3] == ["aws", "ec2", "describe-network-interfaces"]:
                    value = json.loads(result.stdout); change(value["NetworkInterfaces"][0]); return subprocess.CompletedProcess(command, 0, json.dumps(value), "")
                return result
            return alter
        cases = (
            ("wrong-vpc", lambda test: setattr(test, "mutate", endpoint(lambda row: row.update(VpcId="vpc-deadbeef")))),
            ("wrong-service", lambda test: setattr(test, "mutate", endpoint(lambda row: row.update(ServiceName="com.amazonaws.ap-northeast-2.s3")))),
            ("private-dns", lambda test: setattr(test, "mutate", endpoint(lambda row: row.update(PrivateDnsEnabled=False)))),
            ("duplicate-eni", lambda test: setattr(test, "mutate", endpoint(lambda row: row.update(NetworkInterfaceIds=["eni-1", "eni-1"])))),
            ("eni-type", lambda test: setattr(test, "mutate", eni(lambda row: row.update(InterfaceType="interface")))),
            ("eni-public", lambda test: setattr(test, "mutate", eni(lambda row: row.update(PrivateIpAddress="8.8.8.8")))),
            ("eni-subnet", lambda test: setattr(test, "mutate", eni(lambda row: row.update(SubnetId="subnet-foreign")))),
            ("foreign-session", lambda test: test.session_data.update(cluster_name="other-node")),
            ("divergent-policy", lambda test: test.policy_value.update(spec={"other": True})),
            ("not-ready-policy", lambda test: test.policy_value.update(status={"conditions": []})),
            ("session-exception", lambda test: setattr(test, "session_failure", RuntimeError("bad session"))),
        )
        for name, configure in cases:
            with self.subTest(name=name):
                self.setUp(); configure(self)
                with self.assertRaises(installer.CollectorInstallError): self.invoke()
                self.assertFalse(any("apply" in call and "--dry-run=server" not in call for call in self.calls))

    def test_server_dryrun_failure_prevents_real_apply_and_rollout_failure_propagates(self):
        self.fail = lambda command: "apply" in command and "--dry-run=server" in command
        with self.assertRaises(installer.CollectorInstallError): self.invoke()
        self.assertFalse(any("apply" in call and "--dry-run=server" not in call for call in self.calls))
        self.setUp(); self.fail = lambda command: "rollout" in command
        with self.assertRaises(installer.CollectorInstallError): self.invoke()
        self.assertTrue(any("rollout" in call for call in self.calls))

    def test_public_installer_places_collector_before_audit_custody_and_runtime_apply(self):
        source = (ROOT / "scripts/release/interactive-hoodi-release.sh").read_text()
        kyverno = source.index('Installing verified private Kyverno')
        collector = source.index('Applying verified validator log collector')
        audit = source.index('Configuring Vault audit devices before custody', collector)
        custody = source.index('if [ "$lifecycle_phase" = audit-complete ]; then', audit)
        runtime = source.index('Applying Vault-backed validator runtime', custody)
        self.assertLess(kyverno, collector)
        self.assertLess(collector, runtime)
        self.assertLess(collector, audit)
        self.assertLess(audit, custody)
        self.assertLess(custody, runtime)
        hook = source[collector:audit]
        self.assertIn('"$collector_apply"', hook)
        self.assertIn('--release-sha "$release_revision"', hook)
        self.assertIn('--work-dir "$output_dir/deployment-work"', hook)


if __name__ == "__main__": unittest.main()
