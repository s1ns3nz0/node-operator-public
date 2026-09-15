#!/usr/bin/env python3
"""Mock-only checks for the release-bound private Kyverno bootstrap."""
import hashlib, importlib.util, json, shutil, subprocess, sys, tempfile, unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]; sys.path.insert(0, str(ROOT / "scripts/release"))
spec = importlib.util.spec_from_file_location("bootstrap", ROOT / "scripts/release/apply-kyverno-bootstrap.py")
bootstrap = importlib.util.module_from_spec(spec); assert spec.loader; spec.loader.exec_module(bootstrap)
A, R, N, D = "123456789012", "ap-northeast-2", "node-op-001", "sha256:" + "a" * 64

class Tests(unittest.TestCase):
 def setUp(self):
  self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup); root = Path(self.temp.name)
  self.bundle, self.state = root / "bundle", root / "state"; self.source, self.work, self.inputs = self.bundle / "source", self.state / "work", self.state / "inputs"
  for path in (self.source / "scripts/release", self.source / "scripts/ops", self.source / "deploy/kyverno/policies", self.work, self.inputs): path.mkdir(parents=True, exist_ok=True)
  self.state.chmod(0o700); self.work.chmod(0o700)
  for name in ("kyverno_bootstrap_inputs.py", "verify-platform-private-eks-session.py"): shutil.copy2(ROOT / "scripts/release" / name, self.source / "scripts/release" / name)
  (self.source / "scripts/ops/with-private-eks.sh").write_text("#!/usr/bin/env bash\n")
  (self.source / "deploy/kyverno/policies/node-operator-project-workload-baseline.yaml").write_text("apiVersion: kyverno.io/v1\nkind: ClusterPolicy\n")
  required = ("source/scripts/release/verify-platform-private-eks-session.py", "source/scripts/release/kyverno_bootstrap_inputs.py", "source/scripts/ops/with-private-eks.sh", "source/deploy/kyverno/policies/node-operator-project-workload-baseline.yaml")
  (self.bundle / "bundle-manifest.json").write_text(json.dumps({"source_revision":"a" * 40, "entries":[{"path":p,"sha256":hashlib.sha256((self.bundle / p).read_bytes()).hexdigest()} for p in required]}))
  self.calls = []
 def receipt(self):
  registry = f"{A}.dkr.ecr.{R}.amazonaws.com/"
  rows = [{"component": c, "image_ref":registry + N + "-baseline-gitops-nodes@" + D, "tag":"a" * 64, "manifest_digest":D} for c in ("kyverno-preflight", "kyverno", "kyverno-background-controller", "kyverno-cleanup-controller", "kyverno-reports-controller", "kyverno-readiness-checker", "kyverno-cli")]
  rows.append({"component":"kyverno-chart", "image_ref":registry + N + "-baseline-gitops-charts@" + D, "tag":"3.8.1", "manifest_digest":D})
  return {"status":"verified", "scope":"non-Vault OCI artifacts", "aws_account_id":A, "aws_region":R, "deployment_name":N, "artifacts":rows}
 def runner(self, command, **kwargs):
  self.calls.append((command, kwargs))
  output = json.dumps({"apiVersion":"kyverno.io/v1", "kind":"ClusterPolicy", "metadata":{"name":"node-operator-project-workload-baseline"}, "spec":{}}) if "create" in command else ""
  return subprocess.CompletedProcess(command, 0, output, "")
 def invoke(self):
  session = type("S", (), {"verify":staticmethod(lambda *args: {"cluster_name":N, "aws_region":R, "ssm_ops_instance_id":"i-0123456789abcdef0"})})
  with patch.object(bootstrap, "verify_full_mirror", return_value=self.receipt()), patch.object(bootstrap, "_module", side_effect=[import_module(ROOT / "scripts/release/kyverno_bootstrap_inputs.py"), session]):
   bootstrap.install(bundle_root=self.bundle, state_dir=self.state, work_dir=self.work, inputs_dir=self.inputs, session=self.state / "private-eks-session.json", baseline_config=self.inputs / "baseline.tfvars.json", account=A, region=R, deployment=N, profile="chosen", release_sha="a" * 40, runner=self.runner)
 def test_private_digest_chart_precedes_policy_apply_and_ready_wait(self):
  self.invoke(); commands = [x[0] for x in self.calls]; helm = next(i for i, x in enumerate(commands) if "helm" in x); render = next(i for i, x in enumerate(commands) if "create" in x); dry = next(i for i, x in enumerate(commands) if "--dry-run=server" in x); wait = next(i for i, x in enumerate(commands) if "clusterpolicy/node-operator-project-workload-baseline" in x)
  self.assertLess(helm, render); self.assertLess(render, dry); self.assertLess(dry, wait); self.assertTrue(any(x.startswith("oci://") for x in commands[helm])); self.assertTrue(any("@sha256:" in x for x in commands[helm])); self.assertNotIn("--set", commands[helm]); self.assertNotIn("--disable-openapi-validation", commands[helm])
  self.assertEqual(next(kwargs["timeout"] for command, kwargs in self.calls if "helm" in command), 660)
 def test_endpoint_override_refuses_before_mirror_or_commands(self):
  with patch.dict(bootstrap.os.environ, {"AWS_ENDPOINT_URL":""}, clear=True), patch.object(bootstrap, "verify_full_mirror") as mirror:
   with self.assertRaises(bootstrap.KyvernoBootstrapError): self.invoke()
  mirror.assert_not_called(); self.assertEqual(self.calls, [])
 def test_wrong_policy_rendering_refuses_after_helm_and_before_policy_apply(self):
  original = self.runner
  def malformed(command, **kwargs):
   value = original(command, **kwargs)
   return subprocess.CompletedProcess(command, 0, "{}", "") if "create" in command else value
  self.runner = malformed
  with self.assertRaises(bootstrap.KyvernoBootstrapError): self.invoke()
  commands = [call for call, _ in self.calls]
  self.assertTrue(any("helm" in call for call in commands))
  self.assertFalse(any("--dry-run=server" in call for call in commands))
 def test_interactive_installs_kyverno_before_collector(self):
  source = (ROOT / "scripts/release/interactive-hoodi-release.sh").read_text()
  self.assertLess(source.index("Installing verified private Kyverno"), source.index("Applying verified validator log collector"))

def import_module(path):
 spec = importlib.util.spec_from_file_location("inputs", path); module = importlib.util.module_from_spec(spec); assert spec.loader; spec.loader.exec_module(module); return module

if __name__ == "__main__": unittest.main()
