#!/usr/bin/env python3
# Check objective: Verify suite ordering, failure propagation and pinned offline container boundaries without executing infrastructure tools.
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
import re

ROOT = Path(__file__).resolve().parents[2]


class Entrypoints(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.work = Path(self.tmp.name)
        self.log = self.work / "calls.jsonl"
        self.bin = self.work / "bin"
        self.bin.mkdir()
        self.env = dict(os.environ, PATH=str(self.bin) + os.pathsep + os.environ["PATH"],
                        CALL_LOG=str(self.log), CI_OUTPUT_DIR=str(self.work / "output"))
        self.env.pop("TERRAFORM_IMAGE", None)

    def mock(self, name):
        import sys
        path = self.bin / name
        path.write_text("#!" + sys.executable + "\n" +
                        "import json,os,sys\n"
                        "with open(os.environ['CALL_LOG'],'a') as f: f.write(json.dumps(sys.argv[1:])+'\\n')\n"
                        "sys.exit(int(os.environ.get('MOCK_EXIT','0')))\n")
        path.chmod(0o700)

    def run_script(self, name, *args):
        return subprocess.run(["/bin/bash", str(ROOT / "scripts/ci" / name), *args],
                              cwd=self.work, env=self.env, capture_output=True, text=True)

    def calls(self):
        return [json.loads(line) for line in self.log.read_text().splitlines()] if self.log.exists() else []

    def test_suite_lists_and_runs_identical_order_from_another_directory(self):
        self.mock("python3")
        listed = self.run_script("run-suite.sh", "uc5-offline", "--list")
        self.assertEqual(listed.returncode, 0, listed.stderr)
        self.assertEqual(self.calls(), [])
        result = self.run_script("run-suite.sh", "uc5-offline")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([args[-1] for args in self.calls()], listed.stdout.splitlines())
        self.assertEqual(len(self.calls()), 15)

    def test_suite_stops_at_first_failure(self):
        self.mock("python3")
        self.env["MOCK_EXIT"] = "42"
        self.assertEqual(self.run_script("run-suite.sh", "uc5-offline").returncode, 42)
        self.assertEqual(len(self.calls()), 1)

    def test_unknown_suite_and_traversal_rejected(self):
        for suite in ("missing", "../policy", "/tmp/policy"):
            self.assertEqual(self.run_script("run-suite.sh", suite).returncode, 64)
        self.assertEqual(self.calls(), [])

    def test_all_terraform_suites_dispatch_pinned_offline_calls(self):
        self.mock("docker")
        self.mock("python3")
        result = self.run_script("run-terraform-ci.sh", "all")
        self.assertEqual(result.returncode, 0, result.stderr)
        docker_calls = [args for args in self.calls() if args[0] == "run"]
        python_calls = [args for args in self.calls() if args[0] != "run"]
        self.assertEqual(
            [args[args.index("bash") + 1] for args in docker_calls],
            [
                "/workspace/scripts/ci/validate-terraform-offline.sh",
                "/workspace/scripts/ci/test-selected-terraform-apply-role-plan.sh",
                "/workspace/scripts/ci/test-validator-runtime-mirror-enabled-plan.sh",
                "/workspace/scripts/ci/test-argocd-bootstrap-enabled-plan.sh",
                "/workspace/scripts/ci/test-argocd-bootstrap-destination-contract.sh",
                "/workspace/scripts/ci/test-pre-eks-artifact-plan.sh",
                "/workspace/scripts/ci/validate-terraform-module-offline.sh",
                "/workspace/scripts/ci/validate-terraform-module-offline.sh",
                "/workspace/scripts/ci/validate-terraform-module-offline.sh",
                "/workspace/scripts/ci/validate-terraform-module-offline.sh",
                "/workspace/scripts/ci/test-bootstrap-state-cli.sh",
                "/workspace/scripts/ci/test-foundation-backend-contract.sh",
                "/workspace/scripts/ci/test-ops-access-basic-monitoring.sh",
                "/workspace/scripts/ci/test-ops-access-ebs-binding.sh",
            ],
        )
        for args in docker_calls:
            self.assertEqual(args[:2], ["run", "--rm"])
            self.assertEqual(args[args.index("--network") + 1], "none")
            self.assertEqual(args[args.index("--platform") + 1], "linux/amd64")
            self.assertIn(str(ROOT) + ":/workspace:ro", args)
            image = args[args.index("bash") - 1]
            self.assertRegex(image, r"@sha256:[a-f0-9]{64}$")
            self.assertNotIn("--privileged", args)
        self.assertEqual(python_calls[-1], [str(ROOT / "scripts/ci/test-validator-monitoring-dashboard-terraform.py")])

    def test_dashboard_selector_forces_the_pinned_container_mode(self):
        import sys
        python = self.bin / "python3"
        python.write_text("#!" + sys.executable + "\n" +
                          "import json,os,sys\n" +
                          "with open(os.environ['CALL_LOG'],'a') as f: f.write(json.dumps({'args': sys.argv[1:], 'mode': os.environ.get('VALIDATOR_DASHBOARD_TERRAFORM_MODE'), 'image': os.environ.get('TERRAFORM_IMAGE')})+'\\n')\n")
        python.chmod(0o700)
        result = self.run_script("run-terraform-ci.sh", "dashboard")
        self.assertEqual(result.returncode, 0, result.stderr)
        call = json.loads(self.log.read_text())
        self.assertEqual(call["args"], [str(ROOT / "scripts/ci/test-validator-monitoring-dashboard-terraform.py")])
        self.assertEqual(call["mode"], "container")
        self.assertRegex(call["image"], r"@sha256:[a-f0-9]{64}$")

    def test_terraform_failure_stops_remaining_modules(self):
        self.mock("docker")
        self.env["MOCK_EXIT"] = "42"
        self.assertEqual(self.run_script("run-terraform-ci.sh", "all").returncode, 42)
        self.assertEqual(len(self.calls()), 1)

    def test_mutable_image_rejected_before_docker(self):
        self.mock("docker")
        self.env["TERRAFORM_IMAGE"] = "terraform:latest"
        self.assertEqual(self.run_script("run-terraform-ci.sh", "all").returncode, 64)
        self.assertEqual(self.calls(), [])

    def test_compatibility_gates_reject_every_non_success_result(self):
        cases = (
            ("continuous-integration.yml", "quality", ("FENCE_SECURITY_RESULT", "QUALITY_RESULT")),
            ("continuous-integration.yml", "scanners", ("SECURITY_RESULT",)),
        )
        import itertools
        for file, job, variables in cases:
            source = (ROOT / ".github/workflows" / file).read_text()
            gate = source.split("\n  " + job + ":", 1)[1]
            self.assertIn("    if: always()", gate)
            self.assertIn("    name: " + job, gate)
            if job == "quality":
                self.assertIn("needs: [fence-security, quality-tests]", gate)
                self.assertIn("FENCE_SECURITY_RESULT: ${{ needs.fence-security.result }}", gate)
                self.assertIn("QUALITY_RESULT: ${{ needs.quality-tests.result }}", gate)
            else:
                self.assertIn("needs: [security-scans]", gate)
                self.assertIn("SECURITY_RESULT: ${{ needs.security-scans.result }}", gate)
            command = re.search(r"^        run: (.+)$", gate, re.M)[1]
            self.assertEqual(command, " && ".join('test "$' + var + '" = success' for var in variables))
            for values in itertools.product(("success", "failure", "cancelled", "skipped"), repeat=len(variables)):
                result = subprocess.run(["/bin/bash", "-c", command],
                                        env=dict(zip(variables, values)), capture_output=True)
                self.assertEqual(result.returncode == 0, all(value == "success" for value in values))

    def test_workflow_script_calls_resolve(self):
        for workflow in (ROOT / ".github/workflows").glob("*.yml"):
            for match in re.finditer(r"run: (bash )?(scripts/[A-Za-z0-9_./-]+\.sh)", workflow.read_text()):
                path = ROOT / match[2]
                self.assertTrue(path.is_file(), str(path))
                if not match[1]:
                    self.assertTrue(os.access(path, os.X_OK), str(path))


if __name__ == "__main__":
    unittest.main()
