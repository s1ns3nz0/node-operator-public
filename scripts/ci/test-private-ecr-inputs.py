#!/usr/bin/env python3
# Check objective: Verify mirror input rejection and per-job credentials, target guards and checkout isolation.
import importlib.util
from pathlib import Path
import re
import os
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("inputs", ROOT / "scripts/ci/validate-private-ecr-inputs.py")
inputs = importlib.util.module_from_spec(spec)
spec.loader.exec_module(inputs)


class MirrorContract(unittest.TestCase):
    def test_cli(self):
        env = dict(os.environ, MIRROR_TARGET="vault-chart", SOURCE="", DESTINATION="none",
                   GITHUB_REF="refs/heads/main")
        command = [sys.executable, str(ROOT / "scripts/ci/validate-private-ecr-inputs.py")]
        result = subprocess.run(command, env=env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("PASS", result.stdout)
        env["MIRROR_TARGET"] = "signer"
        result = subprocess.run(command, env=env, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("immutable source digest", result.stderr)

    def test_valid_targets(self):
        for target in inputs.TARGETS:
            with self.subTest(target=target):
                inputs.validate(target, "example/image@sha256:" + "a" * 64 if target in inputs.SOURCED else "",
                                "nodes" if target == "gitops" else "none", "refs/heads/main")

    def test_invalid_inputs(self):
        for args in [("unknown", "", "none", "refs/heads/main"),
                     ("private-dast", "", "none", "refs/heads/dev"),
                     ("gitops", "example@sha256:" + "a" * 64, "none", "refs/heads/main"),
                     ("vault-chart", "", "nodes", "refs/heads/main"),
                     ("vault-chart", "example@sha256:" + "a" * 64, "none", "refs/heads/main")]:
            with self.subTest(args=args), self.assertRaises(ValueError):
                inputs.validate(*args)
        for target in inputs.SOURCED:
            for source in ["", "image:latest", "image@sha256:abc", "image\n@sha256:" + "a" * 64]:
                with self.subTest(target=target, source=source), self.assertRaises(ValueError):
                    inputs.validate(target, source, "nodes" if target == "gitops" else "none", "refs/heads/main")

    def test_job_isolation(self):
        workflow = (ROOT / ".github/workflows/private-ecr-mirror.yml").read_text()
        header, body = workflow.split("jobs:\n", 1)
        self.assertNotIn("id-token: write", header)
        self.assertNotIn("packages:", header)
        chunks = re.split(r"^  ([\w-]+):\n", body, flags=re.M)
        jobs = dict(zip(chunks[1::2], chunks[2::2]))
        self.assertEqual(set(jobs), inputs.TARGETS | {"preflight"})
        self.assertNotIn("id-token:", jobs["preflight"])
        self.assertNotIn("AWS_ROLE_ARN", jobs["preflight"])
        boundaries = {
            "signer": ("ecr-signer-mirror", "ECR_SIGNER_MIRROR_ROLE_ARN"),
            "gitops": ("gitops-oci-mirror", "GITOPS_OCI_MIRROR_ROLE_ARN"),
            "private-dast": ("private-dast-ecr-mirror", "PRIVATE_DAST_ECR_MIRROR_ROLE_ARN"),
            "validator-client": ("validator-client-ecr-mirror", "VALIDATOR_CLIENT_ECR_MIRROR_ROLE_ARN"),
            "validator-log-collector": ("validator-log-collector-ecr-mirror", "VALIDATOR_LOG_COLLECTOR_ECR_MIRROR_ROLE_ARN"),
            "validator-runtime": ("validator-runtime-ecr-mirror", "VALIDATOR_RUNTIME_ECR_MIRROR_ROLE_ARN"),
            "vault-chart": ("gitops-oci-mirror", "GITOPS_OCI_MIRROR_ROLE_ARN"),
            "cert-manager-chart": ("gitops-oci-mirror", "GITOPS_OCI_MIRROR_ROLE_ARN"),
        }
        for target in inputs.TARGETS:
            job = jobs[target]
            with self.subTest(target=target):
                self.assertIn("needs: [preflight]", job)
                self.assertIn("github.ref == 'refs/heads/main'", job)
                self.assertIn("inputs.target == '" + target + "'", job)
                self.assertIn("needs.preflight.result == 'success'", job)
                self.assertIn("id-token: write", job)
                environment, role = boundaries[target]
                self.assertIn("environment: " + environment + "\n", job)
                self.assertIn("AWS_ROLE_ARN: ${{ vars." + role + " }}", job)
                self.assertIn("actions/checkout@", job)
                self.assertLess(job.index("actions/checkout@"), job.index("run:"))
                self.assertEqual("packages: read" in job, target == "signer")


if __name__ == "__main__":
    unittest.main()
