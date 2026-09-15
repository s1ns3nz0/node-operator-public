#!/usr/bin/env python3
# Check objective: Block Docker access before approved image evidence verification.
"""Prove verifier ordering using doubles; actual Cosign validation has its own suite."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class RunnerAdmissionTests(unittest.TestCase):
    def run_case(self, reject=False, missing=False, preflight=False, run_id="123"):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            scripts = root / "scripts/ci"; (scripts / "workflows").mkdir(parents=True)
            script = scripts / "workflows/check-private-runner.sh"
            script.write_bytes((ROOT / "scripts/ci/workflows/check-private-runner.sh").read_bytes())
            (scripts / "verify-ci-image-evidence.sh").write_text(
                'echo verify >> "$TRACE"\nexit ' + ("65" if reject else "0") + '\n')
            tools = root / "bin"; tools.mkdir()
            docker = tools / "docker"
            docker.write_text('#!/bin/sh\necho "docker:$1" >> "$TRACE"\nexit 0\n'); docker.chmod(0o755)
            trace = root / "trace"
            env = {**os.environ, "PATH": str(tools) + os.pathsep + os.environ["PATH"],
                   "TRACE": str(trace), "CODEBUILD_BUILD_ID": "test", "GITHUB_RUN_ID": "1",
                   "REGISTRY_TOKEN": "synthetic", "REGISTRY_USERNAME": "test",
                   "RELEASE_BUILD_IMAGE": "ghcr.io/s1ns3nz0/node-operator/release-build@sha256:" + "b" * 64,
                   "RELEASE_BUILD_SOURCE_SHA": "a" * 40, "RELEASE_BUILD_PUBLICATION_RUN_ID": run_id,
                   "RELEASE_BUILD_SBOM": "sbom", "RELEASE_BUILD_RECEIPT": "receipt"}
            if missing: env.pop("RELEASE_BUILD_SOURCE_SHA")
            result = subprocess.run(["bash", str(script)] + (["--preflight"] if preflight else []), env=env, capture_output=True, timeout=10)
            return result.returncode, trace.read_text().splitlines() if trace.exists() else []

    def test_denial_precedes_daemon_and_credentials(self):
        code, trace = self.run_case(reject=True)
        self.assertEqual(code, 65); self.assertEqual(trace, ["verify"])

    def test_missing_approval_does_not_touch_daemon(self):
        code, trace = self.run_case(missing=True)
        self.assertNotEqual(code, 0); self.assertEqual(trace, [])

    def test_success_order(self):
        code, trace = self.run_case()
        self.assertEqual(code, 0)
        self.assertEqual(trace, ["verify", "docker:version", "docker:login", "docker:pull"])

    def test_publication_run_is_required_before_artifact_download(self):
        for run_id in ("", "0", "latest", "12x"):
            code, trace = self.run_case(preflight=True, run_id=run_id)
            self.assertNotEqual(code, 0); self.assertEqual(trace, [])
        code, trace = self.run_case(preflight=True)
        self.assertEqual(code, 0); self.assertEqual(trace, [])


if __name__ == "__main__": unittest.main()
