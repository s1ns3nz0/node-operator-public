#!/usr/bin/env python3
"""Sandbox checks for the release-bundled local artifact authority handoff."""
from __future__ import annotations
import os, subprocess, tempfile, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/release/bootstrap-local-installer-artifacts.sh"

class BootstrapLocalArtifacts(unittest.TestCase):
    def fixture(self, root: Path):
        bundle = root / "bundle"; release = bundle / "source/scripts/release"; release.mkdir(parents=True); (bundle / "bundle-manifest.json").write_text("{}")
        work = root / "work"; work.mkdir(); (work / "artifact-prerequisites.json").write_text("{}")
        bin_dir = root / "bin"; bin_dir.mkdir()
        cosign = bin_dir / "cosign"; cosign.write_text("#!/bin/sh\nprintf 'cosign:%s\\n' \"$1\" >> \"$TRACE\"\nexit 0\n"); cosign.chmod(0o755)
        publisher = release / "local-installer-artifact-publisher.sh"
        publisher.write_text("#!/bin/sh\nset -eu\nout=''; while [ \"$#\" -gt 0 ]; do [ \"$1\" = --output ] && out=$2; shift; done\nprintf '{}' > \"$out\"\nprintf public > \"$(dirname \"$out\")/local-artifact-authority.pub\"\nprintf signature > \"$(dirname \"$out\")/local-artifact-authority.sigstore.json\"\n")
        publisher.chmod(0o755)
        trace = root / "trace"
        env = os.environ | {"PATH": f"{bin_dir}:{os.environ['PATH']}", "TRACE": str(trace), "AWS_ACCESS_KEY_ID": "blocked", "AWS_SECRET_ACCESS_KEY": "blocked", "AWS_SESSION_TOKEN": "blocked", "NODE_OPERATOR_LOCAL_ARTIFACT_PUBLISHER": str(root / "attacker-publisher"), "NODE_OPERATOR_LOCAL_ARTIFACT_AUTHORITY_PUBLIC_KEY": str(root / "attacker.pub")}
        args = [str(SCRIPT), "--bundle-root", str(bundle), "--work-dir", str(work), "--account", "123456789012", "--region", "ap-northeast-2", "--deployment-name", "node-operator", "--release-sha", "a" * 40]
        return work, env, args, trace

    def test_bundled_publisher_output_is_verified_without_aws(self):
        with tempfile.TemporaryDirectory() as temporary:
            work, env, args, trace = self.fixture(Path(temporary))
            result = subprocess.run(args, text=True, capture_output=True, env=env)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue((work / "local-artifact-authority.json").is_file())
            self.assertEqual(trace.read_text().splitlines(), ["cosign:verify-blob"])
            self.assertIn("PASS local artifact", result.stdout)

    def test_existing_authority_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as temporary:
            work, env, args, _ = self.fixture(Path(temporary)); authority = work / "local-artifact-authority.json"; authority.write_text("original")
            result = subprocess.run(args, text=True, capture_output=True, env=env)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(authority.read_text(), "original")

if __name__ == "__main__": unittest.main()
