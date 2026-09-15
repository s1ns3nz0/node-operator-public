#!/usr/bin/env python3
"""Sandbox checks for the local artifact authority handoff."""
from __future__ import annotations
import os, stat, subprocess, tempfile, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/release/bootstrap-local-installer-artifacts.sh"

class BootstrapLocalArtifacts(unittest.TestCase):
    def fixture(self, root: Path):
        bundle = root / "bundle"; (bundle / "source").mkdir(parents=True); (bundle / "bundle-manifest.json").write_text("{}")
        work = root / "work"; work.mkdir(); (work / "artifact-prerequisites.json").write_text("{}")
        bin_dir = root / "bin"; bin_dir.mkdir()
        cosign = bin_dir / "cosign"; cosign.write_text("#!/bin/sh\nexit 0\n"); cosign.chmod(0o755)
        key = root / "authority.pub"; key.write_text("public")
        publisher = root / "publisher"; publisher.write_text("#!/bin/sh\nset -eu\nout=''; while [ \"$#\" -gt 0 ]; do [ \"$1\" = --output ] && out=$2; shift; done\nprintf '{}' > \"$out\"\nprintf '{}' > \"$(dirname \"$out\")/local-artifact-authority.sigstore.json\"\n"); publisher.chmod(0o755)
        env = os.environ | {"PATH": f"{bin_dir}:{os.environ['PATH']}", "NODE_OPERATOR_LOCAL_ARTIFACT_PUBLISHER": str(publisher), "NODE_OPERATOR_LOCAL_ARTIFACT_AUTHORITY_PUBLIC_KEY": str(key)}
        args = [str(SCRIPT), "--bundle-root", str(bundle), "--work-dir", str(work), "--account", "123456789012", "--region", "ap-northeast-2", "--deployment-name", "node-operator", "--release-sha", "a" * 40]
        return work, env, args

    def test_publisher_output_is_verified_without_aws(self):
        with tempfile.TemporaryDirectory() as temporary:
            work, env, args = self.fixture(Path(temporary))
            result = subprocess.run(args, text=True, capture_output=True, env=env)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue((work / "local-artifact-authority.json").is_file())
            self.assertIn("PASS local artifact", result.stdout)

    def test_existing_authority_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as temporary:
            work, env, args = self.fixture(Path(temporary)); authority = work / "local-artifact-authority.json"; authority.write_text("original")
            result = subprocess.run(args, text=True, capture_output=True, env=env)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(authority.read_text(), "original")

if __name__ == "__main__": unittest.main()
