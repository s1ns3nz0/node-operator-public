#!/usr/bin/env python3
"""Offline contract for first-party local Vault artifact publication."""
from __future__ import annotations
import json, os, subprocess, tempfile, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PUBLISHER = ROOT / "scripts/release/local-installer-artifact-publisher.sh"
REVISION = "a" * 40
DIGESTS = {"vault-bootstrap": "b", "gitops-oci-mirror": "c", "vault-audit-relay": "d"}

class LocalPublisher(unittest.TestCase):
    def test_builds_publishes_and_signs_only_first_party_vault_artifacts(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); bundle = root / "bundle"; source = bundle / "source"; work = root / "work"; work.mkdir()
            for relative in (".ci/toolchains/vault-bootstrap.Dockerfile", ".ci/toolchains/gitops-oci-mirror.Dockerfile", ".ci/vault-audit-relay/Dockerfile"):
                path = source / relative; path.parent.mkdir(parents=True, exist_ok=True); path.write_text("FROM scratch\n")
            (bundle / "bundle-manifest.json").write_text("{}")
            bin_dir = root / "bin"; bin_dir.mkdir(); log = root / "log"
            (bin_dir / "docker").write_text("#!/bin/sh\nprintf 'docker:%s\\n' \"$1\" >> \"$LOG\"\nexit 0\n")
            (bin_dir / "aws").write_text("#!/bin/sh\nprintf 'aws:%s\\n' \"$1\" >> \"$LOG\"\ncase \"$*\" in *vault-bootstrap*) x=b;; *gitops-oci-mirror*) x=c;; *vault-audit-relay*) x=d;; *) exit 64;; esac\nprintf 'sha256:%064d\\n' 0 | tr '0' \"$x\"\n")
            (bin_dir / "cosign").write_text("#!/bin/sh\nprintf 'cosign:%s\\n' \"$1\" >> \"$LOG\"\nif [ \"$1\" = generate-key-pair ]; then while [ \"$#\" -gt 0 ]; do [ \"$1\" = --output-key-prefix ] && p=$2; shift; done; : > \"$p.key\"; : > \"$p.pub\"; elif [ \"$1\" = sign-blob ]; then while [ \"$#\" -gt 0 ]; do [ \"$1\" = --bundle ] && b=$2; shift; done; : > \"$b\"; fi\n")
            for path in bin_dir.iterdir(): path.chmod(0o755)
            output = work / "local-artifact-authority.json"
            env = os.environ | {"PATH": f"{bin_dir}:{os.environ['PATH']}", "LOG": str(log), "AWS_ACCESS_KEY_ID": "blocked", "AWS_SECRET_ACCESS_KEY": "blocked", "AWS_SESSION_TOKEN": "blocked"}
            result = subprocess.run([str(PUBLISHER), "--bundle-root", str(bundle), "--work-dir", str(work), "--account", "123456789012", "--region", "ap-northeast-2", "--deployment-name", "node-operator", "--release-sha", REVISION, "--output", str(output)], text=True, capture_output=True, env=env)
            self.assertEqual(result.returncode, 0, result.stderr)
            authority = json.loads(output.read_text())
            self.assertEqual(authority["release_revision"], REVISION)
            self.assertEqual({item["component"] for item in authority["artifacts"]}, set(DIGESTS))
            self.assertEqual(next(item for item in authority["artifacts"] if item["component"] == "gitops-oci-mirror")["destination"], None)
            self.assertIn("cosign:sign-blob", log.read_text())
            self.assertNotIn("aws:sts", log.read_text())

if __name__ == "__main__": unittest.main()
