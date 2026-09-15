#!/usr/bin/env python3
"""Sandbox contract for local artifact bootstrap after zero prerequisites."""
from __future__ import annotations
import json, os, subprocess, tempfile, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CLI = ROOT / "scripts/release/hoodi-validator-release.sh"

class LocalArtifactBootstrap(unittest.TestCase):
    def test_infrastructure_bootstraps_after_zero_prepare_before_inventory(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); bundle = root / "bundle"; release = bundle / "source/scripts/release"; release.mkdir(parents=True)
            (bundle / "bundle-manifest.json").write_text(json.dumps({"source_revision": "a" * 40}))
            inputs = root / "inputs"; zero = inputs / "zero-resource"; zero.mkdir(parents=True)
            baseline = zero / "baseline.tfvars.json"; baseline.write_text(json.dumps({"name": "node-operator"}))
            (zero / "zero-resource-inputs.json").write_text(json.dumps({"schema_version": 1, "aws_account_id": "123456789012", "aws_region": "ap-northeast-2", "baseline_config": str(baseline)}))
            handoff = inputs / "validator-deployment"; handoff.mkdir(); (handoff / "validator-deployment-handoff.json").write_text(json.dumps({"schema_version": 1, "network": "hoodi", "aws_account_id": "123456789012", "aws_region": "ap-northeast-2", "staged_client_replicas": 0, "staged_fence_replicas": 0}))
            top = inputs / "hoodi-zero-release-inputs.json"; top.write_text(json.dumps({"schema_version": 1, "network": "hoodi", "aws_account_id": "123456789012", "aws_region": "ap-northeast-2", "validator_set": "hoodi-1", "zero_resource_inputs": str(zero / "zero-resource-inputs.json"), "validator_deployment_handoff": str(handoff / "validator-deployment-handoff.json"), "required_checkpoints": [1,2,3,4,5,6]}))
            log = root / "trace"
            def tool(name: str, code: str) -> None:
                target = release / name; target.write_text("#!/bin/sh\nset -eu\n" + code); target.chmod(0o755)
            tool("node-operator-release.sh", 'printf "node:%s:%s\\n" "$1" "${2:-}" >> "$TRACE"; [ "$1:$2" != "zero:prepare-artifacts" ] || mkdir -p "$8"')
            tool("bootstrap-local-installer-artifacts.sh", 'printf "bootstrap:%s\\n" "$*" >> "$TRACE"; : > "$4/local-artifact-authority.json"')
            inventory = release / "installer_artifact_inventory.py"; inventory.write_text('#!/usr/bin/env python3\nimport os, sys\nopen(os.environ["TRACE"], "a").write("inventory:" + " ".join(sys.argv[1:]) + "\\n")\nraise SystemExit(0 if "--local-artifact-authority" in sys.argv else 92)\n'); inventory.chmod(0o755)
            mirror = release / "mirror-installer-vault-artifacts.py"; mirror.write_text('#!/usr/bin/env python3\nimport os, sys\nopen(os.environ["TRACE"], "a").write("mirror:" + sys.argv[1] + "\\n")\n'); mirror.chmod(0o755)
            bin_dir = root / "bin"; bin_dir.mkdir(); aws = bin_dir / "aws"; aws.write_text('#!/bin/sh\nprintf "aws:%s:%s\\n" "$1" "$2" >> "$TRACE"\n[ "$1:$2" = "sts:get-caller-identity" ] && { echo 123456789012; exit 0; }; exit 64\n'); aws.chmod(0o755)
            env = os.environ | {"PATH": f"{bin_dir}:{os.environ['PATH']}", "TRACE": str(log), "AWS_ACCESS_KEY_ID": "blocked", "AWS_SECRET_ACCESS_KEY": "blocked", "AWS_SESSION_TOKEN": "blocked"}
            result = subprocess.run([str(CLI), "infrastructure", "apply", "--bundle-root", str(bundle), "--inputs", str(top), "--work-dir", str(root / "work"), "--profile", "sandbox"], text=True, capture_output=True, env=env)
            self.assertEqual(result.returncode, 0, result.stderr)
            rows = log.read_text().splitlines()
            prepare = rows.index("node:zero:prepare-artifacts")
            bootstrap = next(i for i, row in enumerate(rows) if row.startswith("bootstrap:"))
            inventory = next(i for i, row in enumerate(rows) if row.startswith("inventory:"))
            self.assertLess(prepare, bootstrap); self.assertLess(bootstrap, inventory)
            self.assertTrue(all(not row.startswith("aws:") or row == "aws:sts:get-caller-identity" for row in rows))

if __name__ == "__main__": unittest.main()
