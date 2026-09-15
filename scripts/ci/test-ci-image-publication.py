#!/usr/bin/env python3
# Check objective: Prevent image promotion when publication prerequisites fail.
"""Run real publishers with synthetic archives and traced registry/signing doubles.

Objective: prove rejected evidence never reaches login, and signing failure
never promotes main. This tests orchestration, not cryptographic validity.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SHA = "a" * 40
CONFIG = "sha256:" + "b" * 64
SCANNER_INPUTS = [".ci/scanners/Dockerfile", ".ci/scanners/Dockerfile.dockerignore",
                  ".ci/scanners/run-security-scan.sh", "scripts/ci/collect-pr-evidence.sh",
                  "scripts/ci/collect-security-evidence.sh", "scripts/ci/lib/common.sh"]


class PublicationTests(unittest.TestCase):
    def exercise(self, kind, mode):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for relative in (f"scripts/release/publish-{kind}-image.sh", "scripts/ci/image_sbom_evidence.py", "policy/image_sbom.rego"):
                dest = root / relative
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / relative, dest)
            inputs = SCANNER_INPUTS if kind == "scanner" else [".ci/toolchains/terraform-validation.Dockerfile"]
            hashes = []
            for relative in inputs:
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"fixture\n")
                hashes.append(hashlib.sha256(path.read_bytes()).hexdigest())
            input_hash = hashlib.sha256(("\n".join(hashes) + "\n").encode()).hexdigest()
            stage = root / "stage"
            stage.mkdir()
            (stage / f"{kind}-input.sha256").write_text(input_hash)
            archive = stage / f"{kind}-image.tar"
            archive.write_bytes(b"synthetic archive; never loaded by real Docker")
            sbom_dir = stage / f"{kind}-sbom"
            sbom_dir.mkdir()
            sbom = sbom_dir / "sbom.cyclonedx.json"
            sbom.write_text(json.dumps({
                "bomFormat": "CycloneDX", "specVersion": "1.5",
                "metadata": {"tools": [{"name": "syft", "version": "fixture"}],
                             "component": {"version": "sha256:" + hashlib.sha256(archive.read_bytes()).hexdigest()}},
                "components": [{"type": "library", "name": "example", "version": "1", "purl": "pkg:generic/example@1"}],
            }))
            receipt = sbom_dir / "receipt.json"
            subject = "security-scanners" if kind == "scanner" else "terraform-validation"
            subprocess.run(["python3", str(ROOT / "scripts/ci/image_sbom_evidence.py"), "create",
                            "--archive", str(archive), "--sbom", str(sbom), "--revision", SHA,
                            "--image-config-digest", CONFIG, "--subject", subject, "--output", str(receipt)],
                           check=True, capture_output=True)
            if mode == "tamper":
                archive.write_bytes(b"tampered archive")
            if mode == "opa-deny":
                (root / "policy/image_sbom.rego").write_text("package nodeoperator.image_sbom\nimport rego.v1\ndefault allow := false\n")
            bin_dir = root / "bin"
            bin_dir.mkdir()
            docker = bin_dir / "docker"
            docker.write_text("""#!/usr/bin/env python3
import json, os, sys
with open(os.environ['TRACE'], 'a') as f: f.write(json.dumps(sys.argv[1:])+'\\n')
if sys.argv[1:3] == ['image','inspect']:
    print(os.environ['CONFIG'] if '{{.Id}}' in sys.argv else os.environ['INPUT_HASH'])
elif sys.argv[1] == 'login':
    sys.stdin.read()
elif sys.argv[1] not in ('load','tag','push'):
    raise SystemExit(99)
""")
            docker.chmod(0o755)
            (bin_dir / "cosign").write_text("#!/bin/sh\nexit 99\n")
            (bin_dir / "cosign").chmod(0o755)
            helper = root / "scripts/release/sign-ci-image-evidence.sh"
            helper.write_text(
                'case "$5" in\n'
                '  */toolchain-signing-evidence/*)\n'
                '    test -d "$(dirname "$5")" && test ! -e "$5" || exit 98\n'
                '    ;;\n'
                'esac\n'
                'printf \'["signing-helper"]\\n\' >> "$TRACE"\n'
                'exit "$SIGNING_EXIT"\n'
            )
            trace = root / "trace.jsonl"
            env = {key: value for key, value in os.environ.items() if not key.startswith(("GITHUB_", "ACTIONS_", "AWS_"))}
            env.update(PATH=str(bin_dir) + os.pathsep + os.environ["PATH"], TRACE=str(trace), CONFIG=CONFIG,
                       INPUT_HASH=input_hash, GITHUB_SHA=SHA, GITHUB_REF="refs/heads/main",
                       GITHUB_REPOSITORY="s1ns3nz0/node-operator", GITHUB_RUN_ID="123",
                       IMAGE=f"ghcr.io/s1ns3nz0/node-operator/{subject}", IMAGE_NAME=subject,
                       DOCKERFILE=inputs[0], INPUT_FILE="", RUNNER_TEMP=str(root / "runtime"),
                       SCANNER_IMAGE_DIR=str(stage), TOOLCHAIN_IMAGE_DIR=str(stage),
                       REGISTRY_TOKEN="synthetic", REGISTRY_USERNAME="synthetic",
                       SIGNING_EXIT="1" if mode == "signing-deny" else "0")
            result = subprocess.run(["bash", f"scripts/release/publish-{kind}-image.sh"],
                                    cwd=root, env=env, capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode == 0, mode == "pass", result.stdout + result.stderr)
            calls = [json.loads(line) for line in trace.read_text().splitlines()] if trace.exists() else []
            commands = [call[0] for call in calls]
            if mode in ("tamper", "opa-deny"):
                self.assertNotIn("login", commands)
                self.assertNotIn("push", commands)
                self.assertNotIn("signing-helper", commands)
            else:
                sign_index = commands.index("signing-helper")
                pushes = [call[-1] for call in calls if call[0] == "push"]
                self.assertEqual(pushes[0], env["IMAGE"] + ":" + SHA)
                self.assertLess(commands.index("push"), sign_index)
                if mode == "signing-deny":
                    self.assertEqual(len(pushes), 1)
                    self.assertFalse(any(call[-1] == env["IMAGE"] + ":main" for call in calls))
                else:
                    self.assertEqual(pushes[1], env["IMAGE"] + ":main")
                    self.assertGreater(max(i for i, call in enumerate(calls) if call[0] == "push"), sign_index)

    def test_both_publishers_fail_closed_and_promote_only_after_signing(self):
        for kind in ("scanner", "toolchain"):
            for mode in ("tamper", "opa-deny", "signing-deny", "pass"):
                with self.subTest(kind=kind, mode=mode):
                    self.exercise(kind, mode)


if __name__ == "__main__":
    unittest.main()
