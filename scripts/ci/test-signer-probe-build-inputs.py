#!/usr/bin/env python3
# Check objective: Validate the signer-probe reviewed build-input hash.
"""Offline contract checks for the signer-probe reviewed build input hash."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts" / "release"))
import signer_probe_build_inputs as inputs

EXPECTED_INPUTS = (
    "go.mod",
    ".ci/validator-signer-identity-probe/Dockerfile",
    ".ci/validator-signer-identity-probe/Dockerfile.dockerignore",
    "cmd/validator-signer-identity-probe/main.go",
    "cmd/validator-signer-identity-probe/main_test.go",
)


class SignerProbeBuildInputsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "source"
        self.root.mkdir()
        for relative in inputs.INPUT_PATHS:
            destination = self.root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / relative, destination)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_cli_hash_is_deterministic_and_ordered(self) -> None:
        self.assertEqual(inputs.INPUT_PATHS, EXPECTED_INPUTS)
        expected = inputs.signer_probe_input_sha256(self.root)
        completed = subprocess.run([sys.executable, str(ROOT / "scripts" / "release" / "signer_probe_build_inputs.py"), "--root", str(self.root)], text=True, capture_output=True, timeout=10)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stdout.strip(), expected)
        raw = "".join(hashlib.sha256((self.root / relative).read_bytes()).hexdigest() + "\n" for relative in EXPECTED_INPUTS).encode("ascii")
        self.assertEqual(expected, hashlib.sha256(raw).hexdigest())
        (self.root / "unrelated.txt").write_text("unreviewed")
        self.assertEqual(inputs.signer_probe_input_sha256(self.root), expected)
        for relative in EXPECTED_INPUTS:
            path = self.root / relative
            original = path.read_bytes()
            path.write_bytes(original + b"\n// changed\n")
            self.assertNotEqual(inputs.signer_probe_input_sha256(self.root), expected, relative)
            path.write_bytes(original)
            self.assertEqual(inputs.signer_probe_input_sha256(self.root), expected, relative)

    def test_missing_and_symlinked_inputs_fail_closed(self) -> None:
        (self.root / inputs.INPUT_PATHS[-1]).unlink()
        with self.assertRaises(inputs.SignerProbeInputError):
            inputs.signer_probe_input_sha256(self.root)

    def test_relative_root_and_symlinked_root_or_parent_fail_closed(self) -> None:
        with self.assertRaises(inputs.SignerProbeInputError):
            inputs.signer_probe_input_sha256(Path("relative"))
        linked_root = self.root.parent / "linked-source"
        linked_root.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(inputs.SignerProbeInputError):
            inputs.signer_probe_input_sha256(linked_root)
        ci = self.root / ".ci"
        real_ci = self.root / "real-ci"
        ci.rename(real_ci)
        ci.symlink_to(real_ci, target_is_directory=True)
        with self.assertRaises(inputs.SignerProbeInputError):
            inputs.signer_probe_input_sha256(self.root)
        destination = self.root / inputs.INPUT_PATHS[-1]
        destination.write_text("replacement")
        destination.unlink()
        destination.symlink_to(self.root / inputs.INPUT_PATHS[0])
        with self.assertRaises(inputs.SignerProbeInputError):
            inputs.signer_probe_input_sha256(self.root)

    def test_local_builder_passes_canonical_hash_as_the_label_build_argument(self) -> None:
        expected = inputs.signer_probe_input_sha256(ROOT)
        fake = Path(self.temporary.name) / "bin"; fake.mkdir()
        log = Path(self.temporary.name) / "docker.args"
        docker = fake / "docker"
        docker.write_text("#!/usr/bin/env bash\nset -euo pipefail\nif [ \"$1:$2\" = buildx:version ]; then exit 0; fi\nif [ \"$1:$2\" = buildx:build ]; then printf '%s\\n' \"$@\" > \"$DOCKER_LOG\"; exit 0; fi\nif [ \"$1:$2\" = image:inspect ]; then printf '%s\\n' sha256:$(printf 'a%.0s' {1..64}); exit 0; fi\nexit 99\n")
        docker.chmod(0o755)
        environment = dict(os.environ, PATH=f"{fake}:{os.environ['PATH']}", DOCKER_LOG=str(log))
        completed = subprocess.run(["bash", str(ROOT / "scripts" / "ci" / "build-validator-images.sh"), "identity-probe"], cwd=ROOT, env=environment, text=True, capture_output=True, timeout=20)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        arguments = log.read_text().splitlines()
        self.assertIn("SIGNER_PROBE_INPUT_SHA=" + expected, arguments)
        dockerfile = (ROOT / ".ci" / "validator-signer-identity-probe" / "Dockerfile").read_text()
        self.assertIn("ARG SIGNER_PROBE_INPUT_SHA", dockerfile)
        self.assertIn("io.node-operator.signer-probe-input-sha", dockerfile)


if __name__ == "__main__":
    unittest.main(verbosity=2)
