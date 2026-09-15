#!/usr/bin/env python3
# Check objective: Validate the canonical Fence build-input digest command.
"""Offline contract tests for the canonical Fence build-input digest CLI."""

from __future__ import annotations

import hashlib
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
HELPER = ROOT / "scripts/release/fence_build_inputs.py"
INPUTS = (
    "go.mod",
    ".ci/validator-signing-fence/Dockerfile",
    "cmd/validator-signing-fence/main.go",
    "cmd/validator-signing-fence/main_test.go",
    "scripts/ci/collect-validator-signing-fence-release-evidence.sh",
    ".github/workflows/fence-security.yml",
    ".ci/fence-security/Dockerfile",
    ".ci/fence-security/blackbox.go",
    ".ci/fence-security/tools.env",
    ".ci/fence-security/zap-report.jq",
    "scripts/ci/install-fence-security-tools.sh",
    "scripts/ci/run-fence-security-sast.sh",
    "scripts/ci/run-fence-security-dast.sh",
)


def expected_digest(root: Path) -> str:
    hashes = []
    for relative in INPUTS:
        hashes.append(hashlib.sha256((root / relative).read_bytes()).hexdigest())
    return hashlib.sha256(("\n".join(hashes) + "\n").encode("ascii")).hexdigest()


class FenceBuildInputsCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.fixture = Path(self.temp.name) / "source"
        self.fixture.mkdir()
        for relative in INPUTS:
            destination = self.fixture / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / relative, destination)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def run_helper(self, root: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(HELPER), "--root", str(root)],
            text=True,
            capture_output=True,
            check=False,
        )

    def test_hashes_exact_ordered_source_bytes(self) -> None:
        baseline = expected_digest(self.fixture)
        result = self.run_helper(self.fixture)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), baseline)

        (self.fixture / "go.mod").write_bytes(b"changed source bytes\n")
        changed = self.run_helper(self.fixture)
        self.assertEqual(changed.returncode, 0, changed.stderr)
        self.assertEqual(changed.stdout.strip(), expected_digest(self.fixture))
        self.assertNotEqual(changed.stdout.strip(), baseline)

    def test_rejects_missing_required_input(self) -> None:
        (self.fixture / INPUTS[-1]).unlink()
        result = self.run_helper(self.fixture)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("required input is unavailable", result.stderr)

    def test_rejects_symlinked_required_input(self) -> None:
        target = self.fixture / INPUTS[0]
        saved = self.fixture / "saved-go.mod"
        target.rename(saved)
        target.symlink_to(saved.name)
        result = self.run_helper(self.fixture)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("symlink", result.stderr)

    def test_rejects_symlinked_source_root(self) -> None:
        source_link = self.fixture.parent / "source-link"
        source_link.symlink_to(self.fixture, target_is_directory=True)
        result = self.run_helper(source_link)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("source root must not be a symlink", result.stderr)

    def test_rejects_symlinked_input_parent(self) -> None:
        original = self.fixture / ".ci/fence-security"
        moved = self.fixture / "fence-security-real"
        original.rename(moved)
        original.symlink_to(moved.name)
        result = self.run_helper(self.fixture)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("symlink", result.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
