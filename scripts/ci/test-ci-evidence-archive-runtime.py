#!/usr/bin/env python3
# Check objective: exercise read-back verification with mocked archival dependencies.
"""Runtime contract for archive-ci-evidence.sh; no cloud credentials are used."""
import json
import os
import pathlib
import shutil
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/ci/archive-ci-evidence.sh"
SHA = "a" * 40


class ArchiveRuntimeTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = pathlib.Path(self.temp.name)
        self.repo = self.base / "repo"
        (self.repo / "scripts/ci").mkdir(parents=True)
        shutil.copy2(SCRIPT, self.repo / "scripts/ci/archive-ci-evidence.sh")
        self.store = self.base / "s3"
        self.store.mkdir()
        self._write_mocks()

    def tearDown(self):
        self.temp.cleanup()

    def _write_mocks(self):
        installer = self.repo / "scripts/ci/install-validator-signing-fence-release-tools.sh"
        installer.write_text(
            "#!/bin/sh\n"
            "set -eu\n"
            "mkdir -p \"$1\"\n"
            "cat > \"$1/cosign\" <<'EOF'\n"
            "#!/bin/sh\n"
            "set -eu\n"
            "if [ \"$1\" = sign-blob ]; then\n"
            "  while [ \"$1\" != --bundle ]; do shift; done; shift\n"
            "  printf signed > \"$1\"\n"
            "  exit 0\n"
            "fi\n"
            "if [ \"$1\" = verify-blob ]; then\n"
            "  while [ \"$1\" != --bundle ]; do shift; done; shift\n"
            "  [ \"$(cat \"$1\")\" = signed ] || exit 9\n"
            "  exit 0\n"
            "fi\n"
            "exit 64\n"
            "EOF\n"
            "chmod +x \"$1/cosign\"\n"
        )
        installer.chmod(0o755)
        bindir = self.base / "bin"
        bindir.mkdir()
        aws = bindir / "aws"
        aws.write_text(
            "#!/bin/sh\n"
            "set -eu\n"
            "[ \"$1\" = s3 ] && [ \"$2\" = cp ] || exit 64\n"
            "source=$3; destination=$4\n"
            "base=${source##*/}\n"
            "if [ \"${source#s3://}\" != \"$source\" ]; then\n"
            "  [ \"${MOCK_MISSING:-}\" != \"$base\" ] || exit 44\n"
            "  object=${source#s3://*/}\n"
            "  cp \"$MOCK_S3/$object\" \"$destination\"\n"
            "  if [ \"${MOCK_CORRUPT:-}\" = \"$base\" ]; then printf corrupt >> \"$destination\"; fi\n"
            "else\n"
            "  object=${destination#s3://*/}\n"
            "  mkdir -p \"$MOCK_S3/$(dirname \"$object\")\"\n"
            "  cp \"$source\" \"$MOCK_S3/$object\"\n"
            "fi\n"
        )
        aws.chmod(0o755)
        self.bindir = bindir

    def _evidence(self):
        evidence = self.base / "evidence"
        if evidence.exists():
            return evidence
        evidence.mkdir()
        (evidence / "evidence.json").write_text(json.dumps({"subject": {"commit_sha": SHA}}))
        (evidence / "decision.json").write_text(json.dumps({"summary": {"block": 0, "require_approval": 0}, "violations": []}))
        (evidence / "cache-context.json").write_text('{"cache":"redacted"}')
        (evidence / "baseline-summary.json").write_text('{"baseline":"redacted"}')
        return evidence

    def _run(self, output, **extra):
        env = os.environ | {
            "CI_EVIDENCE_ARCHIVE_BUCKET": "private-evidence",
            "MOCK_S3": str(self.store),
            "PATH": f"{self.bindir}:{os.environ['PATH']}",
        } | extra
        return subprocess.run(
            ["bash", str(self.repo / "scripts/ci/archive-ci-evidence.sh"), str(self._evidence()), SHA, "123", str(output)],
            cwd=self.repo,
            env=env,
            text=True,
            capture_output=True,
        )

    def test_valid_archive_is_read_back_and_verified(self):
        result = self._run(self.base / "out")
        self.assertEqual(result.returncode, 0, result.stderr)
        prefix = self.store / f"ci/{SHA}/123"
        self.assertEqual(
            sorted(item.name for item in prefix.iterdir()),
            ["baseline-summary.json", "cache-context.json", "decision.json", "evidence.json", "manifest.json", "manifest.sigstore.json"],
        )

    def test_changed_retrieved_member_is_rejected(self):
        result = self._run(self.base / "out", MOCK_CORRUPT="evidence.json")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("hash mismatch", result.stderr)

    def test_missing_retrieved_member_is_rejected(self):
        result = self._run(self.base / "out", MOCK_MISSING="decision.json")
        self.assertNotEqual(result.returncode, 0)

    def test_invalid_retrieved_signature_is_rejected(self):
        result = self._run(self.base / "out", MOCK_CORRUPT="manifest.sigstore.json")
        self.assertNotEqual(result.returncode, 0)

    def test_changed_retrieved_manifest_is_rejected(self):
        result = self._run(self.base / "out", MOCK_CORRUPT="manifest.json")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("retrieved manifest differs", result.stderr)

    def test_boolean_decision_is_rejected(self):
        evidence = self._evidence()
        (evidence / "decision.json").write_text(json.dumps({"summary": {"block": False, "require_approval": 0}, "violations": []}))
        result = self._run(self.base / "out")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(list(self.store.iterdir()), [])

    def test_source_symlink_is_rejected(self):
        evidence = self._evidence()
        original = evidence / "decision.json"
        safe_target = self.base / "decision-target.json"
        safe_target.write_text(original.read_text())
        original.unlink()
        original.symlink_to(safe_target)
        result = self._run(self.base / "out")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(any(self.store.iterdir()))

    def test_existing_output_is_preserved_on_rejection(self):
        output = self.base / "existing-output"
        output.mkdir()
        sentinel = output / "keep"
        sentinel.write_text("untouched")
        result = self._run(output)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(sentinel.read_text(), "untouched")
        self.assertEqual(list(self.store.iterdir()), [])

    def test_symlink_output_is_rejected_without_touching_target(self):
        target = self.base / "output-target"
        target.mkdir()
        sentinel = target / "keep"
        sentinel.write_text("untouched")
        output = self.base / "output-link"
        output.symlink_to(target, target_is_directory=True)
        result = self._run(output)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(sentinel.read_text(), "untouched")
        self.assertEqual(list(self.store.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
