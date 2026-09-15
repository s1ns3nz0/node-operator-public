#!/usr/bin/env python3
# Check objective: Exercise fail-closed review check publication with mocked GitHub responses and changed PR state.
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SHA = "a" * 40
BASE = "b" * 40


class Publication(unittest.TestCase):
    def run_case(self, head=SHA, base=BASE, cache=True, evaluation="success"):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "bin").mkdir()
            fake = root / "bin/gh"
            fake.write_text('#!/bin/sh\ncase "$*" in\n*check-runs*) printf "%s\\n" "$*" >> "$CALLS";;\n*) printf "%s\\n" "$CURRENT_PR";;\nesac\n')
            fake.chmod(0o700)
            evidence = root / "evidence"
            (evidence / "cache").mkdir(parents=True)
            (evidence / "published").mkdir()
            if cache:
                (evidence / "cache/cache-context.json").write_text(json.dumps({"base_sha": BASE}))
                (evidence / "published/decision.json").write_text(json.dumps({
                    "summary": {"block": 0, "require_approval": 0}, "violations": []}))
            env = dict(os.environ, PATH=str(root / "bin") + os.pathsep + os.environ["PATH"],
                       EVIDENCE_ROOT=str(evidence), SUBJECT_SHA=SHA, PR_NUMBER="7", EVALUATION_RESULT=evaluation,
                       GITHUB_REPOSITORY="owner/repo", GH_TOKEN="fixture",
                       DETAILS_URL="https://github.com/owner/repo/actions/runs/42",
                       CALLS=str(root / "calls"), CURRENT_PR=json.dumps({
                           "state": "open", "head": {"sha": head}, "base": {"sha": base}}))
            result = subprocess.run(["bash", str(ROOT / "scripts/ci/workflows/publish-review-refresh.sh")],
                                    cwd=ROOT, env=env, capture_output=True, text=True)
            return result, (root / "calls").read_text() if (root / "calls").exists() else ""

    def test_current_approved(self):
        result, calls = self.run_case()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("conclusion=success", calls)

    def test_changed_base_rejected(self):
        result, calls = self.run_case(base="c" * 40)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("conclusion=failure", calls)

    def test_changed_head_not_published(self):
        result, calls = self.run_case(head="c" * 40)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(calls, "")

    def test_missing_cache_rejected(self):
        result, calls = self.run_case(cache=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("conclusion=failure", calls)

    def test_failed_evaluation_cannot_publish_success(self):
        result, calls = self.run_case(evaluation="failure")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("conclusion=failure", calls)


if __name__ == "__main__":
    unittest.main()
