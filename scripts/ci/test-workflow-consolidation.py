#!/usr/bin/env python3
# Check objective: Preserve the workflow entrypoints, CI authority boundaries and non-publishing release verification mode.
import itertools
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / ".github/workflows"


def jobs(name):
    source = (WORKFLOWS / name).read_text().split("jobs:\n", 1)[1]
    pieces = re.split(r"^  ([\w-]+):\n", source, flags=re.M)
    return dict(zip(pieces[1::2], pieces[2::2]))


class Consolidation(unittest.TestCase):
    def test_entrypoints(self):
        self.assertEqual({p.name for p in WORKFLOWS.glob("*.yml")}, {
            "continuous-integration.yml", "fence-security.yml", "evidence-gate.yml", "review-signal.yml",
            "release-bundle.yml", "image-publish.yml", "private-ecr-mirror.yml", "operations-verification.yml",
            "evidence-archive.yml", "repository-posture.yml"})

    def test_ci_permissions_and_checks(self):
        source = (WORKFLOWS / "continuous-integration.yml").read_text()
        self.assertNotIn(": write", source)
        self.assertNotIn("packages:", source.split("jobs:\n")[0])
        parsed = jobs("continuous-integration.yml")
        self.assertEqual(set(parsed), {"fence-security", "quality-tests", "quality", "policy",
                                      "policy-foundation", "terraform", "security-scans", "scanners"})
        for job, title in {"quality": "quality", "scanners": "scanners", "policy": "Policy Rules",
                           "policy-foundation": "Evidence Contracts", "terraform": "Terraform Validation"}.items():
            self.assertIn("name: " + title + "\n", parsed[job])
        for job in parsed:
            self.assertEqual("packages: read" in parsed[job], job in {"terraform", "security-scans"})

    def test_release_modes(self):
        source = (WORKFLOWS / "release-bundle.yml").read_text()
        self.assertIn("default: verify-only", source)
        parsed = jobs("release-bundle.yml")
        self.assertNotIn("contents: write", parsed["reproducibility"])
        self.assertIn("id-token: write", parsed["reproducibility"])
        self.assertIn("attestations: write", parsed["reproducibility"])
        self.assertIn("artifact_digest: ${{ steps.sca-binding.outputs.artifact_digest }}", parsed["reproducibility"])
        expression = re.search(r"    if: >-\n((?:      .*\n)+)", parsed["build-and-publish"]).group(1)
        for event, mode, eligible, integrity in itertools.product(
                ["push", "workflow_dispatch"], ["verify-only", "publish"],
                ["success", "failure", "skipped", "cancelled"],
                ["success", "failure", "skipped", "cancelled"]):
            translated = expression.replace("github.event_name", repr(event)).replace("inputs.mode", repr(mode))
            translated = translated.replace("needs.eligibility.result", repr(eligible))
            translated = translated.replace("needs.reproducibility.result", repr(integrity))
            translated = " ".join(translated.split()).replace("&&", "and").replace("||", "or")
            actual = eval(translated, {"__builtins__": {}}, {})
            expected = (event == "push" or mode == "publish") and eligible == integrity == "success"
            self.assertEqual(actual, expected, (event, mode, eligible, integrity))

    def test_verify_only_runs_without_eligibility(self):
        job = jobs("release-bundle.yml")["reproducibility"]
        expression = re.search(r"    if: >-\n((?:      .*\n)+)", job).group(1)
        expression = expression.replace("${{", "").replace("}}", "")
        for event, mode, eligible, cancelled in itertools.product(
                ["push", "workflow_dispatch"], ["verify-only", "publish"],
                ["success", "failure", "skipped", "cancelled"], [False, True]):
            translated = expression.replace("!cancelled()", repr(not cancelled))
            translated = translated.replace("github.event_name", repr(event)).replace("inputs.mode", repr(mode))
            translated = translated.replace("needs.eligibility.result", repr(eligible))
            translated = " ".join(translated.split()).replace("&&", "and").replace("||", "or")
            actual = eval(translated, {"__builtins__": {}}, {})
            expected = not cancelled and (eligible == "success" or (event == "workflow_dispatch" and mode == "verify-only"))
            self.assertEqual(actual, expected)

    def test_operations_boundaries(self):
        parsed = jobs("operations-verification.yml")
        self.assertEqual(set(parsed), {"smoke", "verify", "sign-evidence"})
        self.assertIn("environment: private-runner-smoke", parsed["smoke"])
        self.assertIn("codebuild-node-operator-baseline-private-release-", parsed["smoke"])
        self.assertNotIn("id-token: write", parsed["smoke"])
        for job in parsed.values():
            self.assertIn("github.ref == 'refs/heads/main'", job)
        self.assertIn("inputs.target == 'private-runner'", parsed["smoke"])
        self.assertIn("inputs.target == 'vault-runtime'", parsed["verify"])
        self.assertIn("inputs.sign_evidence", parsed["sign-evidence"])
        self.assertIn("needs.verify.result == 'success'", parsed["sign-evidence"])


if __name__ == "__main__":
    unittest.main()
