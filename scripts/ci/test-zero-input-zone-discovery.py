#!/usr/bin/env python3
# Check objective: Validate zone discovery without AWS or Terraform access.
"""Check zone discovery with the actual shell, without AWS or Terraform access."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class ZoneDiscovery(unittest.TestCase):
    def exercise(self, response, rc=0):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            binary = base / "aws"
            binary.write_text('#!/bin/sh\n[ "$1:$2" = ec2:describe-availability-zones ] || exit 98\nprintf "%s\\n" "$ZONE_RESPONSE"\nexit "$ZONE_RC"\n')
            binary.chmod(0o700)
            output = base / "inputs"
            result = subprocess.run([
                "/bin/bash", str(ROOT / "scripts/release/prepare-zero-resource-inputs.sh"),
                "--aws-account-id", "123456789012", "--aws-region", "ap-northeast-2",
                "--backend-principal-arn", "arn:aws:iam::123456789012:role/test",
                "--github-repository", "example/operator", "--github-owner-id", "101", "--github-repository-id", "102",
                "--gitops-client-github-repository", "example/gitops", "--gitops-client-github-owner-id", "103", "--gitops-client-github-repository-id", "104",
                "--output-dir", str(output),
            ], env={**os.environ, "PATH": str(base) + os.pathsep + os.environ["PATH"],
                    "ZONE_RESPONSE": response, "ZONE_RC": str(rc)},
                capture_output=True, text=True, timeout=15)
            payload = json.loads((output / "foundation-network.tfvars.json").read_text()) if output.exists() else None
            return result, payload

    def test_default_discovery_is_sorted_unique_and_system_bash_compatible(self):
        result, payload = self.exercise("ap-northeast-2c\tap-northeast-2a\tap-northeast-2a\tap-northeast-2b")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(payload["availability_zones"], ["ap-northeast-2a", "ap-northeast-2b"])

    def test_failed_request_cannot_turn_partial_stdout_into_inputs(self):
        result, payload = self.exercise("ap-northeast-2a\tap-northeast-2b", 42)
        self.assertEqual(result.returncode, 69)
        self.assertIsNone(payload)

    def test_missing_or_wrong_region_zones_fail_before_output(self):
        for response in ("", "ap-northeast-2a", "ap-northeast-1a\tap-northeast-1c"):
            result, payload = self.exercise(response)
            self.assertNotEqual(result.returncode, 0)
            self.assertIsNone(payload)


if __name__ == "__main__":
    unittest.main()
