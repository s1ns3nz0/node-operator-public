#!/usr/bin/env python3
"""Offline contract tests; no Kubernetes access or real credentials."""
import json
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
RENDERER = ROOT / "scripts/ops/render-signer-tls-probes.py"
KEY = "0x" + "a" * 96


class TLSProbeTests(unittest.TestCase):
    def render(self, validator_set="hoodi-example", key=KEY,
               fixture="signer-tls-fixture-ab123456"):
        return subprocess.run(
            [sys.executable, "-B", str(RENDERER), "--validator-set", validator_set,
             "--expected-public-key", key, "--fixture-name", fixture],
            capture_output=True, text=True, check=False,
        )

    def test_only_credentials_vary(self):
        result = self.render()
        self.assertEqual(result.returncode, 0, result.stderr)
        pods = json.loads(result.stdout)["items"]
        self.assertEqual(len(pods), 4)
        self.assertEqual([p["metadata"]["labels"]["node-operator.io/probe-role"]
                          for p in pods], ["pre", "badca", "badclient", "post"])
        for pod in pods:
            spec = pod["spec"]
            self.assertFalse(spec["automountServiceAccountToken"])
            self.assertEqual(spec["activeDeadlineSeconds"], 120)
            self.assertEqual(pod["metadata"]["labels"]["app.kubernetes.io/component"],
                             "validator-signing-fence")
            self.assertEqual(spec["containers"], pods[0]["spec"]["containers"])
            self.assertEqual(spec["securityContext"], pods[0]["spec"]["securityContext"])
        self.assertEqual(pods[0]["spec"], pods[3]["spec"])
        real = "validator-hoodi-example-client-tls"
        fake = "signer-tls-fixture-ab123456"
        for pod, identities in [(pods[1], [real, fake]), (pods[2], [fake, real])]:
            projected = pod["spec"]["volumes"][0]["projected"]
            self.assertEqual(projected["defaultMode"], 288)
            sources = [entry["secret"] for entry in projected["sources"]]
            self.assertEqual([s["name"] for s in sources], identities)
            self.assertEqual(sources[0]["items"], [
                {"key": "tls.crt", "path": "tls.crt"},
                {"key": "tls.key", "path": "tls.key"}])
            self.assertEqual(sources[1]["items"], [{"key": "ca.crt", "path": "ca.crt"}])

    def test_invalid_inputs_rejected_without_manifest(self):
        for invalid in [{"validator_set": "../other"}, {"key": "0x123"},
                        {"fixture": "validator-hoodi-example-client-tls"},
                        {"fixture": "signer-tls-fixture-../../other"}]:
            with self.subTest(invalid=invalid):
                result = self.render(**invalid)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, "")


if __name__ == "__main__":
    unittest.main()
