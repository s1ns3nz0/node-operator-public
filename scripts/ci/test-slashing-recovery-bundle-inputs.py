#!/usr/bin/env python3
"""Check objective: keep slashing recovery source authority in release bundles."""
import pathlib
import subprocess
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]


class BundleBoundaryTest(unittest.TestCase):
    def test_exact_non_secret_source_inputs(self):
        text = (ROOT / "scripts/ci/build-release-bundle.sh").read_text()
        function = "path_is_in_release_boundary() {" + text.split(
            "path_is_in_release_boundary() {", 1
        )[1].split("\n}\n", 1)[0] + "\n}\n"
        cases = {
            ".ci/web3signer-hardened/source.lock.json": True,
            "scripts/ops/recover-missing-hoodi-slashing-history.py": True,
            "scripts/ops/lib/uc5-beacon-reader.py": True,
            "scripts/ops/prepare-hoodi-missing-slashing-history.sh": True,
            ".ci/web3signer-hardened/credentials.json": False,
            ".ci/web3signer-hardened/private-key.pem": False,
        }
        for path, allowed in cases.items():
            with self.subTest(path=path):
                result = subprocess.run(
                    ["bash", "-c", function + 'path_is_in_release_boundary "$1"', "test", path],
                    capture_output=True, timeout=10,
                )
                self.assertEqual(result.returncode, 0 if allowed else 1)
                if allowed:
                    self.assertTrue((ROOT / path).is_file())


if __name__ == "__main__":
    unittest.main()
