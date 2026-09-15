#!/usr/bin/env python3
# Check objective: Validate custody validator key verification.
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/ops/verify-custody-validator-key.py"
KEY = "0x" + "ab" * 48
def keyfile(pubkey=KEY[2:]): return {"version":4,"pubkey":pubkey,"description":"","path":"m/12381/3600/0/0/0","uuid":"00000000-0000-4000-8000-000000000000","crypto":{"kdf":{"function":"scrypt","params":{"dklen":32,"n":262144,"r":8,"p":1,"salt":"a"*64},"message":""},"checksum":{"function":"sha256","params":{},"message":"b"*64},"cipher":{"function":"aes-128-ctr","params":{"iv":"c"*32},"message":"d"*64}}}


class CustodyKeyIdentity(unittest.TestCase):
    def invoke(self, directory: Path, expected: str = KEY):
        return subprocess.run(["python3", str(SCRIPT), "--keystore-dir", str(directory), "--expected-public-key", expected], text=True, capture_output=True)

    def test_valid_metadata_returns_only_identity(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp) / "keys"; directory.mkdir()
            (directory / "keystore-safe.json").write_text(json.dumps(keyfile(KEY[2:].upper())))
            result = self.invoke(directory)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout), {"schema_version": 1, "public_key": KEY, "keystore_file": "keystore-safe.json"})
            self.assertNotIn("crypto", result.stdout + result.stderr)

    def test_unsafe_wrong_or_invalid_metadata_rejects_without_echoing_contents(self):
        for kind in ("missing", "two", "symlink", "version", "pubkey", "malformed"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temp:
                directory = Path(temp) / "keys"; directory.mkdir()
                payload = "secret-fixture-value"
                if kind == "two":
                    for name in ("keystore-one.json", "keystore-two.json"): (directory / name).write_text(json.dumps(keyfile()))
                elif kind == "symlink":
                    target = Path(temp) / "target.json"; target.write_text(json.dumps(keyfile())); (directory / "keystore-link.json").symlink_to(target)
                elif kind != "missing":
                    value = keyfile()
                    if kind == "version": value["version"] = 3
                    if kind == "pubkey": value["pubkey"] = "cd" * 48
                    (directory / "keystore-bad.json").write_text(payload if kind == "malformed" else json.dumps(value))
                result = self.invoke(directory)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn(payload, result.stdout + result.stderr)


if __name__ == "__main__": unittest.main()
