#!/usr/bin/env python3
"""Contract tests for the pinned offline EIP-2335 secret verifier."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/ops/verify-custody-keystore-secret.py"
UPSTREAM_VALUE = os.environ.get("CUSTODY_VERIFIER_UPSTREAM_ROOT")
PYTHON_VALUE = os.environ.get("CUSTODY_VERIFIER_PYTHON")
PASSWORD = "𝔱𝔢𝔰𝔱𝔭𝔞𝔰𝔰𝔴𝔬𝔯𝔡🔑"
PUBLIC_KEY = "0x9612d7a727c9d0a22e185a1c768478dfe919cada9266988cb32359c11f2b7b27f4ae4040902382ae2910c15e2b420d07"


class SecretVerifierTests(unittest.TestCase):
    def setUp(self):
        if not UPSTREAM_VALUE or not PYTHON_VALUE:
            self.fail("CUSTODY_VERIFIER_UPSTREAM_ROOT and CUSTODY_VERIFIER_PYTHON are required")
        self.upstream = Path(UPSTREAM_VALUE)
        self.python = Path(PYTHON_VALUE)
        if not self.upstream.is_dir() or not self.python.is_file():
            self.fail("locked upstream or hash-enforced test environment is unavailable")
        self.tmp = tempfile.TemporaryDirectory()
        self.work = Path(self.tmp.name)
        self.keystore = self.work / "keystore.json"
        self.password = self.work / "password"
        self.password.write_text(PASSWORD, encoding="utf-8")
        self.password.chmod(0o600)

    def tearDown(self):
        self.tmp.cleanup()

    def stage_vector(self, name: str):
        shutil.copy2(self.upstream / "tests/test_key_handling/keystore_test_vectors" / name, self.keystore)
        self.keystore.chmod(0o600)

    def invoke(self, *extra, pass_fds=()):
        return subprocess.run(
            [str(self.python), str(SCRIPT), "--upstream-root", str(self.upstream), "--expected-public-key", PUBLIC_KEY, *extra],
            capture_output=True, text=True, pass_fds=pass_fds, check=False, timeout=20,
        )

    def test_official_pbkdf2_and_scrypt_vectors(self):
        for vector in ("test0.json", "test1.json"):
            with self.subTest(vector=vector):
                self.stage_vector(vector)
                result = self.invoke("--keystore-file", str(self.keystore), "--password-file", str(self.password))
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, PUBLIC_KEY + "\n")
                self.assertEqual(result.stderr, "")

    def test_private_file_and_fd_rules_fail_closed_without_secret_echo(self):
        self.stage_vector("test0.json")
        self.password.chmod(0o644)
        result = self.invoke("--keystore-file", str(self.keystore), "--password-file", str(self.password))
        self.assertEqual(result.returncode, 65)
        self.assertEqual(result.stdout, "")
        self.assertEqual(result.stderr, "custody keystore verification failed\n")
        self.assertNotIn(PASSWORD, result.stderr)
        self.password.chmod(0o600)
        key_fd = os.open(self.keystore, os.O_RDONLY)
        password_fd = os.open(self.password, os.O_RDONLY)
        try:
            result = self.invoke("--keystore-fd", str(key_fd), "--password-fd", str(password_fd), pass_fds=(key_fd, password_fd))
        finally:
            os.close(key_fd)
            os.close(password_fd)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, PUBLIC_KEY + "\n")

    def test_wrong_key_password_and_resource_kdf_fail_generically(self):
        self.stage_vector("test0.json")
        result = self.invoke("--keystore-file", str(self.keystore), "--password-file", str(self.password), "--expected-public-key", "0x" + "00" * 48)
        self.assertEqual(result.returncode, 65)
        self.assertEqual(result.stdout, "")
        self.assertEqual(result.stderr, "custody keystore verification failed\n")
        self.password.write_text("not-the-password", encoding="utf-8")
        self.password.chmod(0o600)
        result = self.invoke("--keystore-file", str(self.keystore), "--password-file", str(self.password))
        self.assertEqual(result.returncode, 65)
        self.assertEqual(result.stderr, "custody keystore verification failed\n")

    def test_metadata_mismatch_and_unselectable_tampered_lock_fail_before_output(self):
        self.stage_vector("test0.json")
        document = json.loads(self.keystore.read_text(encoding="utf-8"))
        document["pubkey"] = "00" * 48
        self.keystore.write_text(json.dumps(document), encoding="utf-8")
        self.keystore.chmod(0o600)
        result = self.invoke("--keystore-file", str(self.keystore), "--password-file", str(self.password))
        self.assertEqual(result.returncode, 65)
        self.assertEqual(result.stdout, "")
        self.assertEqual(result.stderr, "custody keystore verification failed\n")

    def test_ciphertext_duplicate_symlink_and_oversize_inputs_fail_generically(self):
        self.stage_vector("test0.json")
        document = json.loads(self.keystore.read_text(encoding="utf-8"))
        document["crypto"]["cipher"]["message"] = "00" * 32
        self.keystore.write_text(json.dumps(document), encoding="utf-8")
        self.keystore.chmod(0o600)
        result = self.invoke("--keystore-file", str(self.keystore), "--password-file", str(self.password))
        self.assertEqual(result.returncode, 65)
        self.assertEqual(result.stdout, "")
        self.assertEqual(result.stderr, "custody keystore verification failed\n")
        self.stage_vector("test0.json")
        raw = self.keystore.read_text(encoding="utf-8")
        self.keystore.write_text('{"pubkey":"' + "00" * 48 + '",' + raw[1:], encoding="utf-8")
        self.keystore.chmod(0o600)
        result = self.invoke("--keystore-file", str(self.keystore), "--password-file", str(self.password))
        self.assertEqual(result.returncode, 65)
        self.assertEqual(result.stderr, "custody keystore verification failed\n")

    def test_source_code_substitution_and_cache_candidates_reject_before_decrypt(self):
        self.stage_vector("test0.json")
        altered = self.work / "altered-upstream"
        clone = subprocess.run(
            ["git", "clone", "--no-local", str(self.upstream), str(altered)],
            capture_output=True, text=True, check=False, timeout=20,
        )
        self.assertEqual(clone.returncode, 0, clone.stderr)
        source = altered / "ethstaker_deposit/key_handling/keystore.py"
        source.write_text(source.read_text(encoding="utf-8") + "\n# substitution\n", encoding="utf-8")
        result = self.invoke("--upstream-root", str(altered), "--keystore-file", str(self.keystore), "--password-file", str(self.password))
        self.assertEqual(result.returncode, 65)
        self.assertEqual(result.stdout, "")
        self.assertEqual(result.stderr, "custody keystore verification failed\n")
        source.write_text(source.read_text(encoding="utf-8").removesuffix("\n# substitution\n"), encoding="utf-8")
        shadow = altered / "ethstaker_deposit.py"
        shadow.write_text("raise RuntimeError('must not import')\n", encoding="utf-8")
        result = self.invoke("--upstream-root", str(altered), "--keystore-file", str(self.keystore), "--password-file", str(self.password))
        self.assertEqual(result.returncode, 65)
        self.assertEqual(result.stdout, "")
        self.assertEqual(result.stderr, "custody keystore verification failed\n")
        shadow.unlink()
        (altered / "ethstaker_deposit/__pycache__").mkdir()
        result = self.invoke("--upstream-root", str(altered), "--keystore-file", str(self.keystore), "--password-file", str(self.password))
        self.assertEqual(result.returncode, 65)
        self.assertEqual(result.stdout, "")
        self.assertEqual(result.stderr, "custody keystore verification failed\n")
        target = self.work / "target.json"
        self.stage_vector("test0.json")
        self.keystore.replace(target)
        target.chmod(0o600)
        self.keystore.symlink_to(target)
        result = self.invoke("--keystore-file", str(self.keystore), "--password-file", str(self.password))
        self.assertEqual(result.returncode, 65)
        self.assertEqual(result.stderr, "custody keystore verification failed\n")
        self.keystore.unlink()
        self.keystore.write_bytes(b"{" + b" " * (1024 * 1024 + 1))
        self.keystore.chmod(0o600)
        result = self.invoke("--keystore-file", str(self.keystore), "--password-file", str(self.password))
        self.assertEqual(result.returncode, 65)
        self.assertEqual(result.stderr, "custody keystore verification failed\n")
        self.stage_vector("test0.json")
        result = self.invoke("--keystore-file", str(self.keystore), "--password-file", str(self.password), "--source-lock", str(self.work / "not-accepted.json"))
        self.assertEqual(result.returncode, 65)
        self.assertEqual(result.stdout, "")
        self.assertEqual(result.stderr, "custody keystore verification failed\n")
        self.password.write_text(PASSWORD, encoding="utf-8")
        document = json.loads(self.keystore.read_text(encoding="utf-8"))
        document["crypto"]["kdf"]["params"]["c"] = 2_000_001
        self.keystore.write_text(json.dumps(document), encoding="utf-8")
        self.keystore.chmod(0o600)
        result = self.invoke("--keystore-file", str(self.keystore), "--password-file", str(self.password))
        self.assertEqual(result.returncode, 65)
        self.assertEqual(result.stderr, "custody keystore verification failed\n")


if __name__ == "__main__":
    unittest.main()
