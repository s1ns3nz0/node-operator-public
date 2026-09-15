#!/usr/bin/env python3
"""Mock the audit ceremony's post-revoke proof boundary; no Vault is contacted."""
import json
import os
import signal
import shutil
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "scripts/ops/recover-and-configure-private-vault-validator-audit.sh"


class AuditRevokeProof(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name); self.ops = self.base / "ops"; self.bin = self.base / "bin"; self.trace = self.base / "trace"
        (self.ops / "lib").mkdir(parents=True); self.bin.mkdir()
        self.script = self.ops / SOURCE.name; shutil.copy(SOURCE, self.script); self.script.chmod(0o700)
        (self.ops / "lib/vault-recovery-auth.sh").write_text(
            "vault_recovery_auth_preflight(){ :; }\nvault_recovery_decode_generated_root(){ printf root; }\n"
        )
        verify = self.ops / "verify-vault-validator-audit.sh"; verify.write_text("#!/usr/bin/env bash\nexit 0\n"); verify.chmod(0o700)
        self._command("kubectl", "#!/usr/bin/env bash\ncase \" $* \" in *statefulset*) printf '{\"spec\":{\"template\":{\"spec\":{\"containers\":[{\"name\":\"vault-validator-audit-relay\",\"securityContext\":{\"readOnlyRootFilesystem\":true}}]}}}}' ;; *' get pod '*) printf '{\"status\":{\"containerStatuses\":[{\"name\":\"vault-validator-audit-relay\",\"ready\":true}]}}' ;; *) exit 0;; esac\n")
        self._command("openssl", "#!/usr/bin/env bash\nprintf '%064d' 0\n")
        vault = '''#!/usr/bin/env bash
printf '%s\\n' "$*" >> "$TRACE"
case "$1:$2" in
operator:generate-root)
  case " $* " in *' -status '*) printf '{"started":false}' ;; *' -init '*) [ "${WAIT_INIT:-0}" != 1 ] || sleep 30; printf '{"nonce":"n","otp":"o","required":1}' ;; *' -nonce=n '*) cat >/dev/null; printf '{"complete":true,"encoded_token":"x"}' ;; *) exit 64;; esac ;;
audit:list) printf '{}' ;;
audit:enable) : ;;
write:-format=json) printf '{"data":{"hash":"hmac-sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"request_id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"}' ;;
token:revoke) : ;;
token:lookup)
  # Match the real CLI: lookup defaults to self and rejects the revoke-only flag.
  [ "$*" = 'token lookup -format=json' ] || { printf 'flag provided but not defined or unexpected arguments' >&2; exit 1; }
  case "${LOOKUP_MODE:-invalid}" in invalid) printf 'Error making API request.\\n\\nCode: 403. Errors:\\n\\n* invalid token\\n' >&2 ;; network) printf 'connection refused' >&2 ;; active) printf '{"data":{"id":"synthetic"}}'; exit 0 ;; denied) printf 'Code: 403. Errors: permission denied' >&2 ;; *) exit 64;; esac; exit 2 ;;
*) exit 64;; esac
'''
        self._command("vault", vault)

    def tearDown(self): self.tmp.cleanup()

    def _command(self, name, body):
        path = self.bin / name; path.write_text(body); path.chmod(0o700)

    def invoke(self, mode, **extra):
        env = {**os.environ, "PATH": f"{self.bin}:{os.environ['PATH']}", "PRIVATE_VAULT_SESSION": "1", "LOOKUP_MODE": mode, "TRACE": str(self.trace)}
        for key in ("AUDIT_RECEIPT", "AUDIT_ACCOUNT", "AUDIT_REGION", "AUDIT_DEPLOYMENT", "AUDIT_RELEASE_REVISION", "AUDIT_OPERATION_ID"):
            env.pop(key, None)
        env.update({key: str(value) for key, value in extra.items()})
        return subprocess.run(["bash", str(self.script)], input="share\n", text=True, capture_output=True, env=env, timeout=10)

    def receipt_args(self, receipt, **override):
        result = {"AUDIT_RECEIPT": receipt, "AUDIT_ACCOUNT": "123456789012", "AUDIT_REGION": "ap-northeast-2", "AUDIT_DEPLOYMENT": "node-op-123", "AUDIT_RELEASE_REVISION": "a" * 40, "AUDIT_OPERATION_ID": "b" * 32}
        result.update(override)
        return result

    def root_started(self):
        return "operator generate-root" in self.trace.read_text() if self.trace.exists() else False

    def test_only_http_403_invalid_token_confirms_revocation(self):
        result = self.invoke("invalid")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Preflight passed", result.stderr)
        self.assertIn("revocation was verified", result.stdout)

    def test_network_lookup_failure_never_confirms_revocation(self):
        audit = self.base / "audit"; audit.mkdir(mode=0o700)
        receipt = audit / "audit-challenge.json"
        result = self.invoke("network", **self.receipt_args(receipt))
        self.assertEqual(result.returncode, 75, result.stderr)
        self.assertIn("not explicitly confirmed as HTTP 403 invalid token", result.stderr)
        self.assertNotIn("revocation was verified", result.stdout)
        self.assertFalse(receipt.exists())

    def test_active_token_or_generic_denial_never_confirms_revocation(self):
        for mode in ("active", "denied"):
            with self.subTest(mode=mode):
                receipt = self.base / "audit-challenge.json"
                result = self.invoke(mode, **self.receipt_args(receipt))
                self.assertEqual(result.returncode, 75, result.stderr)
                self.assertFalse(receipt.exists())
                self.assertNotIn("revocation was verified", result.stdout)

    def test_receipt_mode_binds_exact_operation_after_revocation(self):
        audit = self.base / "audit"; audit.mkdir(mode=0o700)
        receipt = audit / "audit-challenge.json"
        result = self.invoke("invalid", **self.receipt_args(receipt))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(receipt.stat().st_mode & 0o777, 0o600)
        record = json.loads(receipt.read_text())
        self.assertEqual(record["operation_id"], "b" * 32)
        self.assertEqual(record["aws_account_id"], "123456789012")
        self.assertEqual(record["release_revision"], "a" * 40)

    def test_invalid_binding_or_existing_receipt_blocks_before_root_generation(self):
        audit = self.base / "audit"; audit.mkdir(mode=0o700)
        receipt = audit / "audit-challenge.json"
        shared = self.base / "shared"; shared.mkdir(mode=0o755)
        for override in ({"AUDIT_ACCOUNT": "bad"}, {"AUDIT_RECEIPT": "relative-receipt.json"}, {"AUDIT_RECEIPT": shared / "audit-challenge.json"}, {}):
            with self.subTest(override=override):
                self.trace.unlink(missing_ok=True)
                if not override: receipt.write_text("occupied")
                result = self.invoke("invalid", **self.receipt_args(receipt, **override))
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(self.root_started())
                receipt.unlink(missing_ok=True)

    def test_term_exits_and_never_publishes_a_receipt(self):
        audit = self.base / "audit"; audit.mkdir(mode=0o700)
        receipt = audit / "audit-challenge.json"
        env = {**os.environ, "PATH": f"{self.bin}:{os.environ['PATH']}", "PRIVATE_VAULT_SESSION": "1", "LOOKUP_MODE": "invalid", "TRACE": str(self.trace), "WAIT_INIT": "1"}
        for key in ("AUDIT_RECEIPT", "AUDIT_ACCOUNT", "AUDIT_REGION", "AUDIT_DEPLOYMENT", "AUDIT_RELEASE_REVISION", "AUDIT_OPERATION_ID"):
            env.pop(key, None)
        env.update({key: str(value) for key, value in self.receipt_args(receipt).items()})
        process = subprocess.Popen(["bash", str(self.script)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env, start_new_session=True)
        process.stdin.write("share\n"); process.stdin.flush()
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            if self.trace.exists() and "operator generate-root -init" in self.trace.read_text():
                break
            time.sleep(0.01)
        self.assertTrue(self.trace.exists() and "operator generate-root -init" in self.trace.read_text())
        os.killpg(process.pid, signal.SIGTERM)
        stdout, stderr = process.communicate(timeout=5)
        self.assertEqual(process.returncode, 143, stderr)
        self.assertFalse(receipt.exists())
        self.assertNotIn("revocation was verified", stdout)


if __name__ == "__main__":
    unittest.main()
