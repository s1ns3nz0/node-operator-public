#!/usr/bin/env python3
# Check objective: Validate mocked validator-custody recovery and onboarding orchestration.
"""Mocked Vault/runtime orchestration checks for the validator-custody ceremony.

Cryptographic and TLS semantics are exercised by their dedicated vector and
real-OpenSSL suites; this fixture proves no live deployment behavior.
"""

import hashlib
import json
import os
import select
import shutil
import signal
import subprocess
import tempfile
import time
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "scripts/ops/recover-and-onboard-hoodi-validator-keystore.sh"


class OnboardingLifecycleTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.ops = self.base / "ops"
        self.bin = self.base / "bin"
        (self.ops / "lib").mkdir(parents=True)
        self.bin.mkdir()
        self.script = self.ops / SOURCE.name
        self.script.write_bytes(SOURCE.read_bytes())
        self.script.chmod(0o700)
        for name in ("verify-custody-keystore-secret.py",):
            staged = self.ops / name
            staged.write_bytes((ROOT / "scripts/ops" / name).read_bytes())
            staged.chmod(0o700)
        transport = self.ops / "verify-hoodi-vault-v2-transport-records.sh"
        transport.write_text(
            "#!/usr/bin/env bash\nset -eu\n"
            "while [ \"$#\" -gt 0 ]; do case \"$1\" in --output-dir) output=$2; shift 2 ;; *) shift ;; esac; done\n"
            "mkdir \"$output\"; printf ca > \"$output/signer-ca.crt\"; printf known > \"$output/known-clients.txt\"\n"
        )
        transport.chmod(0o700)
        self.verifier_python = self.bin / "verifier-python"
        self.verifier_python.write_text("#!/usr/bin/env bash\nset -eu\nprintf '0x%s\\n' \"$(printf 'a%.0s' {1..96})\"\n")
        self.verifier_python.chmod(0o700)
        self.verifier_upstream = self.base / "verified-upstream"; self.verifier_upstream.mkdir()
        (self.ops / "lib/vault-recovery-auth.sh").write_text(
            "vault_recovery_auth_preflight() { :; }\n"
            "vault_recovery_decode_generated_root() { printf '%s' root-sentinel; }\n"
        )
        helper = self.ops / "configure-hoodi-vault-kubernetes-auth.sh"
        helper.write_text("#!/usr/bin/env bash\nset -eu\nprintf 'auth-helper\\n' >> \"$TRACE\"\n")
        helper.chmod(0o700)
        wrapper = self.ops / "with-private-vault.sh"
        wrapper.write_text("#!/usr/bin/env bash\nset -eu\nprintf 'wrapper %s\\n' \"$*\" >> \"$TRACE\"\n")
        wrapper.chmod(0o700)
        self.keys = self.base / "keys"
        self.keys.mkdir()
        (self.keys / "keystore-test.json").write_text("{}")
        self.trace = self.base / "trace"
        self.record_state = self.base / "record-state"; self.record_state.mkdir()
        self.ready = self.base / "ready"
        self.scratch_root = self.base / "owned-scratch"
        self.scratch_root.mkdir()
        self.scratch_record = self.base / "scratch-path"
        self._write_vault()
        self._write_openssl()
        self._write_mktemp()
        self._write_cleanup_commands()
        self._write_bootstrap("bootstrap-node-operator-vault-v2.sh")
        self._write_bootstrap("bootstrap-hoodi-validator-runtime-vault.sh")

    def tearDown(self):
        self.temp.cleanup()

    def _write_vault(self):
        vault = self.bin / "vault"
        vault.write_text(
            "#!/usr/bin/env bash\n"
            "set -eu\n"
            "printf '%s\\n' \"$*\" >> \"$TRACE\"\n"
            "case \"$1:$2\" in\n"
            "operator:generate-root)\n"
            "  case \" $* \" in\n"
            "    *' -status '*) if [ \"${ROOT_STARTED:-0}\" = 1 ] || { [ \"${INIT_PENDING:-0}\" = 1 ] && [ -e \"$READY\" ]; }; then printf '%s\\n' '{\"started\":true,\"progress\":1,\"required\":3}'; else printf '%s\\n' '{\"started\":false}'; fi ;;\n"
            "    *' -init '*) : > \"$READY\"; [ \"${FAIL_INIT:-0}\" != 1 ] || exit 9; printf '%s\\n' '{\"nonce\":\"n\",\"otp\":\"o\",\"required\":1}' ;;\n"
            "    *' -nonce=n '*) cat >/dev/null; printf '%s\\n' '{\"complete\":true,\"encoded_token\":\"encoded\"}' ;;\n"
            "    *' -cancel '*) printf 'cancel\\n' >> \"$TRACE\" ;;\n"
            "    *) exit 64 ;;\n"
            "  esac ;;\n"
            "token:create) printf '%s\\n' child-sentinel ;;\n"
            "token:revoke)\n"
            "  if [ \"${VAULT_TOKEN:-}\" = root-sentinel ] && [ \"${3:-}\" = child-sentinel ]; then\n"
            "    [ \"${FAIL_CHILD_REVOKE:-0}\" != 1 ] || exit 9\n"
            "  elif [ \"${VAULT_TOKEN:-}\" = root-sentinel ] && [ \"${3:-}\" = -self ]; then\n"
            "    [ \"${FAIL_ROOT_REVOKE:-0}\" != 1 ] || exit 9\n"
            "  else exit 64; fi ;;\n"
            "kv:get) name=${!#}; name=${name##*/}; if [ -f \"$RECORD_STATE/$name.json\" ]; then printf '{\\\"data\\\":{\\\"data\\\":'; cat \"$RECORD_STATE/$name.json\"; printf '}}\\n'; elif [ \"${READ_ERROR_RECORD:-}\" = \"$name\" ]; then printf 'permission denied\\n' >&2; exit 2; else missing_path=\"${MISSING_RESPONSE_PATH:-node-operator-runtime/data/validators/hoodi/hoodi-example/runtime/$name}\"; printf 'No value found at %s\\n' \"$missing_path\" >&2; exit \"${MISSING_STATUS:-2}\"; fi ;;\n"
            "kv:metadata) exit 2 ;;\n"
            "kv:put) name=${4##*/}; source=${5#@}; if [ -f \"$RECORD_STATE/$name.json\" ]; then exit 9; fi; cp \"$source\" \"$RECORD_STATE/$name.json\"; [ \"${CAS_RACE_RECORD:-}\" != \"$name\" ] || exit 9 ;;\n"
            "write:-format=json) printf '%s\\n' '{\"data\":{\"private_key\":\"key\",\"certificate\":\"cert\",\"ca_chain\":[\"ca\"]}}' ;;\n"
            "*) exit 64 ;;\n"
            "esac\n"
        )
        vault.chmod(0o700)

    def _write_openssl(self):
        openssl = self.bin / "openssl"
        openssl.write_text(
            "#!/usr/bin/env bash\nset -eu\n"
            "case \"$1\" in\n"
            "rand) printf tls-password ;;\n"
            "pkcs12) while [ \"$#\" -gt 0 ]; do [ \"$1\" != -out ] || { printf p12 > \"$2\"; exit 0; }; shift; done; exit 64 ;;\n"
            "x509) printf 'sha256 Fingerprint=AA:BB\\n' ;;\n"
            "dgst) if command -v sha256sum >/dev/null; then sha256sum \"$4\"; else shasum -a 256 \"$4\"; fi ;;\n"
            "*) exit 64 ;;\n"
            "esac\n"
        )
        openssl.chmod(0o700)

    def _write_mktemp(self):
        mktemp = self.bin / "mktemp"
        mktemp.write_text(
            "#!/usr/bin/env bash\nset -eu\n"
            "if [ \"${1:-}\" = -d ]; then\n"
            "  : \"${TEST_SCRATCH_ROOT:?}\" \"${SCRATCH_RECORD:?}\"\n"
            "  scratch=\"$TEST_SCRATCH_ROOT/scratch-$$\"\n"
            "  mkdir \"$scratch\"\n"
            "  printf '%s\\n' \"$scratch\" > \"$SCRATCH_RECORD\"\n"
            "  printf '%s\\n' \"$scratch\"\n"
            "else\n"
            "  output=${1//XXXXXX/$$}; : > \"$output\"; printf '%s\\n' \"$output\"\n"
            "fi\n"
        )
        mktemp.chmod(0o700)

    def _write_cleanup_commands(self):
        for name, variable in (("unlink", "FAIL_UNLINK"), ("rmdir", "FAIL_RMDIR")):
            command = self.bin / name
            command.write_text(
                "#!/usr/bin/env bash\nset -eu\n"
                f"[ \"${{{variable}:-0}}\" != 1 ] || exit 9\n"
                f"exec {shutil.which(name)} \"$@\"\n"
            )
            command.chmod(0o700)

    def _write_bootstrap(self, name):
        program = self.ops / name
        program.write_text("#!/usr/bin/env bash\nset -eu\nprintf 'bootstrap %s\\n' \"${0##*/}\" >> \"$TRACE\"\n")
        program.chmod(0o700)

    def invoke(self, stdin="", refresh=True, result_output=None, operation_id="1" * 32, **extra):
        environment = os.environ.copy()
        environment.update({
            "PATH": f"{self.bin}:{environment['PATH']}",
            "PRIVATE_VAULT_SESSION": "1",
            "TRACE": str(self.trace),
            "READY": str(self.ready),
            "TEST_SCRATCH_ROOT": str(self.scratch_root),
            "SCRATCH_RECORD": str(self.scratch_record),
            "RECORD_STATE": str(self.record_state),
            "CUSTODY_VERIFIER_PYTHON": str(self.verifier_python),
            "CUSTODY_VERIFIER_UPSTREAM_ROOT": str(self.verifier_upstream),
        })
        environment.update({key: str(value) for key, value in extra.items()})
        arguments = ["bash", str(self.script), "--validator-set", "hoodi-example", "--keystore-dir", str(self.keys),
                     "--signer-ca-output", str(self.base / "signer-ca.crt"), "--known-clients-output", str(self.base / "known-clients.txt")]
        if refresh:
            arguments.append("--refresh-auth-only")
        else:
            arguments += ["--expected-public-key", "0x" + "aa" * 48]
        if result_output is not None:
            arguments += ["--result-output", str(result_output)]
            if operation_id is not None:
                arguments += ["--operation-id", operation_id]
        return subprocess.run(
            arguments,
            input=stdin, text=True, capture_output=True, env=environment, timeout=10,
        )

    def trace_lines(self):
        return self.trace.read_text().splitlines() if self.trace.exists() else []

    def store(self, name, value):
        (self.record_state / f"{name}.json").write_text(value)

    def all_records(self):
        self.store("keystore", '{"keystore":"stored-keystore"}')
        self.store("password", '{"password":"stored-password"}')
        self.store("slashing-db-password", '{"password":"stored-slashing"}')
        self.store("signer-tls", '{"pkcs12_b64":"cDEy","password":"stored-tls"}')
        self.store("client-tls", '{"tls_crt_b64":"Y2VydA==","tls_key_b64":"a2V5","ca_crt_b64":"Y2E="}')

    def test_existing_pending_exit_and_eof_are_nonzero_and_untouched(self):
        for response in ("EXIT\n", ""):
            with self.subTest(response=response):
                result = self.invoke(response, ROOT_STARTED="1")
                self.assertEqual(result.returncode, 75, result.stderr)
                self.assertIn("Leaving the existing root-token ceremony untouched", result.stderr)
                self.assertNotIn("generate-root -cancel", "\n".join(self.trace_lines()))
                self.assertNotIn("token revoke", "\n".join(self.trace_lines()))
                self.assertNotIn("PASS:", result.stdout + result.stderr)
                self.trace.unlink(missing_ok=True)

    def test_outer_wrapper_forwards_refresh_only_flag(self):
        environment = os.environ.copy()
        environment.update({"PATH": f"{self.bin}:{environment['PATH']}", "TRACE": str(self.trace), "READY": str(self.ready)})
        result = subprocess.run(
            ["bash", str(self.script), "--validator-set", "hoodi-example", "--keystore-dir", str(self.keys),
             "--signer-ca-output", str(self.base / "signer-ca.crt"), "--known-clients-output", str(self.base / "known-clients.txt"),
             "--refresh-auth-only"],
            text=True, capture_output=True, env=environment, timeout=5,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("--refresh-auth-only", "\n".join(self.trace_lines()))
        self.assertNotIn("operator generate-root", "\n".join(self.trace_lines()))

    def test_outer_wrapper_forwards_completion_receipt_binding(self):
        result_path = self.base / "custody-completion.json"
        environment = os.environ.copy()
        environment.update({"PATH": f"{self.bin}:{environment['PATH']}", "TRACE": str(self.trace)})
        result = subprocess.run(
            ["bash", str(self.script), "--validator-set", "hoodi-example", "--keystore-dir", str(self.keys),
             "--signer-ca-output", str(self.base / "signer-ca.crt"), "--known-clients-output", str(self.base / "known-clients.txt"),
             "--expected-public-key", "0x" + "aa" * 48,
             "--result-output", str(result_path), "--operation-id", "1" * 32],
            text=True, capture_output=True, env=environment, timeout=5,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        forwarded = "\n".join(self.trace_lines())
        self.assertIn(f"--result-output {result_path.resolve()}", forwarded)
        self.assertIn("--operation-id " + "1" * 32, forwarded)

    def test_share_eof_leaves_own_ceremony_pending_without_revocation_or_cancel(self):
        result = self.invoke("")
        self.assertEqual(result.returncode, 75, result.stderr)
        calls = "\n".join(self.trace_lines())
        self.assertIn("operator generate-root -init -format=json", calls)
        self.assertNotIn("generate-root -cancel", calls)
        self.assertNotIn("token revoke", calls)
        self.assertNotIn("PASS:", result.stdout + result.stderr)

    def test_ambiguous_init_failure_reports_pending_without_cancelling(self):
        result = self.invoke("", FAIL_INIT="1", INIT_PENDING="1")
        self.assertEqual(result.returncode, 75, result.stderr)
        calls = "\n".join(self.trace_lines())
        self.assertIn("operator generate-root -init -format=json", calls)
        self.assertGreaterEqual(calls.count("operator generate-root -status -format=json"), 2)
        self.assertNotIn("generate-root -cancel", calls)
        self.assertNotIn("token revoke", calls)
        self.assertNotIn("PASS:", result.stdout + result.stderr)

    def test_signal_during_share_entry_preserves_own_pending_ceremony(self):
        environment = os.environ.copy()
        environment.update({"PATH": f"{self.bin}:{environment['PATH']}", "PRIVATE_VAULT_SESSION": "1",
                            "TRACE": str(self.trace), "READY": str(self.ready),
                            "TEST_SCRATCH_ROOT": str(self.scratch_root), "SCRATCH_RECORD": str(self.scratch_record)})
        process = subprocess.Popen(
            ["bash", str(self.script), "--validator-set", "hoodi-example", "--keystore-dir", str(self.keys),
             "--signer-ca-output", str(self.base / "signer-ca.crt"), "--known-clients-output", str(self.base / "known-clients.txt"),
             "--refresh-auth-only"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment,
        )
        try:
            stderr_prefix = b""
            deadline = time.monotonic() + 5
            while b"Recovery key share 1 of 1:" not in stderr_prefix and time.monotonic() < deadline:
                readable, _, _ = select.select([process.stderr], [], [], 0.05)
                if readable:
                    stderr_prefix += os.read(process.stderr.fileno(), 4096)
            self.assertIn(b"Recovery key share 1 of 1:", stderr_prefix, "ceremony did not reach share entry")
            process.send_signal(signal.SIGINT)
            process.wait(timeout=5)
            stdout = process.stdout.read().decode()
            stderr = process.stderr.read()
            process.stdin.close()
            process.stdout.close()
            process.stderr.close()
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)
        stderr = (stderr_prefix + stderr).decode()
        self.assertEqual(process.returncode, 130, stderr)
        calls = "\n".join(self.trace_lines())
        self.assertNotIn("generate-root -cancel", calls)
        self.assertNotIn("token revoke", calls)
        self.assertNotIn("PASS:", stdout + stderr)

    def test_refresh_success_prints_pass_only_after_root_revocation(self):
        result = self.invoke("share\n")
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = self.trace_lines()
        self.assertIn("token revoke -self", calls)
        self.assertIn("auth-helper", calls)
        self.assertIn("PASS: Kubernetes Auth refresh-only ceremony completed", result.stdout)
        self.assertNotIn("PASS:", result.stderr)

    def test_root_revocation_failure_suppresses_success(self):
        result = self.invoke("share\n", FAIL_ROOT_REVOKE="1")
        self.assertEqual(result.returncode, 70, result.stderr)
        self.assertIn("generated root token revocation could not be confirmed", result.stderr)
        self.assertNotIn("PASS:", result.stdout + result.stderr)

    def test_child_then_root_revocation_are_checked_before_full_success(self):
        result = self.invoke("share\nkeystore-password\n", refresh=False, FAIL_CHILD_REVOKE="1", FAIL_ROOT_REVOKE="1")
        self.assertEqual(result.returncode, 70, result.stderr)
        calls = self.trace_lines()
        child_index = calls.index("token revoke child-sentinel")
        root_index = calls.index("token revoke -self")
        self.assertLess(child_index, root_index)
        self.assertIn("temporary onboarding token revocation could not be confirmed", result.stderr)
        self.assertIn("generated root token revocation could not be confirmed", result.stderr)
        self.assertNotIn("PASS:", result.stdout + result.stderr)

    def test_custody_completion_receipt_is_private_and_post_success_only(self):
        result_path = self.base / "custody-completion.json"
        result = self.invoke(
            "share\nkeystore-password\n", refresh=False, result_output=result_path
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(oct(result_path.stat().st_mode & 0o777), "0o600")
        receipt = json.loads(result_path.read_text())
        self.assertEqual(receipt["result"], "onboarding-complete")
        self.assertEqual(receipt["operation_id"], "1" * 32)
        self.assertEqual(receipt["public_outputs"], {
            "signer_ca_sha256": hashlib.sha256(b"ca").hexdigest(),
            "known_clients_sha256": hashlib.sha256(b"known").hexdigest(),
        })
        calls = self.trace_lines()
        self.assertLess(calls.index("token revoke child-sentinel"), calls.index("token revoke -self"))
        self.assertIn("PASS: Hoodi custody records were coherently reconciled", result.stdout)

    def test_completion_receipt_is_suppressed_by_cleanup_or_revocation_failure(self):
        for failure in ("FAIL_CHILD_REVOKE", "FAIL_ROOT_REVOKE", "FAIL_UNLINK", "FAIL_RMDIR"):
            with self.subTest(failure=failure):
                result_path = self.base / f"{failure}.json"
                result = self.invoke(
                    "share\nkeystore-password\n", refresh=False, result_output=result_path,
                    **{failure: "1"},
                )
                self.assertEqual(result.returncode, 70, result.stderr)
                self.assertFalse(result_path.exists())
                self.assertNotIn("PASS:", result.stdout + result.stderr)

    def test_completion_receipt_never_overwrites_or_reuses_existing_target(self):
        result_path = self.base / "custody-completion.json"
        expected = (
            '{"expected_public_key":"0x' + "aa" * 48
            + '","operation_id":"' + "1" * 32
            + '","result":"custody-complete","schema_version":1,"validator_set":"hoodi-example"}\n'
        )
        result_path.write_text(expected)
        result_path.chmod(0o600)
        result = self.invoke("", refresh=False, result_output=result_path)
        self.assertEqual(result.returncode, 64, result.stderr)
        self.assertEqual(result_path.read_text(), expected)
        self.assertFalse(self.ready.exists())
        mismatch = self.base / "mismatch.json"
        mismatch.write_text("not-a-custody-receipt\n")
        mismatch.chmod(0o600)
        result = self.invoke("", refresh=False, result_output=mismatch)
        self.assertEqual(result.returncode, 64, result.stderr)
        self.assertEqual(mismatch.read_text(), "not-a-custody-receipt\n")
        self.assertNotIn("PASS:", result.stdout + result.stderr)

    def test_completion_receipt_options_are_paired_and_not_refreshable(self):
        result = self.invoke("", result_output=self.base / "only-output.json", operation_id=None)
        self.assertEqual(result.returncode, 64, result.stderr)
        self.assertFalse(self.ready.exists())
        result = self.invoke("", result_output=self.base / "refresh.json")
        self.assertEqual(result.returncode, 64, result.stderr)
        self.assertFalse((self.base / "refresh.json").exists())

    def test_completion_receipt_rejects_nonprivate_parent_before_ceremony(self):
        public = self.base / "public-result-parent"
        public.mkdir(mode=0o755)
        public.chmod(0o755)
        result = self.invoke(
            "", refresh=False, result_output=public / "custody-completion.json"
        )
        self.assertEqual(result.returncode, 64, result.stderr)
        self.assertIn("receipt parent is unavailable or unsafe", result.stderr)
        self.assertFalse(self.ready.exists())

    def test_all_present_records_are_verified_and_reconstructed_without_prompt_or_mutation(self):
        self.all_records()
        result = self.invoke("share\n", refresh=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = self.trace_lines()
        self.assertNotIn("bootstrap bootstrap-node-operator-vault-v2.sh", calls)
        self.assertNotIn("token create", calls)
        self.assertFalse(any(line.startswith("kv put") for line in calls))
        self.assertEqual((self.base / "signer-ca.crt").read_text(), "ca")
        self.assertEqual((self.base / "known-clients.txt").read_text(), "known")
        self.assertIn("coherently verified", result.stdout)

    def test_partial_records_preserve_existing_values_and_write_only_missing_candidate(self):
        self.store("keystore", '{"keystore":"preserved-keystore"}')
        self.store("password", '{"password":"preserved-password"}')
        result = self.invoke("share\n", refresh=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.record_state / "keystore.json").read_text(), '{"keystore":"preserved-keystore"}')
        self.assertEqual((self.record_state / "password.json").read_text(), '{"password":"preserved-password"}')
        calls = self.trace_lines()
        self.assertFalse(any(line.startswith("kv put") and "/keystore " in line for line in calls))
        self.assertFalse(any(line.startswith("kv put") and "/password " in line for line in calls))
        self.assertIn("bootstrap bootstrap-node-operator-vault-v2.sh", calls)
        for name in ("slashing-db-password", "signer-tls", "client-tls"):
            self.assertTrue((self.record_state / f"{name}.json").is_file())

    def test_read_error_stops_before_bootstrap_or_custody_writes(self):
        result = self.invoke("share\n", refresh=False, READ_ERROR_RECORD="keystore")
        self.assertEqual(result.returncode, 69, result.stderr)
        calls = self.trace_lines()
        self.assertFalse(any(line.startswith("bootstrap") for line in calls))
        self.assertFalse(any(line.startswith("kv put") for line in calls))
        self.assertIn("stored custody record could not be read: keystore", result.stderr)

    def test_only_exact_physical_kv2_absence_is_permitted_before_writes(self):
        physical = "node-operator-runtime/data/validators/hoodi/hoodi-example/runtime/keystore"
        cases = {
            "logical-path": ("node-operator-runtime/validators/hoodi/hoodi-example/runtime/keystore", "2"),
            "unrelated-path": ("node-operator-runtime/data/other/keystore", "2"),
            "wrong-status": (physical, "1"),
        }
        for name, (path, status) in cases.items():
            with self.subTest(name=name):
                result = self.invoke("share\nkeystore-password\n", refresh=False,
                                     MISSING_RESPONSE_PATH=path, MISSING_STATUS=status)
                self.assertEqual(result.returncode, 69, result.stderr)
                calls = self.trace_lines()
                self.assertFalse(any(line.startswith("bootstrap") for line in calls))
                self.assertFalse(any(line.startswith("kv put") for line in calls))
                self.assertIn("token revoke -self", calls)
                self.assertIn("stored custody record could not be read: keystore", result.stderr)
                self.trace.unlink(missing_ok=True)

    def test_cas_race_reloads_and_validates_full_winning_record_set(self):
        result = self.invoke("share\nkeystore-password\n", refresh=False, CAS_RACE_RECORD="password")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((self.record_state / "password.json").is_file())
        self.assertIn("coherently reconciled", result.stdout)
        self.assertTrue((self.base / "signer-ca.crt").is_file())

    def test_unavailable_crypto_context_stops_before_root_ceremony(self):
        environment = os.environ.copy()
        environment.update({"PATH": f"{self.bin}:{environment['PATH']}", "PRIVATE_VAULT_SESSION": "1", "TRACE": str(self.trace),
                            "READY": str(self.ready), "TEST_SCRATCH_ROOT": str(self.scratch_root), "SCRATCH_RECORD": str(self.scratch_record),
                            "RECORD_STATE": str(self.record_state)})
        result = subprocess.run(
            ["bash", str(self.script), "--validator-set", "hoodi-example", "--keystore-dir", str(self.keys),
             "--signer-ca-output", str(self.base / "signer-ca.crt"), "--known-clients-output", str(self.base / "known-clients.txt"),
             "--expected-public-key", "0x" + "aa" * 48],
            input="share\n", text=True, capture_output=True, env=environment, timeout=10,
        )
        self.assertEqual(result.returncode, 69)
        self.assertIn("custody crypto verifier runtime is unavailable", result.stderr)
        self.assertNotIn("operator generate-root", "\n".join(self.trace_lines()))

    def test_private_scratch_unlink_failure_suppresses_success(self):
        result = self.invoke("share\nkeystore-password\n", refresh=False, FAIL_UNLINK="1")
        self.assertEqual(result.returncode, 70, result.stderr)
        self.assertIn("private ceremony scratch cleanup could not be confirmed", result.stderr)
        self.assertNotIn("PASS:", result.stdout + result.stderr)
        self.assert_scratch_is_fixture_owned()

    def test_private_scratch_directory_cleanup_failure_suppresses_success(self):
        result = self.invoke("share\n", FAIL_RMDIR="1")
        self.assertEqual(result.returncode, 70, result.stderr)
        self.assertIn("private ceremony scratch directory cleanup could not be confirmed", result.stderr)
        self.assertNotIn("PASS:", result.stdout + result.stderr)
        self.assert_scratch_is_fixture_owned()

    def assert_scratch_is_fixture_owned(self):
        scratch = Path(self.scratch_record.read_text().strip()).resolve()
        self.assertTrue(str(scratch).startswith(str(self.scratch_root.resolve()) + os.sep))
        self.assertTrue(scratch.exists())


if __name__ == "__main__":
    unittest.main()
