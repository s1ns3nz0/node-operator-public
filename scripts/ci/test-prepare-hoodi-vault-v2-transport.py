#!/usr/bin/env python3
# Check objective: Verify stored TLS transport with disposable OpenSSL certificates.
"""Offline stored-TLS verification tests using disposable real OpenSSL certificates."""

import base64
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "scripts/ops/prepare-hoodi-vault-v2-transport.sh"
HELPER = ROOT / "scripts/ops/verify-hoodi-vault-v2-transport-records.sh"
SET = "hoodi-example"
SERVER = f"validator-{SET}-remote-signer.validator-operations.svc"
CLIENT = f"validator-{SET}-client.validator-operations.svc"


class StoredTransportVerificationTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.bin = self.base / "bin"; self.bin.mkdir()
        self.records = self.base / "records"; self.records.mkdir()
        self.trace = self.base / "vault-trace"
        self._write_vault()
        self._write_cleanup_shims()
        self.ca_key, self.ca = self._certificate("ca", "test-ca", ca=True)
        self.server_key, self.server_cert = self._certificate("server", SERVER, issuer=(self.ca_key, self.ca), usage="serverAuth")
        self.client_key, self.client_cert = self._certificate("client", CLIENT, issuer=(self.ca_key, self.ca), usage="clientAuth", san=f"{CLIENT}.cluster.local")
        self._write_records()

    def tearDown(self):
        self.temp.cleanup()

    def invoke(self, name, verify_only=True, script=SOURCE, **environment):
        output = self.base / name
        env = os.environ.copy()
        env.update({"PATH": f"{self.bin}:{env['PATH']}", "VAULT_TOKEN": "synthetic-root", "RECORDS": str(self.records),
                    "TRACE": str(self.trace), "TMPDIR": str(self.base)})
        env.update({key: str(value) for key, value in environment.items()})
        arguments = ["bash", str(script), "--validator-set", SET, "--output-dir", str(output)]
        if verify_only:
            arguments.append("--verify-only")
        return subprocess.run(arguments,
                              text=True, capture_output=True, env=env, timeout=15), output

    def invoke_helper(self, name, **environment):
        scratch = self.base / f"{name}-scratch"; scratch.mkdir()
        output = self.base / name
        env = os.environ.copy()
        env.update({"PATH": f"{self.bin}:{env['PATH']}"})
        env.update({key: str(value) for key, value in environment.items()})
        result = subprocess.run(
            ["bash", str(HELPER), "--validator-set", SET,
             "--signer-record", str(self.records / "signer-tls.json"),
             "--client-record", str(self.records / "client-tls.json"),
             "--scratch-dir", str(scratch), "--output-dir", str(output)],
            text=True, capture_output=True, env=env, timeout=15,
        )
        return result, output

    def openssl(self, *args):
        return subprocess.run(["openssl", *args], check=True, capture_output=True, text=True).stdout

    def _certificate(self, stem, common_name, issuer=None, ca=False, usage=None, san=None):
        key = self.base / f"{stem}.key"; csr = self.base / f"{stem}.csr"; cert = self.base / f"{stem}.crt"
        self.openssl("genrsa", "-out", str(key), "2048")
        if ca:
            self.openssl("req", "-x509", "-new", "-key", str(key), "-sha256", "-days", "2", "-subj", f"/CN={common_name}", "-out", str(cert))
        else:
            self.openssl("req", "-new", "-key", str(key), "-subj", f"/CN={common_name}", "-out", str(csr))
            extension = self.base / f"{stem}.ext"
            extension.write_text(f"subjectAltName=DNS:{san or common_name}\nextendedKeyUsage={usage or ('serverAuth' if stem == 'server' else 'clientAuth')}\n")
            self.openssl("x509", "-req", "-in", str(csr), "-CA", str(issuer[1]), "-CAkey", str(issuer[0]), "-CAcreateserial",
                         "-out", str(cert), "-days", "2", "-sha256", "-extfile", str(extension))
        return key, cert

    def _b64(self, path):
        return base64.b64encode(path.read_bytes()).decode()

    def _write_records(self, client_cert=None, client_key=None, client_ca=None, signer_cert=None, signer_key=None):
        client_cert = client_cert or self.client_cert; client_key = client_key or self.client_key; client_ca = client_ca or self.ca
        signer_cert = signer_cert or self.server_cert; signer_key = signer_key or self.server_key
        p12 = self.base / "signer.p12"
        password_file = self.base / "fixture-pkcs12-password"
        password_file.write_text("fixture-password\n")
        password_file.chmod(0o600)
        self.openssl("pkcs12", "-export", "-inkey", str(signer_key), "-in", str(signer_cert), "-certfile", str(self.ca),
                     "-out", str(p12), "-passout", f"file:{password_file}")
        (self.records / "signer-tls.json").write_text(json.dumps({"pkcs12_b64": self._b64(p12), "password": "fixture-password"}))
        (self.records / "client-tls.json").write_text(json.dumps({"tls_crt_b64": self._b64(client_cert), "tls_key_b64": self._b64(client_key), "ca_crt_b64": self._b64(client_ca)}))

    def _write_vault(self):
        vault = self.bin / "vault"
        vault.write_text(
            "#!/usr/bin/env bash\nset -eu\nprintf '%s\\n' \"$*\" >> \"$TRACE\"\n"
            "[ \"$1 $2\" = 'read -format=json' ] || exit 64\n"
            "case \"${!#}\" in *signer-tls) file=signer-tls.json ;; *client-tls) file=client-tls.json ;; *) exit 64 ;; esac\n"
            "if [ \"${READ_MODE:-ok}\" = missing ]; then printf 'No value found at %s\\n' \"${!#}\" >&2; exit 2; fi\n"
            "if [ \"${READ_MODE:-ok}\" = denied ]; then printf '%s\\n' 'permission denied' >&2; exit 2; fi\n"
            "printf '{\"data\":{\"data\":'\ncat \"$RECORDS/$file\"\nprintf '}}\\n'\n"
        )
        vault.chmod(0o700)

    def _write_cleanup_shims(self):
        for name, variable in (("unlink", "FAIL_UNLINK"), ("rmdir", "FAIL_RMDIR")):
            command = self.bin / name
            command.write_text(
                "#!/usr/bin/env bash\nset -eu\n"
                f"[ \"${{{variable}:-0}}\" != 1 ] || exit 9\n"
                f"exec {shutil.which(name)} \"$@\"\n"
            )
            command.chmod(0o700)

    def assert_no_vault_write(self):
        calls = self.trace.read_text() if self.trace.exists() else ""
        self.assertNotIn("write ", calls)
        self.assertNotIn("secrets enable", calls)

    def test_matching_stored_records_reconstruct_public_outputs_without_vault_write(self):
        result, output = self.invoke("matching")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((output / "signer-ca.crt").read_bytes(), self.ca.read_bytes())
        fingerprint = self.openssl("x509", "-in", str(self.client_cert), "-noout", "-fingerprint", "-sha256").strip().split("=", 1)[1]
        self.assertEqual((output / "known-clients.txt").read_text(), f"{CLIENT} {fingerprint}\n")
        self.assertIn("PASS:", result.stdout)
        self.assert_no_vault_write()

    def test_direct_validator_reconstructs_public_outputs_from_verified_records(self):
        result, output = self.invoke_helper("direct-helper")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((output / "signer-ca.crt").read_bytes(), self.ca.read_bytes())
        fingerprint = self.openssl("x509", "-in", str(self.client_cert), "-noout", "-fingerprint", "-sha256").strip().split("=", 1)[1]
        self.assertEqual((output / "known-clients.txt").read_text(), f"{CLIENT} {fingerprint}\n")
        self.assert_no_vault_write()

    def test_wrong_client_identity_ca_and_key_are_rejected(self):
        for kind in ("identity", "ca", "key"):
            with self.subTest(kind=kind):
                if kind == "identity":
                    wrong_key, wrong_cert = self._certificate("wrong-client", "other-client.validator-operations.svc", issuer=(self.ca_key, self.ca))
                    self._write_records(client_cert=wrong_cert, client_key=wrong_key)
                elif kind == "ca":
                    other_key, other_ca = self._certificate("other-ca", "other-ca", ca=True)
                    self._write_records(client_ca=other_ca)
                else:
                    other_key, _ = self._certificate("other-key", "unused", issuer=(self.ca_key, self.ca))
                    self._write_records(client_key=other_key)
                result, output = self.invoke(f"bad-{kind}")
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(output.exists())
                self.assertNotIn("PASS:", result.stdout + result.stderr)
                self.assert_no_vault_write()
                self.trace.unlink(missing_ok=True)
                self._write_records()

    def test_wrong_server_hostname_wrong_pkcs12_password_and_client_eku_are_rejected(self):
        for kind in ("server-hostname", "pkcs12-password", "client-eku"):
            with self.subTest(kind=kind):
                if kind == "server-hostname":
                    key, cert = self._certificate("wrong-server", "other-signer.validator-operations.svc", issuer=(self.ca_key, self.ca), usage="serverAuth")
                    self._write_records(signer_cert=cert, signer_key=key)
                elif kind == "pkcs12-password":
                    record = json.loads((self.records / "signer-tls.json").read_text())
                    record["password"] = "wrong-password"
                    (self.records / "signer-tls.json").write_text(json.dumps(record))
                else:
                    key, cert = self._certificate("wrong-eku", CLIENT, issuer=(self.ca_key, self.ca), usage="serverAuth", san=f"{CLIENT}.cluster.local")
                    self._write_records(client_cert=cert, client_key=key)
                result, output = self.invoke(f"bad-{kind}")
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(output.exists())
                self.assertNotIn("PASS:", result.stdout + result.stderr)
                self.assert_no_vault_write()
                self.trace.unlink(missing_ok=True)
                self._write_records()

    def test_malformed_base64_and_record_schema_are_rejected(self):
        for kind in ("base64", "schema"):
            with self.subTest(kind=kind):
                record = json.loads((self.records / "client-tls.json").read_text())
                if kind == "base64": record["tls_crt_b64"] = "%%%"
                else: record["unexpected"] = "field"
                (self.records / "client-tls.json").write_text(json.dumps(record))
                result, output = self.invoke(f"bad-{kind}")
                self.assertEqual(result.returncode, 65, result.stderr)
                self.assertFalse(output.exists())
                self.assert_no_vault_write()
                self.trace.unlink(missing_ok=True)
                self._write_records()

    def test_expiring_stored_certificate_is_rejected(self):
        key = self.base / "short.key"; csr = self.base / "short.csr"; cert = self.base / "short.crt"; extension = self.base / "short.ext"
        self.openssl("genrsa", "-out", str(key), "2048")
        self.openssl("req", "-new", "-key", str(key), "-subj", f"/CN={CLIENT}", "-out", str(csr))
        ca_state = self.base / "expired-ca"; (ca_state / "newcerts").mkdir(parents=True)
        (ca_state / "index.txt").touch(); (ca_state / "serial").write_text("1000\n")
        config = ca_state / "openssl.cnf"
        config.write_text(
            "[ ca ]\ndefault_ca = local_ca\n[ local_ca ]\n"
            f"database = {ca_state / 'index.txt'}\nnew_certs_dir = {ca_state / 'newcerts'}\ncertificate = {self.ca}\nprivate_key = {self.ca_key}\nserial = {ca_state / 'serial'}\n"
            "default_md = sha256\npolicy = permissive\nx509_extensions = client_extension\n"
            "[ permissive ]\ncommonName = supplied\n[ client_extension ]\n"
            f"subjectAltName = DNS:{CLIENT}\nextendedKeyUsage = clientAuth\n"
        )
        self.openssl("ca", "-batch", "-config", str(config), "-in", str(csr), "-out", str(cert),
                     "-startdate", "20200101000000Z", "-enddate", "20200102000000Z")
        self._write_records(client_cert=cert, client_key=key)
        result, output = self.invoke("expiring")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(output.exists())
        self.assert_no_vault_write()

    def test_private_scratch_cleanup_failure_suppresses_success(self):
        for variable in ("FAIL_UNLINK", "FAIL_RMDIR"):
            with self.subTest(variable=variable):
                result, output = self.invoke(f"cleanup-{variable}", **{variable: "1"})
                self.assertEqual(result.returncode, 70, result.stderr)
                self.assertTrue((output / "signer-ca.crt").is_file())
                self.assertIn("private transport-validation scratch", result.stderr)
                self.assertNotIn("PASS:", result.stdout + result.stderr)
                self.assert_no_vault_write()
                self.trace.unlink(missing_ok=True)

    def test_only_documented_not_found_may_enter_nonverify_create_path(self):
        ops = self.base / "ops"; ops.mkdir()
        staged = ops / SOURCE.name; staged.write_bytes(SOURCE.read_bytes()); staged.chmod(0o700)
        staged_helper = ops / HELPER.name; staged_helper.write_bytes(HELPER.read_bytes()); staged_helper.chmod(0o700)
        for name in ("bootstrap-node-operator-vault-v2.sh", "bootstrap-hoodi-validator-runtime-vault.sh"):
            bootstrap = ops / name
            bootstrap.write_text("#!/usr/bin/env bash\nset -eu\nprintf 'bootstrap %s\\n' \"${0##*/}\" >> \"$TRACE\"\n")
            bootstrap.chmod(0o700)
        result, _ = self.invoke("missing", verify_only=False, script=staged, READ_MODE="missing")
        self.assertNotEqual(result.returncode, 0)
        missing_calls = self.trace.read_text()
        self.assertIn("read -format=json node-operator-runtime/data/", missing_calls)
        self.assertIn("write -format=json node-operator-pki/issue/validator-mtls", missing_calls)
        self.trace.unlink(missing_ok=True)
        result, output = self.invoke("denied", verify_only=False, script=staged, READ_MODE="denied")
        self.assertEqual(result.returncode, 69, result.stderr)
        self.assertFalse(output.exists())
        calls = self.trace.read_text()
        self.assertIn("read -format=json node-operator-runtime/data/", calls)
        self.assertNotIn("write ", calls)
        self.assertNotIn("token create", calls)
        self.assertIn("bootstrap", calls)
        self.assertIn("stored transport record could not be read", result.stderr)


if __name__ == "__main__":
    unittest.main()
