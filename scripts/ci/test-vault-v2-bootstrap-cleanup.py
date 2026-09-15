#!/usr/bin/env python3
# Check objective: Verify Vault v2 bootstrap cleanup outcomes with synthetic CLI responses.
"""Exercise cleanup outcomes using synthetic CLI responses, without live access."""
import os
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class BootstrapCleanup(unittest.TestCase):
    def test_cutover_requires_activation_not_preparation(self):
        proof = {"schema_version": 1, "operation": "activate-existing-hoodi-vault-v2",
                 "runtime_mount": "node-operator-runtime", "custody_preserved": True,
                 "transport_verified": True, "engine_jwt_verified": True,
                 "generated_root_revoked": True, "live_roles_installed": True,
                 "public_trust_config_updated": True, "client_and_fence_quiesced": True,
                 "live_workloads_changed": False, "source_secrets_retained": True,
                 "secret_values_emitted": False}

        def check(payload):
            return subprocess.run(["jq", "-e", "-f", str(ROOT / "scripts/ops/lib/vault-cutover-authorization.jq")],
                                  input=json.dumps(payload), text=True, capture_output=True).returncode

        self.assertEqual(check(proof), 0)
        for key in ("generated_root_revoked", "live_roles_installed", "public_trust_config_updated",
                    "client_and_fence_quiesced", "custody_preserved"):
            with self.subTest(key=key):
                self.assertNotEqual(check({**proof, key: False}), 0)
        self.assertNotEqual(check({**proof, "operation": "prepare-existing-hoodi-vault-v2"}), 0)

    def invoke(self, bootstrap_rc=0, revoke_rc=0, prepare=False, activate=False):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "lib").mkdir()
            wrapper = root / "recover-and-bootstrap-hoodi-vault-v2.sh"
            shutil.copy2(ROOT / "scripts/ops" / wrapper.name, wrapper)
            (root / "lib/vault-recovery-auth.sh").write_text(
                "vault_recovery_auth_preflight() { :; }\n"
                "vault_recovery_decode_generated_root() { printf synthetic; }\n")
            for name in ("bootstrap-node-operator-vault-v2.sh",
                         "bootstrap-hoodi-engine-api-vault.sh",
                         "bootstrap-hoodi-validator-runtime-vault.sh"):
                path = root / name
                path.write_text('#!/bin/bash\nexit "$BOOTSTRAP_RC"\n')
                path.chmod(0o700)
            auth_helper = root / "configure-hoodi-vault-kubernetes-auth.sh"
            auth_helper.write_text('#!/bin/bash\nexit "$BOOTSTRAP_RC"\n')
            auth_helper.chmod(0o700)
            vault = root / "vault"
            for name in ("copy-hoodi-custody-to-runtime-v2.sh",
                         "prepare-hoodi-vault-v2-transport.sh"):
                path = root / name
                path.write_text('#!/bin/bash\n'
                                'echo "' + name + '" >> "$CALLS"\n'
                                'if [ "$BOOTSTRAP_RC" != 0 ]; then exit "$BOOTSTRAP_RC"; fi\n'
                                'if [ "$1" = --validator-set ] && [ "${3:-}" = --output-dir ]; then mkdir "$4"; fi\n')
                path.chmod(0o700)
            vault.write_text("""#!/bin/bash
case "$*" in
  *"status -format=json"*) echo '{"initialized":true,"sealed":false,"version":"1.18.0"}' ;;
  *"generate-root -status"*) echo '{"started":false}' ;;
  *"generate-root -init"*) echo '{"nonce":"n","otp":"o","required":1}' ;;
  *"generate-root -nonce="*) echo '{"complete":true,"encoded_token":"e"}' ;;
  "token revoke -self") echo revoked >> "$EVENTS"; exit "$REVOKE_RC" ;;
  *) exit 64 ;;
esac
""")
            vault.chmod(0o700)
            events = root / "events"
            output = root / "public"
            args = ["bash", str(wrapper), "--validator-set", "hoodi-example"]
            if activate:
                preparation = root / "preparation.json"
                preparation.write_text('{}')
                args += ["--activate-existing", "--preparation-evidence", str(preparation),
                         "--output-dir", str(output)]
                for name in ("assert-hoodi-validator-quiesced.sh", "activate-hoodi-vault-v2-roles.sh"):
                    path = root / name
                    path.write_text('#!/bin/bash\n' + ('exit 0\n' if name.startswith('assert-')
                                                     else 'exit "$BOOTSTRAP_RC"\n'))
                    path.chmod(0o700)
            if prepare:
                args += ["--prepare-existing", "--output-dir", str(output)]
                for name in ("bootstrap-node-operator-vault-v2.sh",
                             "bootstrap-hoodi-validator-runtime-vault.sh"):
                    (root / name).write_text('#!/bin/bash\nexit 99\n')
                (root / "bootstrap-hoodi-engine-api-vault.sh").write_text(
                    '#!/bin/bash\n[ "$*" = --prepare-only ] || exit 98\n')
            result = subprocess.run(
                args,
                input="synthetic-share\n", text=True, capture_output=True,
                env={**os.environ, "PATH": f"{root}:{os.environ['PATH']}",
                     "PRIVATE_VAULT_SESSION": "1", "BOOTSTRAP_RC": str(bootstrap_rc),
                     "REVOKE_RC": str(revoke_rc), "EVENTS": str(events),
                     "CALLS": str(root / "calls")})
            self.assertEqual(events.read_text(), "revoked\n")
            self.assertNotIn("synthetic", result.stdout + result.stderr)
            if prepare:
                proof = output / "preparation.json"
                if result.returncode == 0:
                    evidence = json.loads(proof.read_text())
                    self.assertTrue(evidence["generated_root_revoked"])
                    self.assertFalse(evidence["live_policies_changed"])
                    self.assertFalse(evidence["live_workloads_changed"])
                    self.assertTrue(evidence["engine_jwt_verified"])
                else:
                    self.assertFalse(proof.exists())
            if activate:
                proof = output / "activation.json"
                if result.returncode == 0:
                    evidence = json.loads(proof.read_text())
                    self.assertEqual(evidence["operation"], "activate-existing-hoodi-vault-v2")
                    self.assertTrue(evidence["generated_root_revoked"])
                    self.assertTrue(evidence["public_trust_config_updated"])
                    self.assertTrue(evidence["live_roles_installed"])
                else:
                    self.assertFalse(proof.exists())
            return result

    def test_success_only_after_revocation(self):
        result = self.invoke()
        self.assertEqual(result.returncode, 0)
        self.assertIn("generated root token revoked", result.stdout)

    def test_activation_proof_after_revocation(self):
        self.assertEqual(self.invoke(activate=True).returncode, 0)

    def test_activation_revoke_failure_has_no_proof(self):
        self.assertEqual(self.invoke(activate=True, revoke_rc=1).returncode, 70)

    def test_activation_failure_has_no_proof(self):
        self.assertEqual(self.invoke(activate=True, bootstrap_rc=42).returncode, 42)

    def test_existing_preparation_does_not_install_live_roles(self):
        self.assertEqual(self.invoke(prepare=True).returncode, 0)

    def test_existing_preparation_revoke_failure_has_no_success_evidence(self):
        result = self.invoke(prepare=True, revoke_rc=1)
        self.assertEqual(result.returncode, 70)
        self.assertNotIn("PASS", result.stdout)

    def test_existing_copy_failure_stops_and_revokes(self):
        self.assertEqual(self.invoke(prepare=True, bootstrap_rc=42).returncode, 42)

    def test_revocation_failure_cannot_report_success(self):
        result = self.invoke(revoke_rc=1)
        self.assertEqual(result.returncode, 70)
        self.assertNotIn("PASS", result.stdout)
        self.assertIn("CRITICAL", result.stderr)

    def test_bootstrap_failure_still_revokes_and_preserves_failure(self):
        result = self.invoke(bootstrap_rc=42)
        self.assertEqual(result.returncode, 42)
        self.assertNotIn("PASS", result.stdout)


if __name__ == "__main__":
    unittest.main()
