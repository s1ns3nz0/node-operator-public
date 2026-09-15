#!/usr/bin/env python3
# Check objective: Verify Vault v2 role activation cannot bypass preparation and quiescence gates.
"""Verify policy changes cannot precede preparation and live quiescence gates."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

OPS = Path(__file__).resolve().parents[1] / "ops"


class Activation(unittest.TestCase):
    def invoke(self, valid=True, stopped=True):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            script = root / "activate-hoodi-vault-v2-roles.sh"
            shutil.copy2(OPS / script.name, script)
            evidence = {"schema_version": 1, "operation": "prepare-existing-hoodi-vault-v2",
                        "validator_set": "hoodi-example", "runtime_mount": "node-operator-runtime",
                        "custody_preserved": valid, "transport_verified": True,
                        "engine_jwt_verified": True, "generated_root_revoked": True,
                        "live_policies_changed": False, "live_workloads_changed": False,
                        "secret_values_emitted": False}
            proof = root / "proof.json"
            proof.write_text(json.dumps(evidence))
            events = root / "events"
            for name in ("assert-hoodi-validator-quiesced.sh", "copy-hoodi-custody-to-runtime-v2.sh",
                         "prepare-hoodi-vault-v2-transport.sh",
                         "bootstrap-hoodi-engine-api-vault.sh", "bootstrap-hoodi-validator-runtime-vault.sh"):
                path = root / name
                path.write_text('#!/bin/bash\necho "' + name + '" >> "$EVENTS"\n' +
                                ('exit 1\n' if not stopped and name.startswith("assert-") else 'exit 0\n'))
                path.chmod(0o700)
            vault = root / "vault"
            vault.write_text('#!/bin/bash\necho \'{"data":{"data":{"jwt":"' + 'a' * 64 + '"}}}\'\n')
            vault.chmod(0o700)
            kubectl = root / "kubectl"
            kubectl.write_text('#!/bin/bash\ncase "$*" in *"create configmap"*) echo \'{"kind":"ConfigMap","data":{"known-clients":"public-fingerprint"}}\';; *"patch configmap"*) jq -e \' .data["known-clients"] == "public-fingerprint"\' >/dev/null;; *) exit 64;; esac\n')
            kubectl.chmod(0o700)
            result = subprocess.run(["bash", str(script), "--validator-set", "hoodi-example",
                                     "--preparation-evidence", str(proof)], capture_output=True,
                                    text=True, env={**os.environ, "PATH": f"{root}:{os.environ['PATH']}",
                                                    "VAULT_TOKEN": "synthetic", "EVENTS": str(events)})
            calls = events.read_text().splitlines() if events.exists() else []
            return result, calls

    def test_preparation_required(self):
        result, calls = self.invoke(valid=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(calls, [])

    def test_live_stop_required(self):
        result, calls = self.invoke(stopped=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(calls, ["assert-hoodi-validator-quiesced.sh"])

    def test_policy_writes_after_two_live_checks(self):
        result, calls = self.invoke()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(calls[:4], ["assert-hoodi-validator-quiesced.sh",
                                    "copy-hoodi-custody-to-runtime-v2.sh",
                                    "prepare-hoodi-vault-v2-transport.sh",
                                    "assert-hoodi-validator-quiesced.sh"])
        self.assertEqual(len(calls), 6)


if __name__ == "__main__":
    unittest.main()
