#!/usr/bin/env python3
"""Public-command tests for the dry-run missing-history recovery guard."""
from __future__ import annotations
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
COMMAND = ROOT / "scripts/ops/recover-missing-hoodi-slashing-history.sh"
KEY = "0x" + "a" * 96
GVR = "0x" + "b" * 64
SET = "hoodi-example"
PVC = "data-validator-hoodi-example-slashing-db-0"
UID = "11111111-2222-3333-4444-555555555555"


class RecoveryPlanTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.work = Path(self.tmp.name)
        self.proof = self.work / "stopped.json"
        self.proof.write_text(json.dumps({"schema_version": 1, "validator_set": SET, "validator_public_key": KEY, "database_pvc": PVC, "database_uid": UID, "client_stopped": True, "signer_stopped": True, "fence_stopped": True, "lease_holder_absent": True}))
        os.chmod(self.proof, 0o600)
        self.output = self.work / "plan.json"
        source = json.loads((ROOT / ".ci/validator/approved-runtime-images.json").read_text())["images"]["web3signer"]["source"]
        digest = source.rsplit(":", 1)[1]
        self.image = "123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/node-operator-selected-validator-runtime-web3signer@sha256:" + digest

    def tearDown(self): self.tmp.cleanup()

    def call(self, *extra):
        return subprocess.run([str(COMMAND), "--source-root", str(ROOT), "--validator-set", SET, "--validator-public-key", KEY, "--gvr", GVR, "--database-pvc", PVC, "--database-uid", UID, "--web3signer-image", self.image, "--slot", "64", "--epoch", "2", "--stopped-paths", str(self.proof), "--output", str(self.output), *extra], text=True, capture_output=True)

    def test_plan_is_noop_and_registers_only_synthetic_guard(self):
        database = self.work / "fresh-isolated-db"
        database.write_bytes(b"empty database sentinel")
        before = database.read_bytes()
        result = self.call()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(database.read_bytes(), before)
        plan = json.loads(self.output.read_text())
        self.assertFalse(plan["historical_evidence_recovered"])
        self.assertFalse(plan["web3signer_authority"]["runtime_destination_verified"])
        self.assertFalse(plan["stopped_path_proposal_verified"])
        self.assertEqual(plan["synthetic_eip3076_guard"]["data"], [{"pubkey": KEY, "signed_blocks": [], "signed_attestations": []}])
        self.assertEqual(stat := (self.output.stat().st_mode & 0o777), 0o600)

    def test_nonpositive_watermark_floor_is_rejected(self):
        result = self.call("--slot", "0")
        self.assertEqual(result.returncode, 65)
        self.assertFalse(self.output.exists())

    def test_unbound_stopped_path_proposal_is_rejected(self):
        value = json.loads(self.proof.read_text()); value["signer_stopped"] = False; self.proof.write_text(json.dumps(value))
        result = self.call()
        self.assertEqual(result.returncode, 65)

    def test_execute_is_explicitly_unavailable_and_restart_plan_is_immutable(self):
        result = self.call("--execute")
        self.assertEqual(result.returncode, 65)
        self.assertFalse(self.output.exists())
        result = self.call("--execute", "--exception-approval-id", "approved-123", "--operation-id", "slashing-recovery-123")
        self.assertEqual(result.returncode, 65)
        self.assertFalse(self.output.exists())
        self.assertEqual(self.call().returncode, 0)
        # A replay cannot overwrite or silently reinterpret an already-bound plan.
        self.assertEqual(self.call().returncode, 65)


if __name__ == "__main__": unittest.main()
