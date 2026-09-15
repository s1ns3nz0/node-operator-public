#!/usr/bin/env python3
# Check objective: Validate existing Hoodi validator registration evidence.
"""Offline tests for public existing-Hoodi-validator registration evidence."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("verify", ROOT / "scripts/release/verify-existing-hoodi-validator.py")
M = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(M)
KEY = "0x" + "a" * 96
WITHDRAWAL = "0x01" + "0" * 22 + "b" * 40


class Transport:
    def __init__(self, values): self.values = values
    def get(self, path):
        value = self.values[path]
        if isinstance(value, Exception): raise value
        return json.dumps(value, sort_keys=True).encode()


class Response:
    status = 200
    headers = {}
    def __init__(self, request): self.request = request
    def __enter__(self): return self
    def __exit__(self, *unused): return False
    def geturl(self): return self.request.full_url
    def read(self, unused): return b"{}"


class Opener:
    def __init__(self): self.request = None
    def open(self, request, timeout): self.request = request; return Response(request)


def values(**overrides):
    genesis = {"data": {"genesis_validators_root": M.HOODI_GENESIS_ROOT, "genesis_time": str(M.HOODI_GENESIS_TIME)}}
    validator = {"finalized": True, "execution_optimistic": False, "data": {"index": "1559065", "status": "pending_queued", "validator": {"pubkey": KEY, "withdrawal_credentials": WITHDRAWAL, "slashed": False}}}
    genesis.update(overrides.pop("genesis", {})); validator.update(overrides.pop("validator_response", {}))
    validator["data"].update(overrides.pop("data", {})); validator["data"]["validator"].update(overrides)
    return {"/eth/v1/beacon/genesis": genesis, f"/eth/v1/beacon/states/finalized/validators/{KEY}": validator}


class VerifyExisting(unittest.TestCase):
    def setUp(self): self.tmp = tempfile.TemporaryDirectory(); self.root = Path(self.tmp.name).resolve(); self.output = self.root / "evidence.json"
    def tearDown(self): self.tmp.cleanup()
    def invoke(self, data=None): return M.verify(KEY, WITHDRAWAL, "https://beacon.example.test", self.output, transport=Transport(data or values()), now=lambda: "2026-09-13T00:00:00Z")
    def reject(self, data):
        with self.assertRaises(M.VerificationError): self.invoke(data)
        self.assertFalse(self.output.exists())

    def test_pending_and_active_validator_are_verified_without_activation(self):
        for status in ("pending_initialized", "pending_queued", "active_ongoing"):
            with self.subTest(status=status):
                result = self.invoke(values(data={"status": status})); self.assertEqual(result["result"], "REGISTRATION_VERIFIED"); self.assertFalse(result["signing_allowed"]); self.assertEqual(json.loads(self.output.read_text())["status"], status); self.output.unlink()

    def test_rejects_network_identity_and_finality_failures(self):
        cases = [values(genesis={"data": {"genesis_validators_root": "0x" + "c" * 64, "genesis_time": str(M.HOODI_GENESIS_TIME)}}), values(genesis={"data": {"genesis_validators_root": M.HOODI_GENESIS_ROOT, "genesis_time": "0"}}), values(validator_response={"finalized": False}), values(validator_response={"execution_optimistic": True}), values(slashed=True), {"/eth/v1/beacon/genesis": b"{", f"/eth/v1/beacon/states/finalized/validators/{KEY}": values()[f"/eth/v1/beacon/states/finalized/validators/{KEY}"]}]
        for data in cases:
            with self.subTest(data=data): self.reject(data)

    def test_rejects_wrong_identity_and_not_found(self):
        self.reject(values(pubkey="0x" + "d" * 96)); self.reject(values(withdrawal_credentials="0x" + "c" * 64))
        self.reject({"/eth/v1/beacon/genesis": values()["/eth/v1/beacon/genesis"], f"/eth/v1/beacon/states/finalized/validators/{KEY}": M.VerificationError("404")})

    def test_rejects_unsafe_status_and_never_overwrites(self):
        self.reject(values(data={"status": "exited_slashed"}))
        self.invoke(); before = self.output.read_bytes()
        with self.assertRaises(M.VerificationError): self.invoke()
        self.assertEqual(self.output.read_bytes(), before)
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o600)

    def test_https_transport_sets_descriptive_user_agent(self):
        opener = Opener(); transport = M.HttpsTransport.__new__(M.HttpsTransport); transport.origin = "https://beacon.example.test"; transport.opener = opener
        self.assertEqual(transport.get("/eth/v1/beacon/genesis"), b"{}")
        self.assertEqual(opener.request.get_header("User-agent"), "node-operator-installer/1.0")


if __name__ == "__main__": unittest.main()
