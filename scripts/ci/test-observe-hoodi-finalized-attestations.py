#!/usr/bin/env python3
# Check objective: Validate the synthetic Hoodi finalized-attestation API contract.
"""Synthetic API contract only; it is not a live-duty proof."""
import importlib.util
import json
import tempfile
import threading
import unittest
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / "scripts/release/observe-hoodi-finalized-attestations.py"
spec = importlib.util.spec_from_file_location("observer", MODULE)
observer = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(observer)

KEY = "0x" + "a" * 96
INDEX = "123"
IDENTITY = {"validator_set": "hoodi-example", "validator_public_key": KEY, "validator_index": INDEX,
            "deployment_name": "node-operator", "release_revision": "b" * 40, "activation_slot": "300"}


class FinalizedAttestationObserver(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.base = Path(self.temp.name)
        self.work = self.base / "checkpoint"; self.work.mkdir()
        self.workload, self.logs = self.base / "workload.json", self.base / "logs.json"

    def tearDown(self): self.temp.cleanup()

    def write_inputs(self, epochs, fork_epoch=15):
        proof_identity = {key: value for key, value in IDENTITY.items() if key != "activation_slot"}
        workload = {**proof_identity, "schema_version": 1, "network": "hoodi", "event_type": "validator-attestation-workload-proof", "observations": []}
        logs = {**proof_identity, "schema_version": 1, "network": "hoodi", "event_type": "validator-log-delivery-proof", "observations": []}
        for epoch in epochs:
            data = {"slot": epoch * 32, "index": 0, "beacon_block_root": "0x" + "d" * 64,
                    "source_epoch": epoch - 1, "source_root": "0x" + "1" * 64,
                    "target_epoch": epoch, "target_root": "0x" + "2" * 64}
            version = "0x01020304" if epoch < fork_epoch else "0x05060708"
            signed = observer.signing_root(observer.attestation_data_root(data), version, "0x" + "3" * 64)
            workload["observations"].append({"epoch": str(epoch), "attestation_slot": str(epoch * 32), "committee_index": "0", "signing_root": signed,
                                              "signer_event": {"source": "web3signer-signing-audit", "evidence_id": f"sign-{epoch}"},
                                              "fence_interval": {"source": "kubernetes-lease", "evidence_id": f"fence-{epoch}"}})
            logs["observations"].append({"epoch": str(epoch), "attestation_slot": str(epoch * 32), "delivery_observed": True, "delivery_source": "aws-cloudwatch", "delivery_evidence_id": f"delivery-{epoch}"})
        self.workload.write_text(json.dumps(workload)); self.logs.write_text(json.dumps(logs))

    def fetch(self, rejected_epoch=None, public_root_suffix=None, electra=False, broken_ancestry=False,
              fork_epoch=15, next_epoch_inclusion=False):
        def request(url, timeout):
            del timeout
            is_public = url.startswith("https://public.example")
            path = url.split(".example", 1)[1]
            if path.startswith("/eth/v1/beacon/states/head/validators/"):
                return {"data": {"index": INDEX, "validator": {"pubkey": KEY}}}
            if path == "/eth/v1/beacon/states/head/finality_checkpoints":
                return {"data": {"finalized": {"epoch": "20", "root": "0x" + f"{20:064x}"}}}
            if path == "/eth/v1/beacon/genesis":
                return {"data": {"genesis_validators_root": "0x" + "3" * 64}}
            if path.startswith("/eth/v1/beacon/states/") and path.endswith("/fork"):
                self.assertGreaterEqual(int(path.split("/")[5], 16), 1000, "fork query must use inclusion state, not an older attested block")
                return {"data": {"epoch": str(fork_epoch), "previous_version": "0x01020304", "current_version": "0x05060708"}}
            if path.startswith("/eth/v1/beacon/headers/"):
                root = path.rsplit("/", 1)[1]
                if root == "0x" + "d" * 64:
                    return {"execution_optimistic":False, "finalized":True, "data":{"canonical":True, "root":root, "header":{"message":{"slot":"300", "parent_root":"0x" + "0" * 64, "state_root":"0x" + "4" * 64}}}}
                epoch = int(root, 16)
                if is_public and public_root_suffix is not None and epoch == public_root_suffix:
                    root = "0x" + "e" * 64
                parent_epoch = 9 if broken_ancestry and epoch == 20 else max(epoch - 1, 0)
                parent = "0x" + f"{parent_epoch:064x}"
                inclusion_slot = 352 if next_epoch_inclusion and epoch == 11 else epoch * 32 + 1
                return {"execution_optimistic":False, "finalized":True, "data": {"canonical": True, "root": root, "header": {"message": {"slot": str(inclusion_slot), "parent_root": parent, "state_root":"0x" + f"{epoch + 1000:064x}"}}}}
            if path.startswith("/eth/v2/beacon/blocks/"):
                root = path.rsplit("/", 1)[1]; epoch = int(root, 16)
                bits = "0x03" if epoch != rejected_epoch else "0x02"
                duty_epoch = 10 if next_epoch_inclusion and epoch == 11 else epoch
                attestation = {"aggregation_bits": bits, "data": {"slot": str(duty_epoch * 32), "index": "0", "beacon_block_root": "0x" + "d" * 64, "source": {"epoch": str(duty_epoch - 1), "root": "0x" + "1" * 64}, "target": {"epoch": str(duty_epoch), "root": "0x" + "2" * 64}}}
                if electra: attestation["committee_bits"] = "0x01"
                inclusion_slot = 352 if next_epoch_inclusion and epoch == 11 else epoch * 32 + 1
                attestations = [attestation] if not next_epoch_inclusion or epoch == 11 else []
                return {"data": {"message": {"slot": str(inclusion_slot), "parent_root": "0x" + f"{max(epoch - 1, 0):064x}", "state_root":"0x" + f"{epoch + 1000:064x}", "body": {"attestations": attestations}}}}
            if path.startswith("/eth/v1/beacon/states/") and "/committees?" in path:
                self.assertGreaterEqual(int(path.split("/")[5], 16), 1000, "committee query must use a state root, not a block root")
                return {"data": [{"slot": path.split("slot=", 1)[1].split("&", 1)[0], "index": "0", "validators": [INDEX]}]}
            raise AssertionError(url)
        return request

    def observe(self, fetch):
        return observer.observe(self.work, IDENTITY, "http://private.example", "https://public.example", self.workload, self.logs, 1, fetch)

    def test_three_consecutive_synthetic_block_body_memberships_complete(self):
        self.write_inputs([10, 11, 12])
        rc, result = self.observe(self.fetch())
        self.assertEqual(rc, 0); self.assertTrue(result["complete"])
        checkpoint = json.loads((self.work / "finalized-attestation-observer.json").read_text())
        self.assertEqual([proof["epoch"] for proof in checkpoint["proofs"]], ["10", "11", "12"])
        self.assertEqual(checkpoint["proofs"][0]["private"]["aggregation_bit_index"], 0)
        self.assertIn("workload_sha256", checkpoint["proofs"][0])

    def test_single_epoch_threshold_is_explicit_and_default_remains_three(self):
        self.write_inputs([10])
        rc, result = observer.observe(self.work, IDENTITY, "http://private.example", "https://public.example", self.workload, self.logs, 1, self.fetch(), required_count=1)
        self.assertEqual(rc, 0); self.assertEqual(result["required_finalized_epochs"], 1)
        rc, result = self.observe(self.fetch())
        self.assertEqual(rc, 75); self.assertEqual(result["required_finalized_epochs"], 3)

    def test_duplicate_epoch_cannot_count_as_two_proofs(self):
        self.write_inputs([10, 10])
        with self.assertRaises(observer.ObservationError):
            observer.observe(self.work, IDENTITY, "http://private.example", "https://public.example", self.workload, self.logs, 1, self.fetch(), required_count=2)
        for invalid in (True, False, 0, 4):
            with self.assertRaises(observer.ObservationError):
                observer.observe(self.work, IDENTITY, "http://private.example", "https://public.example", self.workload, self.logs, 1, self.fetch(), required_count=invalid)

    def test_single_header_rejects_list_or_optimistic_response(self):
        root = "0x" + f"{20:064x}"
        response = self.fetch()("http://private.example/eth/v1/beacon/headers/" + root, 1)
        for invalid in ({**response, "data":[response["data"]]}, {**response, "execution_optimistic":True}):
            api = observer.Beacon("http://private.example", 1, lambda url, timeout: invalid)
            with self.assertRaises(observer.ObservationError): api.header(root)

    def test_repeated_aggregate_of_same_vote_is_not_a_conflicting_duty(self):
        self.write_inputs([10, 11, 12])
        original = self.fetch()
        def duplicate(url, timeout):
            response = original(url, timeout)
            if "/eth/v2/beacon/blocks/" in url:
                rows = response["data"]["message"]["body"]["attestations"]
                rows.append(dict(rows[0]))
            return response
        rc, result = self.observe(duplicate)
        self.assertEqual(rc, 0); self.assertEqual(result["consecutive_finalized_epochs"], ["10", "11", "12"])

    def test_resume_adds_new_epoch_without_reactivation_or_replaying_proofs(self):
        self.write_inputs([10, 11]); rc, _ = self.observe(self.fetch()); self.assertEqual(rc, 75)
        self.write_inputs([10, 11, 12]); rc, result = self.observe(self.fetch())
        self.assertEqual(rc, 0); self.assertEqual(result["consecutive_finalized_epochs"], ["10", "11", "12"])

    def test_gap_starts_a_fresh_consecutive_sequence(self):
        self.write_inputs([10, 12]); rc, result = self.observe(self.fetch())
        self.assertEqual(rc, 75); self.assertEqual(result["consecutive_finalized_epochs"], ["12"])

    def test_unset_aggregation_bit_is_not_an_attestation_proof(self):
        self.write_inputs([10]); rc, result = self.observe(self.fetch(rejected_epoch=10))
        self.assertEqual(rc, 75); self.assertEqual(result["consecutive_finalized_epochs"], [])

    def test_electra_committee_bits_uses_concatenated_membership(self):
        self.write_inputs([10]); rc, result = self.observe(self.fetch(electra=True))
        self.assertEqual(rc, 75); self.assertEqual(result["consecutive_finalized_epochs"], ["10"])

    def test_target_epoch_at_fork_boundary_uses_current_fork_version(self):
        self.write_inputs([10], fork_epoch=10)
        rc, result = self.observe(self.fetch(fork_epoch=10))
        self.assertEqual(rc, 75); self.assertEqual(result["consecutive_finalized_epochs"], ["10"])

    def test_committee_query_explicitly_selects_prior_attestation_epoch(self):
        """The inclusion state is newer, so the API default would select its epoch."""
        self.write_inputs([10])
        original = self.fetch(next_epoch_inclusion=True)

        def prior_epoch_only(url, timeout):
            if "/committees?" in url:
                parsed = urlsplit(url)
                self.assertIn("/states/0x" + f"{1011:064x}" + "/committees", parsed.path)
                query = parse_qs(parsed.query, strict_parsing=True)
                # The inclusion state is from a later state.  Without an explicit
                # duty epoch, Beacon API defaults the committee query to that state
                # epoch and returns no committee for the old attestation slot.
                if query.get("epoch") != ["10"]:
                    return {"data": []}
            return original(url, timeout)

        rc, result = self.observe(prior_epoch_only)
        self.assertEqual(rc, 75)
        self.assertEqual(result["consecutive_finalized_epochs"], ["10"])

    def test_wrong_logged_signing_root_cannot_qualify(self):
        self.write_inputs([10])
        payload = json.loads(self.workload.read_text())
        payload["observations"][0]["signing_root"] = "0x" + "f" * 64
        self.workload.write_text(json.dumps(payload))
        with self.assertRaises(observer.ObservationError):
            self.observe(self.fetch())

    def test_public_canonical_root_disagreement_rejects(self):
        self.write_inputs([10])
        with self.assertRaises(observer.ObservationError): self.observe(self.fetch(public_root_suffix=10))

    def test_earlier_canonical_header_without_finalized_parent_ancestry_cannot_qualify(self):
        self.write_inputs([10])
        rc, result = self.observe(self.fetch(broken_ancestry=True))
        self.assertEqual(rc, 75); self.assertEqual(result["consecutive_finalized_epochs"], [])

    def test_pre_activation_epoch_cannot_qualify(self):
        self.write_inputs([9]); rc, result = self.observe(self.fetch())
        self.assertEqual(rc, 75); self.assertEqual(result["consecutive_finalized_epochs"], [])

    def test_resume_rejects_a_changed_public_source_identity(self):
        self.write_inputs([10]); self.observe(self.fetch())
        with self.assertRaises(observer.ObservationError):
            observer.observe(self.work, IDENTITY, "http://private.example", "https://other-public.example", self.workload, self.logs, 1, self.fetch())

    def test_actual_local_http_transport_observes_without_live_chain_access(self):
        self.write_inputs([10])
        fake = self.fetch()
        def server(prefix):
            class Handler(BaseHTTPRequestHandler):
                def do_GET(self):
                    try:
                        body = json.dumps(fake(prefix + self.path, 1)).encode()
                        self.send_response(200); self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
                    except Exception:
                        self.send_response(500); self.end_headers()
                def log_message(self, *_): pass
            result = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
            threading.Thread(target=result.serve_forever, daemon=True).start()
            return result
        private, public = server("http://private.example"), server("https://public.example")
        try:
            rc, result = observer.observe(self.work, IDENTITY, f"http://127.0.0.1:{private.server_port}", f"http://127.0.0.1:{public.server_port}", self.workload, self.logs, 1)
        finally:
            private.shutdown(); public.shutdown(); private.server_close(); public.server_close()
        self.assertEqual(rc, 75); self.assertEqual(result["consecutive_finalized_epochs"], ["10"])


if __name__ == "__main__": unittest.main()
