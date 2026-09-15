#!/usr/bin/env python3
# Check objective: Verify Hoodi validator observation assembly with synthetic transports.
"""Compose real archive/canonical observers using synthetic external transports."""
import importlib.util
import contextlib
import io
import json
import os
from datetime import datetime, timezone
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


runner = load("runner", ROOT / "scripts/release/run-hoodi-validator-observation.py")
archive_test = load("archive_fixture", ROOT / "scripts/ci/test-collect-hoodi-finalized-attestation-evidence.py")
chain_test = load("chain_fixture", ROOT / "scripts/ci/test-observe-hoodi-finalized-attestations.py")
delivery_fixture = load("delivery_terraform_fixture", ROOT / "scripts/ci/test-operational-log-delivery-terraform.py")


class PrivateBeaconLifecycle(unittest.TestCase):
    """Exercise owned-tunnel cleanup independently of chain/archive fixtures."""
    def start(self, process, announcement):
        def popen(argv, **kwargs):
            self.assertEqual(argv, ["kubectl", "-n", "node-operator", "port-forward",
                                   "--address=127.0.0.1", "pod/prysm-beacon-0", "19501:3500"])
            kwargs["stdout"].write(announcement)
            kwargs["stdout"].flush()
            return process
        return popen

    def test_own_announcement_and_stable_uid_allow_cleanup(self):
        process = Mock(); process.poll.return_value = None
        session = runner.PrivateBeaconSession(19501)
        with patch.object(session, "pod_uid", return_value="beacon-uid"), patch.object(
                runner.subprocess, "Popen", side_effect=self.start(process, b"Forwarding from 127.0.0.1:19501 -> 3500\n")):
            with session as opened:
                self.assertIs(opened, session)
                opened.verify()
        process.terminate.assert_called_once()
        process.wait.assert_called_once_with(timeout=5)
        self.assertTrue(session.log.closed)

    def test_replaced_pod_cannot_authorize_tunnel(self):
        process = Mock(); process.poll.return_value = None
        session = runner.PrivateBeaconSession(19501)
        with patch.object(session, "pod_uid", side_effect=["original", "replacement"]), patch.object(
                runner.subprocess, "Popen", side_effect=self.start(process, b"Forwarding from 127.0.0.1:19501 -> 3500\n")):
            with self.assertRaisesRegex(runner.Pending, "identity changed"):
                with session: self.fail("replacement must not reach observation")
        process.terminate.assert_called_once()
        self.assertTrue(session.log.closed)

    def test_wrong_port_announcement_times_out_and_reaps_owned_process(self):
        process = Mock(); process.poll.return_value = None
        session = runner.PrivateBeaconSession(19501)
        with patch.object(session, "pod_uid", return_value="beacon-uid"), patch.object(
                runner.subprocess, "Popen", side_effect=self.start(process, b"Forwarding from 127.0.0.1:19502 -> 3500\n")), patch.object(
                runner.time, "monotonic", side_effect=[0, 1, 16]), patch.object(runner.time, "sleep"):
            with self.assertRaisesRegex(runner.Pending, "readiness timed out"):
                with session: self.fail("another port must not authorize observation")
        process.terminate.assert_called_once()
        self.assertTrue(session.log.closed)

    def test_caller_recheck_detects_replacement_after_entry(self):
        process = Mock(); process.poll.return_value = None
        session = runner.PrivateBeaconSession(19501)
        with patch.object(session, "pod_uid", side_effect=["original", "original", "replacement"]), patch.object(
                runner.subprocess, "Popen", side_effect=self.start(process, b"Forwarding from 127.0.0.1:19501 -> 3500\n")):
            with self.assertRaisesRegex(runner.Pending, "identity changed"):
                with session as opened: opened.verify()
        process.terminate.assert_called_once()
        self.assertTrue(session.log.closed)

    def test_interrupt_reaps_tunnel_even_when_term_times_out(self):
        process = Mock(); process.poll.return_value = None
        process.wait.side_effect = [runner.subprocess.TimeoutExpired("kubectl", 5), 0]
        session = runner.PrivateBeaconSession(19501)
        with patch.object(session, "pod_uid", return_value="beacon-uid"), patch.object(
                runner.subprocess, "Popen", side_effect=self.start(process, b"Forwarding from 127.0.0.1:19501 -> 3500\n")):
            with self.assertRaises(KeyboardInterrupt):
                with session: raise KeyboardInterrupt()
        process.terminate.assert_called_once()
        process.kill.assert_called_once()
        self.assertEqual(process.wait.call_count, 2)
        self.assertTrue(session.log.closed)


class ObservationPipeline(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.work = Path(self.temp.name).resolve()
        (self.work / "evidence").mkdir(mode=0o700)
        self.identity = dict(chain_test.IDENTITY)
        self.context = {"identity":self.identity, "aws_account_id":"123456789012", "aws_region":"ap-northeast-2",
                        "reader":{"image":"123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/approved@sha256:" + "a" * 64,
                                  "bucket":"node-audit-123", "prefix":"validator/", "namespace":"validator-observability",
                                  "service_account":"validator-audit-reader", "role_arn":"arn:aws:iam::123456789012:role/audit-reader",
                                  "kms_key_arn":"arn:aws:kms:ap-northeast-2:123456789012:key/11111111-2222-3333-4444-555555555555"}}
        deployment = self.identity["deployment_name"]
        self.context["operational_log_delivery"] = delivery_fixture.fixture_contract("123456789012", "ap-northeast-2", deployment)
        self.context["audit_challenge"] = {"marker_hmac":"hmac-sha256:" + "b" * 64, "after_ms":1,
                                           "request_id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"}
        self.context["vault_security_log_group"] = f"/aws/eks/{deployment}/validator-security"
        self.metadata_present = True
        self.audit_mode, self.audit_calls = "matched", []
        self.epoch, self.role, self.entered, self.closed = 10, "audit-reader", 0, 0
        fixture = archive_test.ArchiveCollection()
        events = []
        for epoch in (10, 11, 12):
            data = {"slot":epoch * 32, "index":0, "beacon_block_root":"0x" + "d" * 64,
                    "source_epoch":epoch - 1, "source_root":"0x" + "1" * 64,
                    "target_epoch":epoch, "target_root":"0x" + "2" * 64}
            root = runner.observer.signing_root(runner.observer.attestation_data_root(data), "0x01020304", "0x" + "3" * 64)
            events.append(fixture.event(f"sign-{epoch}", 2000,
                          f"signing_audit audit_request_id=x-{epoch} result=SUCCESS public_key={self.identity['validator_public_key']} artifact_type=ATTESTATION signing_root={root} slot={epoch * 32} source_epoch={epoch - 1} target_epoch={epoch}"))
        events.append(fixture.fence())
        self.aws = fixture.runner(events)
        self.fetch = chain_test.FinalizedAttestationObserver().fetch()

    def tearDown(self): self.temp.cleanup()

    def beacon(self, port):
        owner = self
        class Beacon:
            url = "http://private.example"
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def verify(self): pass
            def request(self, path, payload=None):
                if path.endswith("syncing"):
                    return {"data":{"is_syncing":False, "is_optimistic":False, "el_offline":False, "head_slot":str(owner.epoch * 32)}}
                epoch = int(path.rsplit("/", 1)[1])
                owner.assertEqual(payload, [owner.identity["validator_index"]])
                return {"execution_optimistic":False, "data":[{"pubkey":owner.identity["validator_public_key"],
                        "validator_index":owner.identity["validator_index"], "committee_index":"0", "committee_length":"1",
                        "committees_at_slot":"1", "validator_committee_index":"0", "slot":str(epoch * 32)}]}
        return Beacon()

    def reader(self, **config):
        owner = self
        # Exercise the real constructor's bounds before substituting Kubernetes.
        # Otherwise an invalid caller timeout can pass every composition fixture.
        runner.ReaderPod(**config)
        class Transport:
            def _exec(self, args):
                timestamp = (runner.registration.HOODI_GENESIS_TIME + int(owner.identity["activation_slot"]) * 12) * 1000 + 1
                if args[:3] == ["aws", "logs", "filter-log-events"]:
                    request = json.loads(args[args.index("--cli-input-json") + 1])
                    owner.assertEqual(args[args.index("--query") + 1], runner.operational_delivery.CW_QUERY)
                    stream = request.get("logStreamNamePrefix", "eni-") + "test"
                    events = [{"event_id":"event-1","timestamp":timestamp,"ingestion_time":timestamp,"stream":stream}] if owner.metadata_present else []
                    return json.dumps({"events":events,"next_token":None}).encode()
                if args[:3] == ["aws", "s3api", "list-objects-v2"]:
                    owner.assertEqual(args[args.index("--query") + 1], runner.operational_delivery.S3_QUERY)
                    key = args[args.index("--prefix") + 1] + "current.gz"
                    return json.dumps({"objects":[{"key":key,"last_modified":datetime.fromtimestamp(timestamp / 1000, timezone.utc).isoformat(),"size":1024}],"truncated":False,"next_token":None}).encode()
                owner.assertEqual(args[:3], ["aws", "sts", "get-caller-identity"])
                owner.assertEqual(args[args.index("--region") + 1], owner.context["aws_region"])
                return json.dumps({"Account":"123456789012", "Arn":f"arn:aws:sts::123456789012:assumed-role/{owner.role}/synthetic"}).encode()
            def __call__(self, args): return owner.aws(args)
        class Reader:
            def __enter__(self): owner.entered += 1; return Transport()
            def __exit__(self, *args): owner.closed += 1
        return Reader()

    def observe(self, required_count=3):
        def actual(*args): return runner.observer.observe(*args, fetch=self.fetch, required_count=required_count)
        return runner.observe_once(self.context, self.work, "https://public.example", 19501, self.beacon, self.reader, actual,
                                   vault_audit_verifier=self.audit)

    def audit(self, transport, bucket, prefix, region, account, group, marker, after_ms, kms, token=None, matches=None):
        self.audit_calls.append((transport, bucket, prefix, region, account, group, marker, after_ms, kms, token, matches))
        self.assertEqual((bucket, prefix, region, account, group, marker, after_ms, kms),
                         ("node-audit-123", "validator/", "ap-northeast-2", "123456789012",
                          self.context["vault_security_log_group"], self.context["audit_challenge"]["marker_hmac"], 1,
                          self.context["reader"]["kms_key_arn"]))
        if self.audit_mode == "pending": return {"state":"pending", "continuation_token":"next", "matches":[]}
        if self.audit_mode == "mismatch": return {"state":"matched", "bucket":bucket, "key":"validator/a.gz", "version_id":"v1", "event_id":"event-1", "request_id":"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", "timestamp_ms":2}
        if self.audit_mode == "unavailable": raise RuntimeError("reader unavailable")
        return {"state":"matched", "bucket":bucket, "key":"validator/a.gz", "version_id":"v1", "event_id":"event-1", "request_id":self.context["audit_challenge"]["request_id"], "timestamp_ms":2}

    def test_two_passes_accumulate_actual_archive_and_canonical_proofs(self):
        rc, first = self.observe()
        self.assertEqual(rc, 75); self.assertEqual(first["consecutive_finalized_epochs"], ["10", "11"])
        self.epoch = 11
        rc, second = self.observe()
        self.assertEqual(rc, 0); self.assertEqual(second["consecutive_finalized_epochs"], ["10", "11", "12"])
        self.assertEqual(second["vault_audit"]["state"], "matched")
        self.assertTrue(hasattr(self.audit_calls[-1][0], "_exec"))
        self.assertEqual((self.entered, self.closed), (2, 2))
        checkpoint = json.loads((self.work / "evidence/observation/finalized-attestation-observer.json").read_text())
        self.assertEqual(len(checkpoint["proofs"]), 3)

    def test_one_explicit_finalized_duty_retains_delivery_and_vault_proof_predicates(self):
        rc, proof = self.observe(required_count=1)
        self.assertEqual(rc, 0)
        self.assertTrue(proof["duties_complete"])
        self.assertEqual(proof["required_finalized_epochs"], 1)
        self.assertEqual(proof["consecutive_finalized_epochs"], ["10", "11"])
        self.assertEqual(proof["operational_log_delivery"]["result"], "PASS_OPERATIONAL_METADATA")
        self.assertEqual(proof["vault_audit"]["state"], "matched")

    def test_wrong_pod_role_is_rejected_and_reader_is_cleaned(self):
        self.role = "wrong-role"
        with self.assertRaises(runner.Pending): self.observe()
        self.assertEqual((self.entered, self.closed), (1, 1))
        self.assertFalse((self.work / "evidence/observation/workload.json").exists())

    def test_unchanged_epoch_snapshot_is_reused(self):
        self.observe()
        path = self.work / "evidence/observation/assignments-10.json"
        before = path.stat().st_mtime_ns
        self.observe()
        self.assertEqual(path.stat().st_mtime_ns, before)

    def test_three_duties_do_not_bypass_missing_operational_metadata(self):
        self.observe(); self.epoch = 11; self.metadata_present = False
        rc, proof = self.observe()
        self.assertEqual(rc, 75)
        self.assertTrue(proof["duties_complete"])
        self.assertEqual(proof["consecutive_finalized_epochs"], ["10", "11", "12"])
        self.assertNotEqual(proof["operational_log_delivery"]["result"], "PASS_OPERATIONAL_METADATA")
        self.metadata_present = True
        rc, proof = self.observe()
        self.assertEqual(rc, 0)
        self.assertEqual(proof["operational_log_delivery"]["result"], "PASS_OPERATIONAL_METADATA")
        self.assertEqual((self.entered, self.closed), (3, 3))

    def test_vault_pending_cursor_blocks_three_finalized_duties_and_persists(self):
        self.observe(); self.epoch = 11; self.audit_mode = "pending"
        rc, proof = self.observe()
        self.assertEqual(rc, 75); self.assertTrue(proof["duties_complete"])
        self.assertEqual(proof["vault_audit"], {"state":"pending", "reason":"archive-correlation-pending"})
        cursor = json.loads((self.work / "evidence/observation/vault-audit-cursor.json").read_text())
        self.assertEqual(cursor["continuation_token"], "next")
        self.assertNotIn(self.context["audit_challenge"]["marker_hmac"], json.dumps(cursor))

    def test_vault_request_id_mismatch_blocks_three_finalized_duties(self):
        self.observe(); self.epoch = 11; self.audit_mode = "mismatch"
        rc, proof = self.observe()
        self.assertEqual(rc, 75); self.assertTrue(proof["duties_complete"])
        self.assertEqual(proof["vault_audit"], {"state":"pending", "reason":"request-id-mismatch"})

    def test_vault_reader_failure_is_pending_not_completion(self):
        self.audit_mode = "unavailable"
        with self.assertRaisesRegex(runner.Pending, "Vault audit archive correlation is unavailable"):
            self.observe()

    def test_missing_validated_audit_context_is_pending_not_completion(self):
        del self.context["audit_challenge"]
        with self.assertRaisesRegex(runner.Pending, "validated Vault audit challenge context is unavailable"):
            self.observe()

    def test_final_beacon_recheck_blocks_available_emission(self):
        emitted, calls = [], []
        def unstable_beacon(port):
            value = self.beacon(port)
            original = value.verify
            def verify():
                calls.append(1)
                if len(calls) == 2: raise runner.Pending("private Beacon identity changed during observation")
                original()
            value.verify = verify
            return value
        with self.assertRaises(runner.Pending):
            runner.observe_once(self.context, self.work, "https://public.example", 19501,
                                unstable_beacon, self.reader,
                                lambda *args: runner.observer.observe(*args, fetch=self.fetch),
                                lambda *args: emitted.append(args), self.audit)
        self.assertEqual(len(calls), 2)
        self.assertEqual(emitted, [])

    def test_continuous_mode_rechecks_after_pass_and_reports_unavailable_fresh_failure(self):
        trusted = {"consecutive_finalized_epochs":["10", "11"], "operational_log_delivery":{"pending":[]}}
        fresh_result = {"schema_version":1, "identity":self.identity | {"private_beacon_url":"http://private.example", "public_beacon_url":"https://public.example", "workload_proof_path":"/safe/workload.json", "log_delivery_proof_path":"/safe/logs.json"}, "consecutive_finalized_epochs":["10"], "required_finalized_epochs":1, "complete":True}
        output = io.StringIO()
        calls = []
        def fresh(*args, **kwargs):
            calls.append(1)
            if len(calls) == 1:
                kwargs["emit_emf"](self.context, fresh_result, True)
                return 0, trusted
            raise runner.Pending("transient")
        with patch.object(runner, "load_context", return_value=self.context), \
             patch.object(runner.observer, "validate_url", return_value="https://public.example"), \
             patch.object(runner, "observe_once", side_effect=fresh) as observed, \
             patch.object(runner.time, "sleep", side_effect=[None, KeyboardInterrupt]), \
             patch.object(runner.sys, "argv", ["runner", "--bundle-root", str(self.work), "--work-dir", str(self.work), "--public-beacon-url", "https://public.example", "--continuous", "--required-finalized-epochs", "1", "--emit-emf"]), \
             patch.dict(os.environ, {"PRIVATE_EKS_SESSION":"1"}, clear=False), contextlib.redirect_stdout(output):
            self.assertEqual(runner.main(), 75)
        self.assertEqual(observed.call_count, 2)
        records = [json.loads(line) for line in output.getvalue().splitlines() if line.strip()]
        states = [record["state"] for record in records if "state" in record]
        self.assertEqual(states, ["verified", "unavailable"])
        verified = next(record for record in records if record.get("state") == "verified")
        self.assertEqual(verified["required_finalized_epochs"], 1)
        self.assertIsInstance(verified["timestamp_ms"], int)
        emf = [record for record in records if "ChainObservationAvailable" in record]
        self.assertEqual([record["ChainObservationAvailable"] for record in emf], [1, 0])
        self.assertTrue(all("validator_public_key" not in record for record in emf))


if __name__ == "__main__": unittest.main()
