#!/usr/bin/env python3
# Check objective: Verify bounded UC5 probe interpretation against synthetic Kubernetes responses.
"""Offline tests of actual bounded UC5 Kubernetes probe interpretation."""
import copy
import importlib.util
import json
import pathlib
import stat
import tempfile
import unittest

PATH = pathlib.Path(__file__).resolve().parents[2] / "scripts/ops/lib/uc5-probes.py"
SPEC = importlib.util.spec_from_file_location("probes", PATH)
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)

class Control:
    def assert_maintenance_lock(self): return True

class ProbeTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.baseline = {"controllers": {"signer": {"uid": "deployment"}}}
        self.deployment = {"metadata": {"uid": "deployment", "generation": 8}, "spec": {"replicas": 1}, "status": {"observedGeneration": 8}}
        self.rs = {"metadata": {"uid": "rs", "ownerReferences": [{"kind": "Deployment", "uid": "deployment", "controller": True}]}}
        self.pod = {"metadata": {"uid": "pod", "creationTimestamp": "2026-09-11T01:00:01Z", "ownerReferences": [{"kind": "ReplicaSet", "name": "rs", "uid": "rs", "controller": True}]},
                    "status": {"podIP": "10.80.0.5", "initContainerStatuses": [{"name": "vault-agent-init", "state": {"running": {}}}], "containerStatuses": [{"name": "web3signer", "state": {"waiting": {}}}]}}
        def runner(args, body=None):
            if args[3] == "deployment": return copy.deepcopy(self.deployment)
            if args[3] == "replicaset": return copy.deepcopy(self.rs)
            if args[3] == "pods": return {"items": [copy.deepcopy(self.pod)]}
            raise AssertionError(args)
        self.service = M.ProbeService(Control(), "0x" + "ab" * 48, self.directory.name, runner=runner)
        self.service._quiesced = lambda: True
        self.service.absent_at = "2026-09-11T00:59:59Z"

    def identity(self):
        return self.service.new_signer_identity(self.baseline, "2026-09-11T01:00:00Z")

    def test_fresh_init_blocked_identity(self):
        result = self.identity()
        self.assertEqual(result["deployment_generation"], 8)
        self.assertEqual(result["pod_uid"], "pod")
        self.assertTrue(result["init_blocked"])

    def test_old_pod_refused(self):
        self.pod["metadata"]["creationTimestamp"] = "2026-09-11T00:59:59Z"
        with self.assertRaises(M.ProbeError): self.identity()

    def test_foreign_owner_refused(self):
        self.rs["metadata"]["ownerReferences"][0]["uid"] = "foreign"
        with self.assertRaises(M.ProbeError): self.identity()

    def test_started_signer_refused(self):
        self.pod["status"]["containerStatuses"][0]["state"] = {"running": {}}
        with self.assertRaises(M.ProbeError): self.identity()

    def test_completed_init_refused(self):
        self.pod["status"]["initContainerStatuses"][0]["state"] = {"terminated": {"exitCode": 0}}
        with self.assertRaises(M.ProbeError): self.identity()

    def test_absence_required(self):
        self.service.absent_at = None
        with self.assertRaises(M.ProbeError): self.identity()

    def test_wait_is_bounded(self):
        self.service.clock = iter([0, 1, 3]).__next__
        self.service.sleep = lambda _: None
        with self.assertRaises(M.ProbeError): self.service._wait(lambda: False, 2)

    def test_stop_observation_waits_for_pod_disappearance(self):
        live = {"controllers": {"signer": {"uid": "deployment", "spec_replicas": 0, "status_replicas": 0}}, "matching_pods": {"signer": []}}
        pending = copy.deepcopy(live)
        pending["matching_pods"]["signer"] = ["owned"]
        self.service._live = iter([pending, live]).__next__
        self.service.sleep = lambda _: None
        self.assertTrue(self.service.wait_signer_absent(self.baseline))

    def test_evidence_is_private_and_exclusive(self):
        self.service._save("test.json", {"result": "synthetic"})
        path = pathlib.Path(self.directory.name) / "test.json"
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        with self.assertRaises(FileExistsError): self.service._save("test.json", {})
        with self.assertRaises(M.ProbeError): self.service._save("../escape.json", {})

    def test_evidence_symlink_refused(self):
        target = pathlib.Path(self.directory.name) / "target"
        target.mkdir()
        link = pathlib.Path(self.directory.name) / "link"
        link.symlink_to(target, target_is_directory=True)
        with self.assertRaises(M.ProbeError):
            M.ProbeService(Control(), "0x" + "ab" * 48, link)

    def test_real_audit_matchers_write_only_sanitized_evidence(self):
        fixture_spec = importlib.util.spec_from_file_location("audit_fixture", PATH.parents[2] / "ci/test-uc5-audit-proof.py")
        fixture = importlib.util.module_from_spec(fixture_spec)
        fixture_spec.loader.exec_module(fixture)
        context = fixture.context()
        identity = {k: context[k] for k in ("pod_uid", "pod_ip", "pod_created_at", "deployment_uid", "deployment_generation")}
        identity["init_blocked"] = True
        self.service.audit_hmac_reader = lambda: context["role_hmac"]
        self.service.new_signer_identity = lambda *_: identity
        self.service.audit_reader = lambda *_: fixture.records()[:4]
        original_utc = M.utc
        try:
            M.utc = lambda: fixture.time(7)
            self.assertTrue(self.service.confirm_denied_start(identity, context["delete_after"]))
        finally:
            M.utc = original_utc
        self.service.audit_reader = lambda *_: fixture.records()
        self.assertTrue(self.service.audit_chain(context))
        for filename in ("vault-denial-binding.json", "vault-audit-chain.json"):
            content = (pathlib.Path(self.directory.name) / filename).read_text()
            self.assertNotIn(fixture.SECRET, content)
            self.assertNotIn(context["role_hmac"], content)
            self.assertTrue(json.loads(content)["result"].startswith("PASS_"))

    def test_audit_preflight_requires_recent_paired_records(self):
        ident = "00000000-0000-4000-8000-000000000001"
        def records(*_):
            return [{"type": kind, "time": "2026-09-11T01:00:01Z", "request": {
                "id": ident, "path": "auth/token/lookup-self", "operation": "read", "remote_address": "10.80.0.5"}}
                for kind in ("request", "response")]
        self.service.audit_hmac_reader = lambda: "hmac-sha256:" + "a" * 64
        self.service.audit_reader = records
        original = M.utc
        try:
            M.utc = lambda: "2026-09-11T01:00:05Z"
            self.assertTrue(self.service.audit_preflight())
        finally:
            M.utc = original
        saved = json.loads((pathlib.Path(self.directory.name) / "audit-readiness.json").read_text())
        self.assertEqual(saved["paired_events_observed"], 1)
        self.assertNotIn(ident, str(saved))
        self.assertNotIn("hmac-sha256:", str(saved))

    def test_audit_preflight_missing_ingestion_times_out(self):
        self.service.audit_hmac_reader = lambda: "hmac-sha256:" + "a" * 64
        self.service.audit_reader = lambda *_: []
        self.service.clock = iter([0, 61]).__next__
        with self.assertRaises(M.ProbeError): self.service.audit_preflight()
        self.assertFalse((pathlib.Path(self.directory.name) / "audit-readiness.json").exists())

if __name__ == "__main__": unittest.main()
