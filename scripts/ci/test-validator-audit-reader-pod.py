#!/usr/bin/env python3
# Check objective: Validate the audit reader Pod lifecycle with synthetic kubectl.
"""Synthetic-kubectl lifecycle coverage for the audit reader Pod."""
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("reader_pod", ROOT / "scripts/release/validator_audit_reader_pod.py")
reader_pod = importlib.util.module_from_spec(spec); sys.modules[spec.name] = reader_pod; spec.loader.exec_module(reader_pod)

IMAGE = "123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/node-operator-vault-bootstrap@sha256:" + "a" * 64


class ReaderPodLifecycleTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.state, self.log, self.manifest = self.base / "state.json", self.base / "log", self.base / "manifest.json"
        self.kubectl = self.base / "kubectl"
        self.kubectl.write_text("#!" + sys.executable + r'''
import json, os, pathlib, sys, time
root = pathlib.Path(os.environ["READER_FAKE_ROOT"]); state = root / "state.json"; log = root / "log"
args = sys.argv[1:]; mode = os.environ.get("READER_FAKE_MODE", "ok")
log.open("a").write(json.dumps(args) + "\n")
def load(): return json.loads(state.read_text()) if state.exists() else None
def save(value): state.write_text(json.dumps(value))
def pod(value, ready=True):
    spec=value["spec"]
    if mode == "mutated-security":
        spec={**spec, "containers":[{**spec["containers"][0], "securityContext":{**spec["containers"][0]["securityContext"], "readOnlyRootFilesystem":False}}]}
    return {"metadata":{"name":value["name"],"namespace":"validator-observability","uid":value["uid"]},"spec":spec,"status":{"conditions":[{"type":"Ready","status":"True" if ready else "False"}]}}
if "create" in args:
    raw = sys.stdin.buffer.read(); (root / "manifest.json").write_bytes(raw)
    if mode == "ambiguous": print("{}", end=""); raise SystemExit(0)
    if mode == "create-timeout": time.sleep(3); raise SystemExit(0)
    data = json.loads(raw); value={"name":data["metadata"]["name"],"uid":"uid-1","image":data["spec"]["containers"][0]["image"],"spec":data["spec"]}; save(value)
    print(json.dumps(pod(value))); raise SystemExit(0)
if "wait" in args:
    if mode == "wait-fail": print("not ready", file=sys.stderr); raise SystemExit(1)
    raise SystemExit(0)
if "delete" in args:
    value=load(); options=json.loads(sys.stdin.read()); (root / "delete-options.json").write_text(json.dumps(options))
    if value and mode in ("replacement", "cleanup-replacement"): save({**value,"uid":"replacement-uid"})
    if value and mode == "delayed-delete":
        save({**value,"delete_reads":2}); print("{}"); raise SystemExit(0)
    value=load()
    if value and options.get("preconditions",{}).get("uid") == value["uid"]: state.unlink(); print("{}")
    else: print("Conflict", file=sys.stderr); raise SystemExit(1)
    raise SystemExit(0)
if "get" in args:
    value=load()
    if mode == "cleanup-auth" and (root / "delete-options.json").exists(): print("Forbidden", file=sys.stderr); raise SystemExit(1)
    if value and value.get("delete_reads"):
        remaining=value["delete_reads"]-1
        if remaining: save({**value,"delete_reads":remaining})
        else: state.unlink()
    value=load()
    if not value:
        if "--ignore-not-found" in args: raise SystemExit(0)
        print("Error from server (NotFound)", file=sys.stderr); raise SystemExit(1)
    if mode == "replacement": value={**value,"uid":"replacement-uid"}
    print(json.dumps(pod(value))); raise SystemExit(0)
print("unsupported", file=sys.stderr); raise SystemExit(2)
''')
        self.kubectl.chmod(0o700)
        self.old_env = os.environ.copy()
        os.environ.update({"READER_FAKE_ROOT": str(self.base), "READER_FAKE_MODE": "ok"})

    def tearDown(self):
        os.environ.clear(); os.environ.update(self.old_env)
        self.temp.cleanup()

    def lifecycle(self, **extra):
        options = {"image": IMAGE, "bucket": "node-audit-123", "region": "ap-northeast-2",
                   "kubectl": str(self.kubectl), "command_timeout": 2, "ready_timeout": 2}
        options.update(extra)
        return reader_pod.ReaderPod(**options)

    def calls(self):
        return [json.loads(line) for line in self.log.read_text().splitlines()] if self.log.exists() else []

    def test_creates_hardened_pinned_pod_and_uid_precondition_deletes_it(self):
        with self.lifecycle() as transport:
            self.assertIsInstance(transport, reader_pod.PodAWSTransport)
            self.assertEqual(transport.namespace, "validator-observability")
            self.assertEqual(transport.bucket, "node-audit-123")
            self.assertTrue(self.state.exists())
        self.assertFalse(self.state.exists())
        manifest = json.loads(self.manifest.read_text())
        spec = manifest["spec"]; container = spec["containers"][0]
        self.assertFalse(spec["automountServiceAccountToken"])
        self.assertEqual(spec["serviceAccountName"], "validator-audit-reader")
        self.assertEqual(spec["securityContext"]["runAsUser"], 65532)
        self.assertTrue(container["securityContext"]["readOnlyRootFilesystem"])
        self.assertEqual(container["securityContext"]["capabilities"]["drop"], ["ALL"])
        self.assertEqual(spec["volumes"], [{"name": "tmp", "emptyDir": {"sizeLimit": "32Mi"}}])
        self.assertNotIn("python", " ".join(container["command"]).lower())
        delete = next(call for call in self.calls() if "delete" in call)
        self.assertIn("--raw", delete)
        self.assertEqual(json.loads((self.base / "delete-options.json").read_text())["preconditions"]["uid"], "uid-1")
        self.assertFalse(any("apply" in call for call in self.calls()))

    def test_ambiguous_create_never_claims_or_attempts_cleanup(self):
        os.environ["READER_FAKE_MODE"] = "ambiguous"
        with self.assertRaisesRegex(reader_pod.ReaderPodError, "ambiguous; cleanup was not attempted"):
            with self.lifecycle(): pass
        self.assertFalse(any("delete" in call for call in self.calls()))

    def test_create_timeout_never_claims_or_attempts_cleanup(self):
        os.environ["READER_FAKE_MODE"] = "create-timeout"
        with self.assertRaisesRegex(reader_pod.ReaderPodError, "ambiguous; cleanup was not attempted"):
            with self.lifecycle(command_timeout=1): pass
        self.assertFalse(any("delete" in call for call in self.calls()))

    def test_wait_failure_removes_owned_pod_before_propagating_failure(self):
        os.environ["READER_FAKE_MODE"] = "wait-fail"
        with self.assertRaises(reader_pod.ReaderPodError):
            with self.lifecycle(): pass
        self.assertFalse(self.state.exists())
        self.assertTrue(any("delete" in call for call in self.calls()))

    def test_delayed_delete_is_polled_to_confirm_terminal_absence(self):
        os.environ["READER_FAKE_MODE"] = "delayed-delete"
        with self.lifecycle(): pass
        self.assertFalse(self.state.exists())
        self.assertGreaterEqual(sum("--ignore-not-found" in call for call in self.calls()), 2)

    def test_replacement_is_never_deleted_or_reported_clean(self):
        os.environ["READER_FAKE_MODE"] = "replacement"
        with self.assertRaisesRegex(reader_pod.ReaderPodError, "identity could not be verified"):
            with self.lifecycle(): pass
        self.assertTrue(self.state.exists())
        self.assertTrue(any("delete" in call for call in self.calls()))

    def test_cleanup_replacement_or_auth_failure_is_not_reported_clean(self):
        for mode in ("cleanup-replacement", "cleanup-auth"):
            with self.subTest(mode=mode):
                os.environ["READER_FAKE_MODE"] = mode
                with self.assertRaisesRegex(reader_pod.ReaderPodError, "cleanup could not be confirmed"):
                    with self.lifecycle(): pass
                self.assertTrue(any("delete" in call for call in self.calls()))
                self.log.unlink(missing_ok=True); self.state.unlink(missing_ok=True)
                (self.base / "delete-options.json").unlink(missing_ok=True)

    def test_live_security_mutation_is_rejected_and_owned_pod_is_removed(self):
        os.environ["READER_FAKE_MODE"] = "mutated-security"
        with self.assertRaisesRegex(reader_pod.ReaderPodError, "identity could not be verified"):
            with self.lifecycle(): pass
        self.assertFalse(self.state.exists())

    def test_rejects_unpinned_image_or_wrong_identity_before_subprocess(self):
        with self.assertRaises(reader_pod.ReaderPodError):
            self.lifecycle(image="repo:latest")
        with self.assertRaises(reader_pod.ReaderPodError):
            self.lifecycle(namespace="default")
        with self.assertRaises(reader_pod.ReaderPodError):
            self.lifecycle(active_deadline=601)
        self.assertFalse(self.log.exists())


if __name__ == "__main__":
    unittest.main()
