#!/usr/bin/env python3
# Check objective: Verify UC5 Kubernetes mutation controls reject unbounded or unsafe actions.
"""Synthetic-only mutation-boundary tests; no kubectl is invoked."""
import copy
import importlib.util
import json
import pathlib
import unittest

PATH = pathlib.Path(__file__).resolve().parents[2] / "scripts/ops/lib/uc5-kube-control.py"
SPEC = importlib.util.spec_from_file_location("control", PATH)
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)
ID = "00000000-0000-4000-8000-000000000001"


class FakeKube:
    def __init__(self):
        self.lock = None
        self.calls = []
        self.lose_create_response = False
        self.controller = {"metadata": {"name": M.TARGETS["signer"][1], "namespace": M.NS,
                                        "uid": "signer-uid", "resourceVersion": "3"}, "spec": {"replicas": 1}}

    def __call__(self, args, body=None):
        self.calls.append((args, body))
        if "get" in args:
            return copy.deepcopy(self.lock if "configmap" in args else self.controller)
        if args[0] == "create":
            if self.lock is not None: raise M.ControlError("conflict")
            self.lock = copy.deepcopy(body)
            self.lock["metadata"]["uid"] = "lock-uid"
            self.lock["metadata"]["resourceVersion"] = "8"
            if self.lose_create_response: raise M.ControlError("response lost")
            return copy.deepcopy(self.lock)
        if args[0] == "delete":
            assert body["preconditions"]["uid"] == self.lock["metadata"]["uid"]
            assert body["preconditions"]["resourceVersion"] == self.lock["metadata"]["resourceVersion"]
            self.lock = None
            return {}
        if "patch" in args:
            patch = json.loads(args[args.index("-p") + 1])
            assert patch[:3] == [
                {"op": "test", "path": "/metadata/uid", "value": "signer-uid"},
                {"op": "test", "path": "/metadata/resourceVersion", "value": "3"},
                {"op": "test", "path": "/spec/replicas", "value": 1}]
            self.controller["spec"]["replicas"] = patch[3]["value"]
            return copy.deepcopy(self.controller)
        raise AssertionError("unexpected command")


class ControlTests(unittest.TestCase):
    def setUp(self):
        self.kube = FakeKube()
        self.control = M.Control(ID, self.kube)

    def test_owned_lock_and_uid_precondition_cleanup(self):
        self.assertTrue(self.control.acquire_maintenance_lock())
        self.assertTrue(self.control.assert_maintenance_lock())
        self.assertTrue(self.control.release_owned_maintenance_lock())
        self.assertIsNone(self.kube.lock)

    def test_lost_create_response_can_reconcile_owned_lock(self):
        self.kube.lose_create_response = True
        with self.assertRaises(M.ControlError): self.control.acquire_maintenance_lock()
        self.assertEqual(self.control.reconcile_maintenance_lock(), "owned")
        self.assertTrue(self.control.release_owned_maintenance_lock())

    def test_other_marker_is_never_removed(self):
        self.control.acquire_maintenance_lock()
        self.kube.lock["metadata"]["uid"] = "replacement"
        with self.assertRaises(M.ControlError): self.control.release_owned_maintenance_lock()
        self.assertFalse(any(args[0] == "delete" for args, _ in self.kube.calls))

    def test_scale_uses_cas_and_does_not_activate_client_or_fence(self):
        self.control.acquire_maintenance_lock()
        self.assertTrue(self.control.set_replicas("signer", "signer-uid", 0))
        self.assertEqual(self.kube.controller["spec"]["replicas"], 0)
        for target in ("client", "fence", "db"):
            with self.assertRaises(M.ControlError): self.control.set_replicas(target, "uid", 1)
        with self.assertRaises(M.ControlError): self.control.set_replicas("signer", "other-uid", 0)

    def test_no_scale_without_owned_marker(self):
        with self.assertRaises(M.ControlError): self.control.set_replicas("signer", "signer-uid", 0)
        self.assertFalse(any("patch" in args for args, _ in self.kube.calls))


if __name__ == "__main__":
    unittest.main()
