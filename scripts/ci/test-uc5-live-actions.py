#!/usr/bin/env python3
# Check objective: Verify UC5 ceremony actions bind only to approved concrete operations.
"""Synthetic execution tests for concrete UC5 ceremony action bindings."""
import copy
import importlib.util
import pathlib
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
PATH = ROOT / "scripts/ops/lib/uc5-live-actions.py"
SPEC = importlib.util.spec_from_file_location("actions", PATH)
M = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(M)
CEREMONY_SPEC = importlib.util.spec_from_file_location("ceremony", ROOT / "scripts/ops/lib/uc5-ceremony.py")
CEREMONY = importlib.util.module_from_spec(CEREMONY_SPEC); CEREMONY_SPEC.loader.exec_module(CEREMONY)
KEY = "0x" + "ab" * 48
UUID = "00000000-0000-4000-8000-000000000001"


class Vault:
    def __init__(self): self.role = copy.deepcopy(M.STATE.EXPECTED_ROLE); self.revoked = False
    def administrator_ready(self): return True
    def audit_ready(self): return True
    def read_role(self, path): return copy.deepcopy(self.role) if path == M.STATE.RUNTIME_ROLE else copy.deepcopy(M.STATE.EXPECTED_ROLE)
    def read_policy(self, path): return "synthetic-policy"
    def write_role(self, path, value): self.role = copy.deepcopy(value)
    def delete_runtime_role(self, snapshot): self.role = None; return True
    def runtime_role_audit_hash(self): return "hmac-sha256:" + "a" * 64
    def revoke_administrator(self): self.revoked = True; return "revoked"


class Control:
    def __init__(self): self.replicas = {"client": 0, "fence": 0, "signer": 1}; self.lock = False
    def assert_maintenance_lock(self): return self.lock
    def acquire_maintenance_lock(self): self.lock = True; return True
    def reconcile_maintenance_lock(self): return "owned" if self.lock else "not_owned"
    def release_owned_maintenance_lock(self): self.lock = False; return True
    def set_replicas(self, target, uid, replicas): self.replicas[target] = replicas; return True


class Probes:
    def __init__(self): self.calls = []
    def preflight(self, baseline): self.calls.append("preflight"); return True
    def audit_preflight(self): self.calls.append("audit_preflight"); return True
    def fresh_fence(self, baseline):
        self.calls.append("fresh_fence")
        return {"schema_version": 1, "event_type": "signing-proxy-fence", "collected_at_utc": "2026-09-11T00:00:00Z", "network": "hoodi", "validator_set": "hoodi-example", "validator_public_key": KEY, "source": "signing-proxy-fence", "payload": {"fence_live": True, "lease_enforced": True, "direct_client_to_signer_denied": True, "cached_key_requests_blocked": True, "in_flight_request_bound": True, "fence_live_before_quiesce": True, "client_and_fence_quiesced": True, "direct_probe_pod_uid": "direct", "fence_control_probe_pod_uid": "control", "fence_pod_uid_before_quiesce": "fence-old", "probe_scope": M.GUARDS.PROOF_SCOPE}}
    def history(self, phase): self.calls.append("history:" + phase); return []
    def wait_signer_absent(self, baseline): self.calls.append("wait_signer_absent"); return True
    def new_signer_identity(self, baseline, deleted): self.calls.append("new_signer_identity"); return {"pod_uid": UUID, "pod_ip": "10.0.0.9", "pod_created_at": "2026-09-11T00:00:01Z", "deployment_uid": UUID, "deployment_generation": 4, "init_blocked": True}
    def confirm_denied_start(self, identity, deleted): self.calls.append("confirm_denied_start"); return True
    def verify_continuity(self, baseline, history): self.calls.append("verify_continuity"); return True
    def audit_chain(self, context): self.calls.append("audit_chain"); return True


def runner_factory(control):
    labels = dict(M.KUBE.SIGNER_LABELS)
    def obj(uid, name, spec, status): return {"metadata": {"uid": uid, "name": name, "namespace": M.KUBE.NAMESPACE, "generation": 4}, "spec": spec, "status": status}
    def controller(kind, name, uid, replicas, signer=False):
        containers = [{"name": "web3signer", "image": "registry/signer@sha256:" + "a" * 64}] if signer else [{"name": name, "image": "fixture"}]
        return obj(uid, name, {"replicas": replicas, "template": {"metadata": {"labels": labels if signer else {}}, "spec": {"containers": containers}}}, {"replicas": replicas, "readyReplicas": replicas, "observedGeneration": 4})
    def run(args):
        key = tuple(args)
        named = {("statefulset", "validator-hoodi-example-client"): controller("statefulset", "validator-hoodi-example-client", "client-uid", control.replicas["client"]), ("deployment", "validator-hoodi-example-signing-fence"): controller("deployment", "validator-hoodi-example-signing-fence", "fence-uid", control.replicas["fence"]), ("deployment", "validator-hoodi-example-remote-signer"): controller("deployment", "validator-hoodi-example-remote-signer", "signer-uid", control.replicas["signer"], True), ("statefulset", "validator-hoodi-example-slashing-db"): controller("statefulset", "validator-hoodi-example-slashing-db", "db-uid", 1)}
        if len(key) == 7 and (key[3], key[4]) in named: return named[(key[3], key[4])]
        if len(key) == 7 and key[3] == "pvc": return {"metadata": {"uid": "pvc-uid", "name": M.KUBE.PVC, "namespace": M.KUBE.NAMESPACE}, "status": {"phase": "Bound"}}
        if len(key) == 7 and key[3] == "service":
            selector, target = (M.KUBE.FENCE_LABELS, "fence-proxy") if key[4] == M.KUBE.PUBLIC_SERVICE else (M.KUBE.SIGNER_LABELS, "signer-api")
            return {"metadata": {"uid": key[4], "name": key[4], "namespace": M.KUBE.NAMESPACE}, "spec": {"type": "ClusterIP", "selector": selector, "ports": [{"protocol": "TCP", "port": 9000, "targetPort": target}]}}
        if key[3] == "networkpolicies": return {"items": [{"metadata": {"uid": "policy", "name": M.KUBE.SIGNER_POLICY, "namespace": M.KUBE.NAMESPACE}, "spec": {"podSelector": {"matchLabels": M.KUBE.SIGNER_LABELS}, "policyTypes": ["Ingress"], "ingress": [{"from": [{"podSelector": {"matchLabels": M.KUBE.FENCE_LABELS}}], "ports": [{"protocol": "TCP", "port": 9000}]}]}}]}
        if key[3] in ("replicasets", "pods", "hpa", "applications.argoproj.io", "endpointslices.discovery.k8s.io"): return {"items": []}
        if len(key) == 7 and key[3] == "lease": return {"metadata": {"uid": "lease", "name": M.KUBE.LEASE, "namespace": M.KUBE.NAMESPACE}, "spec": {"holderIdentity": "", "renewTime": "2026-09-10T23:59:00Z", "leaseDurationSeconds": 30}}
        raise AssertionError(key)
    return run


class LiveActionsTests(unittest.TestCase):
    def test_ceremony_runs_real_action_class_with_only_synthetic_dependencies(self):
        with tempfile.TemporaryDirectory() as directory:
            control, vault, probes = Control(), Vault(), Probes()
            actions = M.LiveActions(pathlib.Path(directory), KEY, vault, control, runner_factory(control), probes,
                                    now_utc=iter(["2026-09-11T00:00:00Z", "2026-09-11T00:00:02Z"]).__next__, now_epoch=lambda: 1_789_084_800)
            result = CEREMONY.run(actions)
        self.assertEqual(result["result"], "PROBE_COMPLETE")
        self.assertTrue(vault.revoked)
        self.assertEqual(probes.calls, ["preflight", "audit_preflight", "fresh_fence", "wait_signer_absent", "history:before", "new_signer_identity", "confirm_denied_start", "wait_signer_absent", "verify_continuity", "audit_chain"])
        self.assertTrue(actions.denied_signer["init_blocked"])

    def test_denial_is_observed_while_role_is_absent(self):
        with tempfile.TemporaryDirectory() as directory:
            control, vault, probes = Control(), Vault(), Probes()
            observed = []
            def denial(identity, deleted):
                observed.append(vault.role is None and control.replicas["signer"] == 1)
                return observed[-1]
            probes.confirm_denied_start = denial
            actions = M.LiveActions(pathlib.Path(directory), KEY, vault, control, runner_factory(control), probes,
                                    now_utc=iter(["2026-09-11T00:00:00Z", "2026-09-11T00:00:02Z"]).__next__, now_epoch=lambda: 1_789_084_800)
            result = CEREMONY.run(actions)
        self.assertEqual(observed, [True])
        self.assertEqual(result["result"], "PROBE_COMPLETE")
        self.assertTrue(vault.revoked)

    def test_missing_semantic_probe_is_refused_before_maintenance(self):
        class Missing: pass
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(M.LiveActionsError):
                M.LiveActions(pathlib.Path(directory), KEY, Vault(), Control(), lambda _: {}, Missing())

    def test_unconfirmed_denial_restores_role_and_revokes_root(self):
        with tempfile.TemporaryDirectory() as directory:
            control, vault, probes = Control(), Vault(), Probes()
            probes.confirm_denied_start = lambda *_: False
            actions = M.LiveActions(pathlib.Path(directory), KEY, vault, control, runner_factory(control), probes,
                                    now_utc=iter(["2026-09-11T00:00:00Z", "2026-09-11T00:00:02Z"]).__next__, now_epoch=lambda: 1_789_084_800)
            result = CEREMONY.run(actions)
        self.assertNotEqual(result["result"], "PROBE_COMPLETE")
        self.assertFalse(result["uc5_complete"])
        self.assertEqual(vault.role, M.STATE.EXPECTED_ROLE)
        self.assertTrue(vault.revoked)
        self.assertEqual(control.replicas, {"client": 0, "fence": 0, "signer": 0})

    def test_missing_audit_readiness_stops_before_any_scale_or_role_delete(self):
        with tempfile.TemporaryDirectory() as directory:
            control, vault, probes = Control(), Vault(), Probes()
            def forbidden(*args): raise AssertionError("mutation must not be reached")
            control.set_replicas = forbidden
            vault.delete_runtime_role = forbidden
            probes.audit_preflight = lambda: False
            actions = M.LiveActions(pathlib.Path(directory), KEY, vault, control, runner_factory(control), probes)
            result = CEREMONY.run(actions)
        self.assertNotEqual(result["result"], "PROBE_COMPLETE")
        self.assertEqual(control.replicas, {"client": 0, "fence": 0, "signer": 1})
        self.assertEqual(vault.role, M.STATE.EXPECTED_ROLE)
        self.assertTrue(vault.revoked)
        self.assertFalse(control.lock)


if __name__ == "__main__": unittest.main()
