#!/usr/bin/env python3
"""Concrete, bounded action bindings for the UC-5 ceremony.

This is intentionally an adapter for ``uc5-ceremony.py``, not a second
orchestrator.  It wires only the reviewed Vault role, fixed Kubernetes
controllers, redacted state collector, and semantic probe service together.
"""
import datetime as dt
import importlib.util
import pathlib
import re
import time


HERE = pathlib.Path(__file__).resolve().parent


def _load(name):
    spec = importlib.util.spec_from_file_location(name, HERE / (name.replace("_", "-") + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


STATE = _load("uc5_runtime_role_state")
KUBE = _load("uc5_kube_state")
GUARDS = _load("uc5_live_guards")
AUDIT = _load("uc5_audit_proof")

UID = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}")
TIMESTAMP = re.compile(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z")


class LiveActionsError(RuntimeError):
    """Fixed, non-sensitive action refusal."""


class LiveActions:
    """The exact action protocol required by :func:`uc5_ceremony.run`.

    ``probe_service`` is deliberately a semantic, finite interface.  It cannot
    be an arbitrary command callback; unavailable probes are rejected during
    construction, before the ceremony can interrupt a workload.
    """
    PROBES = ("preflight", "audit_preflight", "fresh_fence", "history", "wait_signer_absent", "new_signer_identity",
              "confirm_denied_start", "verify_continuity", "audit_chain")

    def __init__(self, evidence_dir, expected_public_key, vault_adapter, control, read_runner,
                 probe_service, now_utc=None, now_epoch=None, sleep=time.sleep):
        if not isinstance(evidence_dir, (str, pathlib.Path)) or not pathlib.Path(evidence_dir).is_absolute():
            raise LiveActionsError("absolute evidence directory required")
        if not isinstance(expected_public_key, str) or KUBE.PUBKEY.fullmatch(expected_public_key) is None:
            raise LiveActionsError("expected public key is malformed")
        if not callable(read_runner):
            raise LiveActionsError("bounded Kubernetes read runner required")
        if any(not callable(getattr(probe_service, method, None)) for method in self.PROBES):
            raise LiveActionsError("required UC5 probe service method is unavailable")
        self.evidence_dir = pathlib.Path(evidence_dir)
        self.expected_public_key = expected_public_key
        self.vault = vault_adapter
        self.control = control
        self.read_runner = read_runner
        self.probes = probe_service
        self.sleep = sleep
        self.now_utc = now_utc or (lambda: dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z"))
        self.now_epoch = now_epoch or (lambda: int(dt.datetime.now(dt.timezone.utc).timestamp()))
        self.snapshot = None
        self.baseline = None
        self.fence_proof = None
        self.before_history = None
        self.delete_started_at = None
        self.restore_finished_at = None
        self.denied_signer = None

    def _checked(self, value, message):
        if value is not True:
            raise LiveActionsError(message)
        return True

    def _lock(self):
        return self._checked(self.control.assert_maintenance_lock(), "maintenance lock is not verified")

    def administrator_ready(self):
        self._checked(self.vault.administrator_ready(), "administrator credential is not ready")
        return self._checked(self.vault.audit_ready(), "Vault audit configuration is not ready")

    def acquire_maintenance_lock(self):
        return self._checked(self.control.acquire_maintenance_lock(), "maintenance lock acquisition is unconfirmed")

    def reconcile_maintenance_lock(self):
        return self.control.reconcile_maintenance_lock()

    def release_owned_maintenance_lock(self):
        return self._checked(self.control.release_owned_maintenance_lock(), "maintenance lock release is unconfirmed")

    def capture_original_role_and_baseline(self):
        self._lock()
        self.snapshot = STATE.capture(self.vault, self.evidence_dir)
        self.baseline = KUBE.collect_baseline(self.read_runner, self.expected_public_key)
        self._checked(self.probes.preflight(self.baseline), "UC5 preflight is not verified")
        self._checked(self.probes.audit_preflight(), "audit readiness is not verified")
        return True

    def ensure_client_fence_quiesced(self):
        if self.baseline is None:
            raise LiveActionsError("UC5 baseline is unavailable")
        self._lock()
        controllers = self.baseline["controllers"]
        self._checked(self.control.set_replicas("fence", controllers["fence"]["uid"], 0), "fence scale-down is unconfirmed")
        self._checked(self.control.set_replicas("client", controllers["client"]["uid"], 0), "client scale-down is unconfirmed")
        # The collector's live shape binds all owned/replacement Pods, including
        # terminating Pods; it is the absence check, not a scale success.
        live = KUBE.collect_live(self.read_runner, self.baseline)
        if live["matching_pods"]["client"] or live["matching_pods"]["fence"]:
            raise LiveActionsError("client or fence owned Pod remains")
        return True

    def prepare_fresh_fence(self):
        if self.baseline is None:
            raise LiveActionsError("UC5 baseline is unavailable")
        self._lock()
        self.fence_proof = self.probes.fresh_fence(self.baseline)
        return True

    def stop_signer_and_verify_absence(self):
        if self.baseline is None:
            raise LiveActionsError("UC5 baseline is unavailable")
        self._lock()
        signer_uid = self.baseline["controllers"]["signer"]["uid"]
        self._checked(self.control.set_replicas("signer", signer_uid, 0), "signer scale-down is unconfirmed")
        self._checked(self.probes.wait_signer_absent(self.baseline), "signer absence is unverified")
        live = KUBE.collect_live(self.read_runner, self.baseline)
        if live["matching_pods"]["signer"]:
            raise LiveActionsError("signer owned Pod remains")
        if self.before_history is None:
            self.before_history = self.probes.history("before")
            if not isinstance(self.before_history, list):
                raise LiveActionsError("UC5 pre-maintenance history is malformed")
        return True

    def verify_immediate_predelete(self):
        if self.baseline is None or self.fence_proof is None:
            raise LiveActionsError("fresh UC5 guards are unavailable")
        self._lock()
        live = KUBE.collect_live(self.read_runner, self.baseline)
        try:
            GUARDS.verify_predelete(self.fence_proof, self.baseline, live, self.now_epoch())
        except Exception as error:
            raise LiveActionsError("immediate UC5 pre-delete guards failed") from error
        return True

    def delete_runtime_role(self):
        if self.snapshot is None:
            raise LiveActionsError("runtime role snapshot is unavailable")
        self._lock()
        stamp = self.now_utc()
        if not isinstance(stamp, str) or TIMESTAMP.fullmatch(stamp) is None:
            raise LiveActionsError("ceremony clock is malformed")
        self.delete_started_at = stamp
        return self._checked(self.vault.delete_runtime_role(self.snapshot), "runtime role deletion is unconfirmed")

    def _fresh_identity(self, value):
        required = {"pod_uid", "pod_ip", "pod_created_at", "deployment_uid", "deployment_generation", "init_blocked"}
        if not isinstance(value, dict) or set(value) != required:
            raise LiveActionsError("fresh signer identity is malformed")
        if (not isinstance(value["pod_uid"], str) or UID.fullmatch(value["pod_uid"]) is None or
                not isinstance(value["deployment_uid"], str) or UID.fullmatch(value["deployment_uid"]) is None or
                not isinstance(value["pod_ip"], str) or not isinstance(value["pod_created_at"], str) or
                TIMESTAMP.fullmatch(value["pod_created_at"]) is None or type(value["deployment_generation"]) is not int or
                value["deployment_generation"] < 1 or value["init_blocked"] is not True):
            raise LiveActionsError("fresh signer identity is malformed")
        return dict(value)

    def prove_new_signer_authentication_denied(self):
        """Start one signer and bind its init-blocked identity to deletion.

        Observe the role-specific denial while the role is still absent and
        the new Pod exists. The complete delete/login/restore audit chain is
        checked separately after restoration.
        """
        if self.baseline is None or self.delete_started_at is None:
            raise LiveActionsError("runtime role deletion is not recorded")
        self._lock()
        signer_uid = self.baseline["controllers"]["signer"]["uid"]
        # Kubernetes creationTimestamp has second precision. Cross the current
        # second after confirmed deletion instead of misordering a new Pod
        # against subsecond Vault audit timestamps.
        self.sleep(1.05)
        self._checked(self.control.set_replicas("signer", signer_uid, 1), "denied signer start is unconfirmed")
        self.denied_signer = self._fresh_identity(self.probes.new_signer_identity(self.baseline, self.delete_started_at))
        self._checked(self.probes.confirm_denied_start(dict(self.denied_signer), self.delete_started_at), "new signer denial is unconfirmed")
        return True

    def restore_exact_runtime_role(self):
        if self.snapshot is None:
            raise LiveActionsError("runtime role snapshot is unavailable")
        self._lock()
        STATE.restore(self.vault, self.snapshot)
        stamp = self.now_utc()
        if not isinstance(stamp, str) or TIMESTAMP.fullmatch(stamp) is None:
            raise LiveActionsError("ceremony clock is malformed")
        self.restore_finished_at = stamp
        return True

    def recover_signer_and_verify_continuity(self):
        if self.baseline is None or self.before_history is None:
            raise LiveActionsError("UC5 recovery inputs are unavailable")
        self._lock()
        signer_uid = self.baseline["controllers"]["signer"]["uid"]
        self.sleep(1.05)
        self._checked(self.control.set_replicas("signer", signer_uid, 1), "restored signer start is unconfirmed")
        return self._checked(self.probes.verify_continuity(self.baseline, self.before_history), "signer continuity is unverified")

    def verify_vault_audit_chain(self):
        if self.denied_signer is None or self.delete_started_at is None or self.restore_finished_at is None:
            raise LiveActionsError("audit binding inputs are unavailable")
        context = {"runtime_role_path": STATE.RUNTIME_ROLE,
                   "role_hmac": self.vault.runtime_role_audit_hash(),
                   **{key: self.denied_signer[key] for key in ("pod_uid", "pod_ip", "pod_created_at", "deployment_uid", "deployment_generation")},
                   "delete_after": self.delete_started_at, "restore_before": self.restore_finished_at}
        self._checked(self.probes.audit_chain(context), "Vault audit chain is unverified")
        return True

    def verify_client_fence_remain_quiesced(self):
        return self.ensure_client_fence_quiesced()

    def revoke_administrator(self):
        return self.vault.revoke_administrator()
