#!/usr/bin/env python3
"""Fixed UC-5 maintenance marker and UID/resourceVersion-scoped replica writes.

No Secret access or workload-template changes. The marker coordinates cooperating
ceremonies only, not unrelated administrators. Callers must prove Pod absence
and fresh pre-delete guards separately; replicas alone do not prove quiescence.
"""
import json
import re
import subprocess

NS = "validator-operations"
LOCK = "uc5-hoodi-example-maintenance"
OWNER = "node-operator.io/ceremony-id"
TARGETS = {"client": ("statefulset", "validator-hoodi-example-client"),
           "fence": ("deployment", "validator-hoodi-example-signing-fence"),
           "signer": ("deployment", "validator-hoodi-example-remote-signer")}


class ControlError(RuntimeError):
    pass


def kubectl(args, body=None):
    try:
        result = subprocess.run(["kubectl", "--request-timeout=20s", *args],
                                input=None if body is None else json.dumps(body),
                                text=True, capture_output=True, timeout=25)
        if result.returncode or len(result.stdout) > 1048576:
            raise ControlError("scoped Kubernetes operation failed")
        return json.loads(result.stdout) if result.stdout.strip() else None
    except ControlError:
        raise
    except Exception:
        raise ControlError("scoped Kubernetes outcome unconfirmed") from None


class Control:
    def __init__(self, ceremony_id, runner=kubectl):
        if not isinstance(ceremony_id, str) or re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", ceremony_id) is None:
            raise ControlError("unique ceremony identifier required")
        self.ceremony_id = ceremony_id
        self.runner = runner
        self.lock_uid = None

    def _lock(self):
        return self.runner(["-n", NS, "get", "configmap", LOCK, "--ignore-not-found", "-o", "json"])

    def _owned(self, value):
        if not isinstance(value, dict): return False
        metadata = value.get("metadata", {})
        return (metadata.get("name") == LOCK and metadata.get("namespace") == NS and
                metadata.get("annotations", {}).get(OWNER) == self.ceremony_id and
                isinstance(metadata.get("uid"), str) and bool(metadata["uid"]) and
                isinstance(metadata.get("resourceVersion"), str) and bool(metadata["resourceVersion"]) and
                metadata.get("deletionTimestamp") is None)

    def acquire_maintenance_lock(self):
        if self._lock() is not None:
            raise ControlError("maintenance marker already exists")
        manifest = {"apiVersion": "v1", "kind": "ConfigMap",
                    "metadata": {"name": LOCK, "namespace": NS,
                                 "annotations": {OWNER: self.ceremony_id}},
                    "data": {"scope": "UC-5 hoodi-example; do not activate during ceremony"}}
        # No apply/overwrite; on ambiguous create the orchestrator reconciles.
        self.runner(["create", "-f", "-", "-o", "json"], manifest)
        value = self._lock()
        if not self._owned(value): raise ControlError("created maintenance marker not verified")
        self.lock_uid = value["metadata"]["uid"]
        return True

    def reconcile_maintenance_lock(self):
        value = self._lock()
        if value is None: return "not_owned"
        if not self._owned(value):
            raise ControlError("maintenance marker ownership cannot be confirmed")
        self.lock_uid = value["metadata"]["uid"]
        return "owned"

    def assert_maintenance_lock(self):
        value = self._lock()
        if not self._owned(value) or value["metadata"]["uid"] != self.lock_uid:
            raise ControlError("maintenance marker changed")
        return True

    def release_owned_maintenance_lock(self):
        value = self._lock()
        if value is None: return True
        if not self._owned(value) or value["metadata"]["uid"] != self.lock_uid:
            raise ControlError("refusing to remove another maintenance marker")
        options = {"apiVersion": "v1", "kind": "DeleteOptions",
                   "preconditions": {"uid": self.lock_uid,
                                     "resourceVersion": value["metadata"]["resourceVersion"]}}
        self.runner(["delete", "--raw", f"/api/v1/namespaces/{NS}/configmaps/{LOCK}", "-f", "-"], options)
        if self._lock() is not None:
            raise ControlError("maintenance marker removal unconfirmed")
        return True

    def set_replicas(self, target, expected_uid, replicas):
        if target not in TARGETS or type(replicas) is not int or replicas not in (0, 1):
            raise ControlError("replica change outside fixed UC-5 boundary")
        # Client/Fence restart belongs exclusively to the later activation gate.
        if replicas == 1 and target != "signer":
            raise ControlError("client and fence activation is not allowed here")
        self.assert_maintenance_lock()
        kind, name = TARGETS[target]
        args = ["-n", NS, "get", kind, name, "-o", "json"]
        current = self.runner(args)
        metadata = current.get("metadata", {}) if isinstance(current, dict) else {}
        old = current.get("spec", {}).get("replicas") if isinstance(current, dict) else None
        rv = metadata.get("resourceVersion")
        if (metadata.get("uid") != expected_uid or metadata.get("name") != name or
                metadata.get("namespace") != NS or metadata.get("deletionTimestamp") is not None or
                not isinstance(rv, str) or not rv or type(old) is not int or old not in (0, 1)):
            raise ControlError("controller identity or replica baseline changed")
        if old == replicas: return True
        patch = [{"op": "test", "path": "/metadata/uid", "value": expected_uid},
                 {"op": "test", "path": "/metadata/resourceVersion", "value": rv},
                 {"op": "test", "path": "/spec/replicas", "value": old},
                 {"op": "replace", "path": "/spec/replicas", "value": replicas}]
        self.runner(["-n", NS, "patch", kind, name, "--type=json", "-p", json.dumps(patch), "-o", "json"])
        after = self.runner(args)
        if after.get("metadata", {}).get("uid") != expected_uid or after.get("spec", {}).get("replicas") != replicas:
            raise ControlError("replica readback unconfirmed")
        return True
