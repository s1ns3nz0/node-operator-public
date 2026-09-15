#!/usr/bin/env python3
"""Create, pin, and remove the short-lived validator-audit reader Pod.

This module is deliberately an internal lifecycle boundary.  Its caller owns
the selected ``kubectl`` executable/environment and kubeconfig, has approved
the immutable vault-bootstrap image, and has validated the S3 scope.  It never
applies, adopts, or reuses Pods.  A
``PodAWSTransport`` is yielded only after the created Pod was re-read with its
UID, image, and ServiceAccount intact.
"""
from __future__ import annotations

from contextlib import AbstractContextManager
import importlib.util
import json
from pathlib import Path
import re
import secrets
import subprocess
import time
from typing import Any


_TRANSPORT_PATH = Path(__file__).with_name("validator_audit_pod_transport.py")
_SPEC = importlib.util.spec_from_file_location("validator_audit_pod_transport", _TRANSPORT_PATH)
if _SPEC is None or _SPEC.loader is None:  # pragma: no cover - immutable bundle error
    raise RuntimeError("validator audit transport is unavailable")
_TRANSPORT = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_TRANSPORT)
PodAWSTransport = _TRANSPORT.PodAWSTransport


class ReaderPodError(subprocess.SubprocessError):
    """The reader Pod was not safely created, pinned, or removed."""


_NAMESPACE = "validator-observability"
_SERVICE_ACCOUNT = "validator-audit-reader"
_IMAGE_RE = re.compile(
    r"[0-9]{12}\.dkr\.ecr\.[a-z]{2}(?:-[a-z0-9]+)+-[0-9]+\.amazonaws\.com/"
    r"[a-z0-9][a-z0-9._/-]*@sha256:[a-f0-9]{64}"
)
_REGION_RE = re.compile(r"[a-z]{2}-[a-z0-9-]+-[0-9]+")
_BUCKET_RE = re.compile(r"[a-z0-9][a-z0-9.-]{2,62}")
_UID_RE = re.compile(r"[A-Za-z0-9-]{1,64}")
_MAX_COMMAND_TIMEOUT = 60
_MAX_READY_TIMEOUT = 180
_MAX_ACTIVE_DEADLINE = 600
_CLEANUP_TIMEOUT = 20


def _strict_json(raw: bytes) -> Any:
    def no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result
    return json.loads(raw.decode("utf-8"), object_pairs_hook=no_duplicates)


class ReaderPod(AbstractContextManager[PodAWSTransport]):
    """A create-only, UID-pinned Pod lifecycle for archive reads.

    ``image`` is an immutable selected-account image reference.  Approval of
    that image, and injection of a projected PodIdentity token, remain caller
    responsibilities.  This manifest intentionally disables the default
    Kubernetes API token and contains no AWS credentials.
    """

    def __init__(
        self,
        *,
        image: str,
        bucket: str,
        region: str,
        namespace: str = _NAMESPACE,
        service_account: str = _SERVICE_ACCOUNT,
        prefix: str = "validator/",
        kubectl: str = "kubectl",
        command_timeout: int = 20,
        ready_timeout: int = 90,
        active_deadline: int = 300,
    ):
        if (namespace != _NAMESPACE or service_account != _SERVICE_ACCOUNT
                or not isinstance(image, str) or not _IMAGE_RE.fullmatch(image)
                or not isinstance(bucket, str) or not _BUCKET_RE.fullmatch(bucket)
                or prefix != "validator/" or not isinstance(region, str)
                or not _REGION_RE.fullmatch(region)
                or not isinstance(kubectl, str) or not kubectl or "\x00" in kubectl
                or not isinstance(command_timeout, int) or not 0 < command_timeout <= _MAX_COMMAND_TIMEOUT
                or not isinstance(ready_timeout, int) or not 0 < ready_timeout <= _MAX_READY_TIMEOUT
                or not isinstance(active_deadline, int) or not 0 < active_deadline <= _MAX_ACTIVE_DEADLINE):
            raise ReaderPodError("invalid reader Pod configuration")
        self.image, self.bucket, self.region = image, bucket, region
        self.namespace, self.service_account, self.prefix = namespace, service_account, prefix
        self.kubectl = kubectl
        self.command_timeout, self.ready_timeout, self.active_deadline = command_timeout, ready_timeout, active_deadline
        self.name = "validator-audit-reader-" + secrets.token_hex(8)
        self.uid: str | None = None

    def _manifest(self) -> bytes:
        manifest = {
            "apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": self.name, "namespace": self.namespace,
                         "labels": {"app.kubernetes.io/name": "validator-audit-reader"}},
            "spec": {
                "serviceAccountName": self.service_account,
                "automountServiceAccountToken": False,
                "restartPolicy": "Never",
                "activeDeadlineSeconds": self.active_deadline,
                "terminationGracePeriodSeconds": 0,
                "securityContext": {"runAsNonRoot": True, "runAsUser": 65532,
                                    "runAsGroup": 65532, "seccompProfile": {"type": "RuntimeDefault"}},
                "containers": [{
                    "name": "reader", "image": self.image,
                    "command": ["sh", "-ec", "umask 077; trap 'exit 0' INT TERM; while :; do sleep 60; done"],
                    "securityContext": {"allowPrivilegeEscalation": False,
                                        "readOnlyRootFilesystem": True,
                                        "capabilities": {"drop": ["ALL"]}},
                    "resources": {"requests": {"cpu": "50m", "memory": "64Mi"},
                                  "limits": {"cpu": "250m", "memory": "128Mi"}},
                    "volumeMounts": [{"name": "tmp", "mountPath": "/tmp"}],
                }],
                "volumes": [{"name": "tmp", "emptyDir": {"sizeLimit": "32Mi"}}],
            },
        }
        return json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()

    def _run(self, args: list[str], *, input_data: bytes | None = None, timeout: int | None = None,
             allow_failure: bool = False) -> subprocess.CompletedProcess[bytes]:
        try:
            completed = subprocess.run(
                args, input=input_data, stdin=subprocess.DEVNULL if input_data is None else None,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
                timeout=self.command_timeout if timeout is None else timeout,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise ReaderPodError("reader Pod command failed") from error
        if completed.returncode and not allow_failure:
            raise ReaderPodError("reader Pod command failed")
        return completed

    def _read_live(self, *, require_ready: bool = False) -> dict[str, Any]:
        completed = self._run([self.kubectl, "-n", self.namespace, "get", "pod", self.name, "-o", "json"])
        try:
            pod = _strict_json(completed.stdout)
            metadata, spec = pod["metadata"], pod["spec"]
            containers = spec["containers"]
            uid = metadata["uid"]
            container_security = containers[0].get("securityContext") if isinstance(containers, list) and len(containers) == 1 else None
            pod_security = spec.get("securityContext")
            if (metadata.get("name") != self.name or metadata.get("namespace") != self.namespace
                    or not isinstance(uid, str) or not _UID_RE.fullmatch(uid)
                    or self.uid is not None and uid != self.uid
                    or spec.get("serviceAccountName") != self.service_account
                    or not isinstance(containers, list) or len(containers) != 1
                    or containers[0].get("name") != "reader" or containers[0].get("image") != self.image
                    or spec.get("automountServiceAccountToken") is not False
                    or spec.get("initContainers") not in (None, [])
                    or not isinstance(pod_security, dict) or pod_security.get("runAsNonRoot") is not True
                    or pod_security.get("runAsUser") != 65532 or pod_security.get("runAsGroup") != 65532
                    or not isinstance(container_security, dict)
                    or container_security.get("allowPrivilegeEscalation") is not False
                    or container_security.get("readOnlyRootFilesystem") is not True
                    or container_security.get("capabilities", {}).get("drop") != ["ALL"]):
                raise ValueError("identity mismatch")
            if require_ready:
                conditions = pod.get("status", {}).get("conditions", [])
                if not any(isinstance(item, dict) and item.get("type") == "Ready" and item.get("status") == "True"
                           for item in conditions):
                    raise ValueError("not ready")
            return pod
        except (KeyError, TypeError, ValueError, UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ReaderPodError("reader Pod identity could not be verified") from error

    def _cleanup(self) -> None:
        if self.uid is None:
            return
        options = json.dumps({"apiVersion": "v1", "kind": "DeleteOptions",
                              "preconditions": {"uid": self.uid}}, separators=(",", ":")).encode()
        delete_error: Exception | None = None
        try:
            self._run([self.kubectl, "-n", self.namespace, "delete", "--raw",
                       f"/api/v1/namespaces/{self.namespace}/pods/{self.name}", "-f", "-"], input_data=options)
        except ReaderPodError as error:
            delete_error = error
        deadline = time.monotonic() + _CLEANUP_TIMEOUT
        while True:
            completed = self._run([self.kubectl, "-n", self.namespace, "get", "pod", self.name,
                                   "--ignore-not-found", "-o", "json"], allow_failure=True)
            if completed.returncode != 0:
                raise ReaderPodError("reader Pod cleanup could not be confirmed") from delete_error
            if not completed.stdout.strip():
                return
            try:
                pod = _strict_json(completed.stdout)
                current_uid = pod["metadata"]["uid"]
            except (KeyError, TypeError, ValueError, UnicodeDecodeError, json.JSONDecodeError) as error:
                raise ReaderPodError("reader Pod cleanup could not be confirmed") from error
            if current_uid != self.uid or time.monotonic() >= deadline:
                raise ReaderPodError("reader Pod cleanup could not be confirmed") from delete_error
            time.sleep(0.1)

    def __enter__(self) -> PodAWSTransport:
        try:
            created = self._run([self.kubectl, "-n", self.namespace, "create", "-f", "-", "-o", "json"],
                                input_data=self._manifest())
        except ReaderPodError as error:
            raise ReaderPodError("reader Pod create outcome is ambiguous; cleanup was not attempted") from error
        try:
            pod = _strict_json(created.stdout)
            uid = pod["metadata"]["uid"]
            if (pod["metadata"].get("name") != self.name or pod["metadata"].get("namespace") != self.namespace
                    or not isinstance(uid, str) or not _UID_RE.fullmatch(uid)):
                raise ValueError("ambiguous create")
            self.uid = uid
        except (KeyError, TypeError, ValueError, UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ReaderPodError("reader Pod create outcome is ambiguous; cleanup was not attempted") from error
        try:
            self._read_live()
            self._run([self.kubectl, "-n", self.namespace, "wait", "--for=condition=Ready", f"pod/{self.name}",
                       f"--timeout={self.ready_timeout}s"], timeout=self.ready_timeout + self.command_timeout)
            self._read_live(require_ready=True)
        except BaseException as primary:
            try:
                self._cleanup()
            except ReaderPodError as cleanup_error:
                primary.add_note("reader Pod cleanup was not confirmed: " + str(cleanup_error))
            raise
        return PodAWSTransport(self.namespace, self.name, self.uid, self.bucket, self.prefix, self.region)

    def __exit__(self, exc_type: Any, exc: BaseException | None, traceback: Any) -> bool:
        try:
            self._cleanup()
        except ReaderPodError as cleanup_error:
            if exc is not None:
                exc.add_note("reader Pod cleanup was not confirmed: " + str(cleanup_error))
                return False
            raise
        return False
