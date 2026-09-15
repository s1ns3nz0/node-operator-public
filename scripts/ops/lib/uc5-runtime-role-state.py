#!/usr/bin/env python3
"""Fail-closed state capture and single-role restoration for Hoodi UC-5.

This module deliberately has no bootstrap, policy, mount, or Kubernetes calls.
The supplied adapter may read the six fixed Vault objects and may write only
``auth/kubernetes/role/hoodi-hoodi-example-runtime``.  Captured data contains the
runtime role's non-secret configuration and hashes of all drift baselines.
"""
import hashlib
import json
import os
import pathlib
import re
import stat

RUNTIME_ROLE = "auth/kubernetes/role/hoodi-hoodi-example-runtime"
RUNTIME_POLICY = "sys/policies/acl/hoodi-hoodi-example-runtime"
DB_ROLE = "auth/kubernetes/role/hoodi-hoodi-example-slashing-db"
DB_POLICY = "sys/policies/acl/hoodi-hoodi-example-slashing-db"
CLIENT_ROLE = "auth/kubernetes/role/hoodi-hoodi-example-client-tls"
CLIENT_POLICY = "sys/policies/acl/hoodi-hoodi-example-client-tls"
BASELINES = (("runtime_policy", "policy", RUNTIME_POLICY),
             ("db_role", "role", DB_ROLE), ("db_policy", "policy", DB_POLICY),
             ("client_role", "role", CLIENT_ROLE), ("client_policy", "policy", CLIENT_POLICY))
ROLE_KEYS = frozenset(("bound_service_account_names", "bound_service_account_namespaces",
                       "bound_service_account_namespace_selector", "audience", "alias_name_source",
                       "token_policies", "token_ttl", "token_max_ttl", "token_explicit_max_ttl",
                       "token_no_default_policy", "token_num_uses", "token_period", "token_type",
                       "token_bound_cidrs"))
REQUIRED_ROLE = {
    "bound_service_account_names": ["validator-remote-signer"],
    "bound_service_account_namespaces": ["validator-operations"],
    "audience": "vault",
    "token_policies": ["hoodi-hoodi-example-runtime"],
    "token_ttl": 300,
    "token_max_ttl": 600,
    "token_no_default_policy": True,
}
# Vault returns these writable fields even when omitted by the reviewed role
# template.  They are deliberately retained in the snapshot and must remain
# their documented defaults; accepting an unknown or non-default field would
# risk replaying a broader role configuration during recovery.
READ_DEFAULTS = {
    "bound_service_account_namespace_selector": "",
    "alias_name_source": "serviceaccount_uid",
    "token_explicit_max_ttl": 0,
    "token_num_uses": 0,
    "token_period": 0,
    "token_type": "default",
    "token_bound_cidrs": [],
}
EXPECTED_ROLE = {**REQUIRED_ROLE, **READ_DEFAULTS}


class StateError(RuntimeError):
    """Fixed, non-sensitive errors suitable for caller evidence."""


def _canonical(value):
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    except (TypeError, ValueError) as error:
        raise StateError("state value is not canonical JSON") from error


def _hash(value):
    return hashlib.sha256(_canonical(value).encode("ascii")).hexdigest()


def _role(value):
    if not isinstance(value, dict) or set(value) != ROLE_KEYS:
        raise StateError("runtime role has unknown, missing, or malformed fields")
    if value != EXPECTED_ROLE:
        raise StateError("runtime role does not match the reviewed fixed configuration")
    if any(type(value[key]) is not int for key in ("token_ttl", "token_max_ttl", "token_explicit_max_ttl", "token_num_uses", "token_period")) or type(value["token_no_default_policy"]) is not bool:
        raise StateError("runtime role field types are invalid")
    return json.loads(_canonical(value))


def _read(adapter, kind, path):
    method = getattr(adapter, "read_" + kind, None)
    if not callable(method):
        raise StateError("adapter does not implement bounded read interface")
    try:
        value = method(path)
    except Exception as error:
        raise StateError("Vault state read failed") from error
    if value is None:
        raise StateError("required Vault state is absent")
    return value


def _baseline(adapter):
    values = {}
    for name, kind, path in BASELINES:
        values[name] = {"path": path, "sha256": _hash(_read(adapter, kind, path))}
    return values


def _safe_destination(directory):
    path = pathlib.Path(directory)
    if not path.is_absolute() or not path.is_dir() or path.is_symlink():
        raise StateError("evidence directory must be an existing non-symlink absolute directory")
    info = path.stat()
    mode = stat.S_IMODE(info.st_mode)
    if mode & 0o022 or info.st_uid != os.getuid():
        raise StateError("evidence directory must be operator-owned and not group or world writable")
    destination = path / "uc5-runtime-role-state.json"
    if destination.exists() or destination.is_symlink():
        raise StateError("exclusive evidence snapshot destination is unavailable")
    return destination, (info.st_dev, info.st_ino)


def capture(adapter, evidence_directory):
    """Capture the reviewed runtime role plus non-target drift hashes once."""
    target = _role(_read(adapter, "role", RUNTIME_ROLE))
    snapshot = {"schema_version": 1, "scope": "UC-5 fixed Hoodi runtime role only",
                "target": {"path": RUNTIME_ROLE, "value": target, "sha256": _hash(target)},
                "baselines": _baseline(adapter)}
    destination, expected_identity = _safe_destination(evidence_directory)
    directory_fd = None
    try:
        directory_fd = os.open(destination.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        info = os.fstat(directory_fd)
        if (info.st_dev, info.st_ino) != expected_identity or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o022:
            raise StateError("evidence directory changed during capture")
        descriptor = os.open(destination.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory_fd)
        with os.fdopen(descriptor, "w", encoding="ascii") as handle:
            json.dump(snapshot, handle, sort_keys=True, separators=(",", ":"))
            handle.write("\n")
    except OSError as error:
        raise StateError("exclusive evidence snapshot publication failed") from error
    finally:
        if directory_fd is not None:
            os.close(directory_fd)
    return snapshot


def _validate_snapshot(snapshot):
    if not isinstance(snapshot, dict) or set(snapshot) != {"schema_version", "scope", "target", "baselines"}:
        raise StateError("snapshot shape is malformed")
    if type(snapshot["schema_version"]) is not int or snapshot["schema_version"] != 1 or snapshot["scope"] != "UC-5 fixed Hoodi runtime role only":
        raise StateError("snapshot version or scope mismatch")
    target = snapshot["target"]
    if not isinstance(target, dict) or set(target) != {"path", "value", "sha256"} or target["path"] != RUNTIME_ROLE:
        raise StateError("snapshot target is malformed")
    value = _role(target["value"])
    if target["sha256"] != _hash(value):
        raise StateError("snapshot target hash mismatch")
    expected = {name for name, _, _ in BASELINES}
    if not isinstance(snapshot["baselines"], dict) or set(snapshot["baselines"]) != expected:
        raise StateError("snapshot baseline set is malformed")
    for name, _, path in BASELINES:
        item = snapshot["baselines"][name]
        if not isinstance(item, dict) or set(item) != {"path", "sha256"} or item["path"] != path:
            raise StateError("snapshot baseline is malformed")
        if not isinstance(item["sha256"], str) or re.fullmatch(r"[0-9a-f]{64}", item["sha256"]) is None:
            raise StateError("snapshot baseline hash is malformed")
    return value


def verify(adapter, snapshot):
    """Reject any non-target policy/role drift before an attempted restore."""
    _validate_snapshot(snapshot)
    for name, kind, path in BASELINES:
        if _hash(_read(adapter, kind, path)) != snapshot["baselines"][name]["sha256"]:
            raise StateError("non-target Vault state drifted; restoration refused")


def restore(adapter, snapshot):
    """Restore only an absent fixed runtime role; never overwrite target drift."""
    target = _validate_snapshot(snapshot)
    verify(adapter, snapshot)
    current = _read_optional_role(adapter, RUNTIME_ROLE)
    if current is not None:
        if _hash(current) != _hash(target):
            raise StateError("target runtime role drifted; restoration refused")
        _role(current)
        return {"restored": False, "state": "already_exact", "sha256": _hash(target)}
    writer = getattr(adapter, "write_role", None)
    if not callable(writer):
        raise StateError("adapter does not implement bounded write interface")
    try:
        writer(RUNTIME_ROLE, target)
    except Exception as error:
        raise StateError("runtime role restoration write failed") from error
    readback = _read(adapter, "role", RUNTIME_ROLE)
    if _hash(readback) != _hash(target):
        raise StateError("runtime role restoration readback mismatch")
    _role(readback)
    verify(adapter, snapshot)
    return {"restored": True, "state": "restored_exact", "sha256": _hash(target)}


def _read_optional_role(adapter, path):
    method = getattr(adapter, "read_role", None)
    if not callable(method):
        raise StateError("adapter does not implement bounded read interface")
    try:
        return method(path)
    except Exception as error:
        raise StateError("Vault state read failed") from error


def load_snapshot(path, *, expected_sha256):
    """Load a protected capture bound to a digest retained outside that file.

The trusted ceremony must retain the original digest in memory or its protected
record. A digest supplied by the same untrusted snapshot is not authentication.
This does not defend against an attacker controlling the operator account.
"""
    candidate = pathlib.Path(path)
    if not candidate.is_absolute() or not isinstance(expected_sha256, str) or re.fullmatch(r"[0-9a-f]{64}", expected_sha256) is None:
        raise StateError("absolute snapshot path and trusted digest required")
    try:
        descriptor = os.open(candidate, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, "r", encoding="ascii") as handle:
            info = os.fstat(handle.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077 or info.st_size > 65536:
                raise StateError("snapshot must be a bounded private operator-owned regular file")
            raw = handle.read(65537)
            if len(raw) > 65536:
                raise StateError("snapshot size limit exceeded")
            snapshot = json.loads(raw)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise StateError("snapshot cannot be loaded") from error
    _validate_snapshot(snapshot)
    if _hash(snapshot) != expected_sha256:
        raise StateError("snapshot does not match trusted ceremony digest")
    return snapshot
