#!/usr/bin/env python3
# Check objective: Verify UC5 restores only the bounded signer runtime role state.
"""Contract tests for the UC-5 single-role restoration boundary."""
import importlib.util
import copy
import pathlib
import tempfile
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "scripts/ops/lib/uc5-runtime-role-state.py"
SPEC = importlib.util.spec_from_file_location("uc5_role_state", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def role():
    return {
        "bound_service_account_names": ["validator-remote-signer"],
        "bound_service_account_namespaces": ["validator-operations"],
        "audience": "vault",
        "token_policies": ["hoodi-hoodi-example-runtime"],
        "token_ttl": 300,
        "token_max_ttl": 600,
        "token_no_default_policy": True,
        # Full `vault read auth/kubernetes/role/...` data shape: these are
        # server-supplied defaults omitted from the reviewed write template.
        "bound_service_account_namespace_selector": "",
        "alias_name_source": "serviceaccount_uid",
        "token_explicit_max_ttl": 0,
        "token_num_uses": 0,
        "token_period": 0,
        "token_type": "default",
        "token_bound_cidrs": [],
    }


class FakeVault:
    def __init__(self):
        self.values = {
            MODULE.RUNTIME_ROLE: role(),
            MODULE.RUNTIME_POLICY: "path \"node-operator-runtime/data/validators/hoodi/hoodi-example/runtime/*\" { capabilities = [\"read\"] }",
            MODULE.DB_ROLE: {"bound_service_account_names": ["validator-slashing-db"]},
            MODULE.DB_POLICY: "path \"node-operator-runtime/data/validators/hoodi/hoodi-example/runtime/slashing-db-password\" { capabilities = [\"read\"] }",
            MODULE.CLIENT_ROLE: {"bound_service_account_names": ["validator-client"]},
            MODULE.CLIENT_POLICY: "path \"node-operator-runtime/data/validators/hoodi/hoodi-example/runtime/client-tls\" { capabilities = [\"read\"] }",
        }
        self.writes = []

    def read_role(self, path):
        return None if path not in self.values else self.values[path]

    def read_policy(self, path):
        return None if path not in self.values else self.values[path]

    def write_role(self, path, value):
        self.writes.append((path, value))
        self.values[path] = value


def test_capture_and_restore_only_the_absent_runtime_role():
    api = FakeVault()
    with tempfile.TemporaryDirectory() as temp:
        snapshot = MODULE.capture(api, pathlib.Path(temp))
        assert snapshot["target"]["path"] == MODULE.RUNTIME_ROLE
        assert snapshot["target"]["value"] == role()
        del api.values[MODULE.RUNTIME_ROLE]
        result = MODULE.restore(api, snapshot)
    assert result["restored"] is True
    assert api.writes == [(MODULE.RUNTIME_ROLE, role())]


def snapshot_for(api):
    with tempfile.TemporaryDirectory() as temp:
        return MODULE.capture(api, pathlib.Path(temp))


def rejected(action, message):
    try:
        action()
    except MODULE.StateError:
        return
    raise AssertionError(message)


def test_refuses_target_or_non_target_drift_without_writes():
    api = FakeVault()
    snapshot = snapshot_for(api)
    api.values[MODULE.RUNTIME_ROLE] = dict(role(), audience="unexpected")
    rejected(lambda: MODULE.restore(api, snapshot), "target drift was overwritten")
    assert api.writes == []

    api = FakeVault()
    snapshot = snapshot_for(api)
    del api.values[MODULE.RUNTIME_ROLE]
    api.values[MODULE.DB_POLICY] += "\n# changed"
    rejected(lambda: MODULE.restore(api, snapshot), "non-target policy drift was ignored")
    assert api.writes == []


def test_rejects_unknown_target_fields_and_restore_write_or_readback_failure():
    api = FakeVault()
    api.values[MODULE.RUNTIME_ROLE]["server_field"] = "unexpected"
    with tempfile.TemporaryDirectory() as temp:
        rejected(lambda: MODULE.capture(api, pathlib.Path(temp)), "unknown role field was accepted")

    class WriteFailure(FakeVault):
        def write_role(self, path, value):
            self.writes.append((path, value))
            raise OSError("transport")

    api = WriteFailure()
    snapshot = snapshot_for(api)
    del api.values[MODULE.RUNTIME_ROLE]
    rejected(lambda: MODULE.restore(api, snapshot), "failed target write was accepted")
    assert api.writes == [(MODULE.RUNTIME_ROLE, role())]

    api = FakeVault()
    api.values[MODULE.RUNTIME_ROLE]["token_type"] = "batch"
    with tempfile.TemporaryDirectory() as temp:
        rejected(lambda: MODULE.capture(api, pathlib.Path(temp)), "non-default server field was accepted")

    class BadReadback(FakeVault):
        def write_role(self, path, value):
            self.writes.append((path, value))
            self.values[path] = dict(value, audience="wrong")

    api = BadReadback()
    snapshot = snapshot_for(api)
    del api.values[MODULE.RUNTIME_ROLE]
    rejected(lambda: MODULE.restore(api, snapshot), "bad target readback was accepted")
    assert api.writes == [(MODULE.RUNTIME_ROLE, role())]


def test_capture_refuses_nonexclusive_or_unsafe_evidence_destination():
    api = FakeVault()
    with tempfile.TemporaryDirectory() as temp:
        directory = pathlib.Path(temp)
        MODULE.capture(api, directory)
        rejected(lambda: MODULE.capture(api, directory), "existing snapshot was overwritten")
    rejected(lambda: MODULE.capture(FakeVault(), pathlib.Path("relative")), "relative evidence path accepted")


def test_strict_types_and_snapshot_tampering_are_rejected():
    for field, value in (("token_ttl", 300.0), ("token_period", False),
                         ("token_no_default_policy", 1)):
        api = FakeVault()
        api.values[MODULE.RUNTIME_ROLE][field] = value
        with tempfile.TemporaryDirectory() as temp:
            rejected(lambda: MODULE.capture(api, pathlib.Path(temp)), "coerced role type accepted")
        assert api.writes == []
    api = FakeVault()
    original = snapshot_for(api)
    mutations = [
        ("schema_version", True),
        ("scope", "another role"),
    ]
    for field, value in mutations:
        snapshot = copy.deepcopy(original)
        snapshot[field] = value
        rejected(lambda: MODULE.restore(api, snapshot), "tampered snapshot accepted")
    snapshot = copy.deepcopy(original)
    snapshot["baselines"]["db_role"]["sha256"] = "G" * 64
    rejected(lambda: MODULE.restore(api, snapshot), "malformed digest accepted")
    assert api.writes == []


def test_restore_detects_non_target_drift_during_write():
    class ConcurrentDrift(FakeVault):
        def write_role(self, path, value):
            super().write_role(path, value)
            self.values[MODULE.DB_POLICY] += "\n# concurrent change"

    api = ConcurrentDrift()
    snapshot = snapshot_for(api)
    del api.values[MODULE.RUNTIME_ROLE]
    rejected(lambda: MODULE.restore(api, snapshot), "post-write drift was reported as success")
    assert api.writes == [(MODULE.RUNTIME_ROLE, role())]
    assert api.values[MODULE.RUNTIME_ROLE] == role()


def test_snapshot_load_requires_private_file_and_external_digest():
    with tempfile.TemporaryDirectory() as temp:
        directory = pathlib.Path(temp)
        snapshot = MODULE.capture(FakeVault(), directory)
        path = directory / "uc5-runtime-role-state.json"
        digest = MODULE._hash(snapshot)
        assert MODULE.load_snapshot(path, expected_sha256=digest) == snapshot
        rejected(lambda: MODULE.load_snapshot(path, expected_sha256="0" * 64), "unbound capture accepted")
        alias = directory / "alias.json"
        alias.symlink_to(path)
        rejected(lambda: MODULE.load_snapshot(alias, expected_sha256=digest), "symlink capture accepted")
        path.chmod(0o644)
        rejected(lambda: MODULE.load_snapshot(path, expected_sha256=digest), "public capture accepted")


def test_directory_swap_cannot_redirect_snapshot_publication():
    with tempfile.TemporaryDirectory() as temp:
        root = pathlib.Path(temp)
        target = root / "target"; target.mkdir(mode=0o700)
        displaced = root / "displaced"
        actual_open = MODULE.os.open
        swapped = False
        def racing_open(path, flags, *args, **kwargs):
            nonlocal swapped
            if flags & MODULE.os.O_DIRECTORY and not swapped:
                swapped = True
                target.rename(displaced)
                target.mkdir(mode=0o700)
            return actual_open(path, flags, *args, **kwargs)
        with mock.patch.object(MODULE.os, "open", side_effect=racing_open):
            rejected(lambda: MODULE.capture(FakeVault(), target), "replacement directory accepted")
        assert not (target / "uc5-runtime-role-state.json").exists()
        assert not (displaced / "uc5-runtime-role-state.json").exists()


if __name__ == "__main__":
    test_capture_and_restore_only_the_absent_runtime_role()
    test_refuses_target_or_non_target_drift_without_writes()
    test_rejects_unknown_target_fields_and_restore_write_or_readback_failure()
    test_capture_refuses_nonexclusive_or_unsafe_evidence_destination()
    test_strict_types_and_snapshot_tampering_are_rejected()
    test_restore_detects_non_target_drift_during_write()
    test_snapshot_load_requires_private_file_and_external_digest()
    test_directory_swap_cannot_redirect_snapshot_publication()
    print("PASS uc5 runtime role state")
