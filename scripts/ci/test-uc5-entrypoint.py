#!/usr/bin/env python3
# Check objective: Verify the UC5 lifecycle entrypoint without credentials or live API access.
"""Offline lifecycle tests; no credentials, CLI processes or live API access."""
import contextlib
import importlib.util
import io
import os
import pathlib
import tempfile
import types
import unittest
from unittest import mock

PATH = pathlib.Path(__file__).resolve().parents[2] / "scripts/ops/run-hoodi-uc5-ceremony.py"
SPEC = importlib.util.spec_from_file_location("entry", PATH)
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)

class EntryTests(unittest.TestCase):
    def setUp(self):
        self.wire = mock.Mock(return_value=(403, None))
        self.api = mock.Mock()
        self.probes = mock.Mock()
        self.constructor = mock.Mock()
        self.constructor.return_value.baseline = None
        self.ceremony = mock.Mock()
        self.modules = {
            "uc5-kube-control": types.SimpleNamespace(Control=mock.Mock(), kubectl=mock.Mock()),
            "uc5-probes": types.SimpleNamespace(ProbeService=mock.Mock(return_value=self.probes)),
            "uc5-audit-reader": types.SimpleNamespace(read_records=mock.Mock()),
            "uc5-beacon-reader": types.SimpleNamespace(read_ready=mock.Mock()),
            "uc5-vault-adapter": types.SimpleNamespace(TunnelTransport=mock.Mock(return_value=self.wire), VaultAdapter=mock.Mock(return_value=self.api), LOOKUP_SELF="auth/token/lookup-self"),
            "uc5-live-actions": types.SimpleNamespace(LiveActions=self.constructor),
            "uc5-ceremony": types.SimpleNamespace(run=self.ceremony),
            "uc5-activation-evidence": M.load("uc5-activation-evidence"),
        }

    def run_main(self, mode, env=None):
        environment = {"PRIVATE_VAULT_SESSION": "1", "UC5_USER_RECOVERY": "1", "VAULT_TOKEN": "synthetic"}
        if env is not None: environment = env
        with mock.patch.dict(os.environ, environment, clear=True), mock.patch.object(M, "load", side_effect=self.modules.__getitem__), \
                mock.patch("sys.argv", [str(PATH), mode, "--evidence-dir", "/synthetic", "--ceremony-dir", "/prior"]), contextlib.redirect_stdout(io.StringIO()):
            return M.main()

    def test_initialization_failure_revokes_and_closes(self):
        self.constructor.side_effect = RuntimeError("synthetic")
        with self.assertRaises(RuntimeError): self.run_main("execute")
        self.api.revoke_administrator.assert_called_once_with()
        self.wire.close.assert_called_once_with()
        self.ceremony.assert_not_called()

    def test_cleanup_confirms_already_revoked_without_second_revoke(self):
        self.assertEqual(self.run_main("cleanup-root"), 0)
        self.wire.assert_called_once_with("GET", "auth/token/lookup-self")
        self.api.revoke_administrator.assert_not_called()
        self.wire.close.assert_called_once_with()

    def test_cleanup_attempts_revocation_when_lookup_not_denied(self):
        self.wire.return_value = (200, {"data": {}})
        self.assertEqual(self.run_main("cleanup-root"), 0)
        self.api.revoke_administrator.assert_called_once_with()

    def test_ambiguous_lookup_still_attempts_scoped_cleanup(self):
        self.wire.return_value = (503, None)
        self.api.revoke_administrator.side_effect = RuntimeError("revocation not confirmed")
        with self.assertRaises(RuntimeError): self.run_main("cleanup-root")
        self.api.revoke_administrator.assert_called_once_with()

    def test_missing_recovery_marker_does_not_construct_transport(self):
        with self.assertRaises(RuntimeError): self.run_main("execute", {"PRIVATE_VAULT_SESSION": "1"})
        self.modules["uc5-vault-adapter"].TunnelTransport.assert_not_called()

    def test_failed_ceremony_is_not_reported_success(self):
        outcome = {"result": "FAILED", "uc5_complete": False}
        self.ceremony.return_value = outcome
        self.assertEqual(self.run_main("execute"), 1)
        self.probes._save.assert_called_once_with("ceremony-outcome.json", outcome)
        self.wire.close.assert_called_once_with()

    def test_evidence_read_refuses_symlinks_and_loose_permissions(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "ceremony-outcome.json"
            path.write_text("{}")
            path.chmod(0o600)
            self.assertEqual(M.read_evidence(directory, path.name), {})
            path.chmod(0o644)
            with self.assertRaises(RuntimeError): M.read_evidence(directory, path.name)
            path.unlink()
            target = pathlib.Path(directory) / "other.json"
            target.write_text("{}")
            path.symlink_to(target)
            with self.assertRaises(OSError): M.read_evidence(directory, path.name)
            with self.assertRaises(RuntimeError): M.read_evidence(directory, "../other.json")

    def activation_fixture(self):
        self.probes._restored_instance = ("00000000-0000-4000-8000-000000000001", "sha256:" + "a" * 64, 0, "2026-09-11T01:00:01Z")
        self.probes.activation_inputs = {"beacon": {"result": "PASS_PRIVATE_BEACON_READY", "validator_public_key": M.VALIDATOR_PUBLIC_IDENTITY, "validator_index": "1559065"},
                    "tls": {"result": "PASS", "layer": "tls+http", "validator_public_key": M.VALIDATOR_PUBLIC_IDENTITY}, "observed_at": "2026-09-11T01:00:02Z"}
        control = self.modules["uc5-kube-control"].Control.return_value
        control.ceremony_id = "00000000-0000-4000-8000-000000000001"
        control.reconcile_maintenance_lock.return_value = "owned"
        data = {"ceremony-outcome.json": {"schema_version": 1, "scope": "UC-5 role revocation and restoration ceremony",
                "result": "PROBE_COMPLETE", "failed_stage": None, "interrupted": False,
                "cleanup": {"administrator": "revoked", "role": "restored_exact", "fenced": "verified", "lock": "released"},
                "uc5_complete": False, "activation_allowed": True, "remaining": "guarded activation"},
                "kubernetes-baseline.json": {"controllers": {"db": {"pvc_uid": "pvc"}}}, "history-before.json": [],
                "continuity-gates.json": {"result": "PASS_CONTINUITY_GATES", "validator_public_key": M.VALIDATOR_PUBLIC_IDENTITY,
                    "activation_performed": False, "uc5_complete": False, "collected_at_utc": "2026-09-11T01:00:02Z",
                    "same_slashing_history": True, "same_pvc_uid": "pvc", "mtls_identity_verified": True, "private_beacon_ready": True,
                    "signer_absent_observed_at": "2026-09-11T01:00:00Z", "signer_instance": list(self.probes._restored_instance)}}
        return control, data

    def test_prepare_activation_has_no_root_or_scale_and_releases_own_marker(self):
        control, data = self.activation_fixture()
        with mock.patch.object(M, "read_evidence", side_effect=lambda _, name: data[name]):
            self.assertEqual(self.run_main("prepare-activation"), 0)
        control.set_replicas.assert_not_called()
        control.release_owned_maintenance_lock.assert_called_once_with()
        self.modules["uc5-vault-adapter"].TunnelTransport.assert_not_called()
        self.assertEqual([call.args[0] for call in self.probes._save.call_args_list],
                         ["private-activation-evidence.json", "signer-activation-evidence.json"])

    def test_prepare_activation_failure_retains_marker(self):
        control, data = self.activation_fixture()
        self.probes.verify_continuity.side_effect = RuntimeError("synthetic cleanup uncertainty")
        with mock.patch.object(M, "read_evidence", side_effect=lambda _, name: data[name]):
            with self.assertRaises(RuntimeError): self.run_main("prepare-activation")
        control.release_owned_maintenance_lock.assert_not_called()
        control.set_replicas.assert_not_called()

    def test_prepare_activation_refuses_unrevoked_root_before_lock(self):
        control, data = self.activation_fixture()
        data["ceremony-outcome.json"]["cleanup"]["administrator"] = "unconfirmed"
        with mock.patch.object(M, "read_evidence", side_effect=lambda _, name: data[name]):
            with self.assertRaises(Exception): self.run_main("prepare-activation")
        control.acquire_maintenance_lock.assert_not_called()

if __name__ == "__main__": unittest.main()
