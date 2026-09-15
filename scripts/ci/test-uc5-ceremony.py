#!/usr/bin/env python3
# Check objective: Verify every UC5 ceremony transition rejects unsafe failure paths.
"""Failure-injection tests for every ceremony transition; no live APIs."""
import importlib.util
import pathlib
import unittest

PATH = pathlib.Path(__file__).resolve().parents[2] / "scripts/ops/lib/uc5-ceremony.py"
SPEC = importlib.util.spec_from_file_location("ceremony", PATH)
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)
ORDER = ["administrator_ready", "acquire_maintenance_lock", "capture_original_role_and_baseline",
         "prepare_fresh_fence", "stop_signer_and_verify_absence", "verify_immediate_predelete",
         "delete_runtime_role", "prove_new_signer_authentication_denied", "stop_signer_and_verify_absence",
         "restore_exact_runtime_role", "recover_signer_and_verify_continuity", "verify_vault_audit_chain",
         "verify_client_fence_remain_quiesced"]


class Actions:
    def __init__(self, fail_at=None, fail_cleanup=()):
        self.calls = []
        self.fail_at = fail_at
        self.fail_cleanup = fail_cleanup
        self.failed = False

    def __getattr__(self, name):
        def action():
            index = len(self.calls)
            self.calls.append(name)
            if index == self.fail_at or (self.failed and name in self.fail_cleanup):
                self.failed = True
                raise RuntimeError("sensitive simulated response must not escape")
            if name == "revoke_administrator": return "revoked"
            if name == "reconcile_maintenance_lock": return "not_owned"
            return True
        return action


class CeremonyTests(unittest.TestCase):
    def test_ordered_success_is_not_full_uc5_completion(self):
        actions = Actions()
        result = M.run(actions)
        self.assertEqual(actions.calls, ORDER + ["revoke_administrator", "release_owned_maintenance_lock"])
        self.assertEqual(result["result"], "PROBE_COMPLETE")
        self.assertFalse(result["uc5_complete"])
        self.assertTrue(result["activation_allowed"])

    def test_each_failure_is_incomplete_and_revokes_administrator(self):
        for index in range(len(ORDER)):
            with self.subTest(stage=ORDER[index], index=index):
                actions = Actions(fail_at=index)
                result = M.run(actions)
                self.assertEqual(result["result"], "INCOMPLETE")
                self.assertFalse(result["activation_allowed"])
                self.assertIn("revoke_administrator", actions.calls)
                self.assertNotIn("sensitive", str(result))
                if index >= ORDER.index("prepare_fresh_fence"):
                    self.assertIn("ensure_client_fence_quiesced", actions.calls)
                if index >= ORDER.index("delete_runtime_role"):
                    self.assertIn("restore_exact_runtime_role", actions.calls)
                if index < ORDER.index("prepare_fresh_fence"):
                    self.assertNotIn("ensure_client_fence_quiesced", actions.calls)

    def test_lost_delete_response_restores_before_root_revocation(self):
        actions = Actions(fail_at=ORDER.index("delete_runtime_role"))
        result = M.run(actions)
        self.assertEqual(result["cleanup"]["role"], "restored_exact")
        self.assertLess(actions.calls.index("restore_exact_runtime_role"), actions.calls.index("revoke_administrator"))

    def test_failed_restore_still_attempts_root_cleanup_and_retains_lock(self):
        actions = Actions(fail_at=ORDER.index("delete_runtime_role"), fail_cleanup=("restore_exact_runtime_role",))
        result = M.run(actions)
        self.assertEqual(result["cleanup"]["role"], "unconfirmed")
        self.assertEqual(result["cleanup"]["administrator"], "revoked")
        self.assertEqual(result["cleanup"]["lock"], "retained_for_recovery")
        self.assertNotIn("release_owned_maintenance_lock", actions.calls)

    def test_failed_root_cleanup_never_allows_activation(self):
        actions = Actions(fail_at=len(ORDER))
        result = M.run(actions)
        self.assertFalse(result["activation_allowed"])
        self.assertEqual(result["cleanup"]["administrator"], "unconfirmed")

    def test_non_boolean_success_is_rejected(self):
        actions = Actions()
        actions.verify_immediate_predelete = lambda: 1
        result = M.run(actions)
        self.assertEqual(result["failed_stage"], "verify_immediate_predelete")
        self.assertNotIn("delete_runtime_role", actions.calls)

    def test_ambiguous_lock_creation_is_reconciled(self):
        actions = Actions(fail_at=1)
        actions.reconcile_maintenance_lock = lambda: "owned"
        result = M.run(actions)
        self.assertEqual(result["result"], "INCOMPLETE")
        self.assertEqual(result["cleanup"]["lock"], "released")
        self.assertIn("release_owned_maintenance_lock", actions.calls)
        actions = Actions(fail_at=1)
        actions.reconcile_maintenance_lock = lambda: "unknown"
        result = M.run(actions)
        self.assertEqual(result["cleanup"]["lock"], "unconfirmed")
        self.assertFalse(result["activation_allowed"])

    def test_interrupt_has_explicit_incomplete_outcome_and_cleanup(self):
        actions = Actions()
        def interrupt(): raise KeyboardInterrupt()
        actions.prepare_fresh_fence = interrupt
        result = M.run(actions)
        self.assertTrue(result["interrupted"])
        self.assertEqual(result["result"], "INCOMPLETE")
        self.assertIn("ensure_client_fence_quiesced", actions.calls)
        self.assertIn("revoke_administrator", actions.calls)


if __name__ == "__main__":
    unittest.main()
