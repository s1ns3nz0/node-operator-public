#!/usr/bin/env python3
"""UC-5 ordered ceremony with explicit recovery on ambiguous mutation failures.

The concrete actions own API validation, a single-writer maintenance lock,
bounded timeouts and independently collected evidence. No raw action result or
exception is copied into the outcome. This module never activates a validator;
activation and post-recovery canonical duty proof are separate required steps.
"""


class CeremonyError(RuntimeError):
    pass


def _verified(value):
    if value is not True:
        raise CeremonyError("action did not return a verified result")


def run(actions):
    """Run after interactive administrator acquisition, before any fencing.

Required action methods must raise on unknown outcomes, not return success
merely because a command exited zero. Cleanup methods are deliberately separate
from success evidence. Root revocation is attempted even after an earlier
cleanup failure. Recovery never calls a full Vault bootstrap.

The single-writer lock coordinates cooperating tools, not unrelated admin API
requests; Vault Kubernetes-role writes have no native compare-and-swap.
"""
    stage = "administrator_ready"
    failed_stage = None
    maintenance_attempted = False
    role_delete_attempted = False
    role_restored = False
    lock_owned = False
    lock_attempted = False
    interrupted = False
    probe_complete = False
    cleanup = {"fenced": "not_needed", "role": "not_changed",
               "administrator": "unknown", "lock": "not_acquired"}
    try:
        _verified(actions.administrator_ready())
        stage = "acquire_maintenance_lock"
        lock_attempted = True
        _verified(actions.acquire_maintenance_lock())
        lock_owned = True
        stage = "capture_original_role_and_baseline"
        _verified(actions.capture_original_role_and_baseline())
        # Capture and restoration readiness precede any interruption.
        stage = "prepare_fresh_fence"
        maintenance_attempted = True  # failure may occur after a scale request
        _verified(actions.prepare_fresh_fence())
        stage = "stop_original_signer"
        _verified(actions.stop_signer_and_verify_absence())
        stage = "verify_immediate_predelete"
        _verified(actions.verify_immediate_predelete())
        stage = "delete_runtime_role"
        # Set before request: a timeout does not mean the deletion failed.
        role_delete_attempted = True
        _verified(actions.delete_runtime_role())
        stage = "prove_new_signer_authentication_denied"
        _verified(actions.prove_new_signer_authentication_denied())
        stage = "stop_denied_signer"
        _verified(actions.stop_signer_and_verify_absence())
        stage = "restore_exact_runtime_role"
        _verified(actions.restore_exact_runtime_role())
        role_restored = True
        cleanup["role"] = "restored_exact"
        stage = "recover_signer_and_verify_continuity"
        _verified(actions.recover_signer_and_verify_continuity())
        stage = "verify_vault_audit_chain"
        _verified(actions.verify_vault_audit_chain())
        stage = "verify_client_fence_remain_quiesced"
        _verified(actions.verify_client_fence_remain_quiesced())
        cleanup["fenced"] = "verified"
        probe_complete = True
    except BaseException as error:
        # KeyboardInterrupt/SystemExit must pass through the same cleanup path.
        failed_stage = stage
        interrupted = isinstance(error, (KeyboardInterrupt, SystemExit))
    finally:
        if lock_attempted and not lock_owned:
            try:
                ownership = actions.reconcile_maintenance_lock()
                if ownership not in ("owned", "not_owned"):
                    raise CeremonyError("maintenance lock ownership unknown")
                lock_owned = ownership == "owned"
                cleanup["lock"] = ownership
            except BaseException:
                cleanup["lock"] = "unconfirmed"
        if maintenance_attempted and not probe_complete:
            try:
                _verified(actions.ensure_client_fence_quiesced())
                cleanup["fenced"] = "verified"
            except BaseException:
                cleanup["fenced"] = "unconfirmed"
            # Remove any pending init/retry signer before restoring its role.
            try:
                _verified(actions.stop_signer_and_verify_absence())
                cleanup["signer_stopped"] = "verified"
            except BaseException:
                cleanup["signer_stopped"] = "unconfirmed"
        if role_delete_attempted and not role_restored:
            try:
                _verified(actions.restore_exact_runtime_role())
                cleanup["role"] = "restored_exact"
                role_restored = True
            except BaseException:
                cleanup["role"] = "unconfirmed"
        try:
            revoked = actions.revoke_administrator()
            if revoked not in ("revoked", "not_issued"):
                raise CeremonyError("administrator cleanup unconfirmed")
            if probe_complete and revoked != "revoked":
                raise CeremonyError("successful ceremony requires credential revocation")
            cleanup["administrator"] = revoked
        except BaseException:
            cleanup["administrator"] = "unconfirmed"
        safe_cleanup = all(value != "unconfirmed" for value in cleanup.values())
        if lock_owned:
            if safe_cleanup:
                try:
                    _verified(actions.release_owned_maintenance_lock())
                    cleanup["lock"] = "released"
                except BaseException:
                    cleanup["lock"] = "unconfirmed"
            else:
                # Keep the incident marker; do not imply activation is safe.
                cleanup["lock"] = "retained_for_recovery"
    complete = probe_complete and all(value != "unconfirmed" for value in cleanup.values())
    return {"schema_version": 1, "scope": "UC-5 role revocation and restoration ceremony",
            "result": "PROBE_COMPLETE" if complete else "INCOMPLETE",
            "failed_stage": failed_stage,
            "interrupted": interrupted,
            "cleanup": cleanup, "uc5_complete": False,
            "activation_allowed": complete,
            "remaining": "guarded activation and new canonical finalized duty evidence"}
