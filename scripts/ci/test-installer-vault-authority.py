#!/usr/bin/env python3
# Check objective: Grant/revoke authority plans reconcile current state, bind stable invariants, and never retry uncertain applies.
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/release"))
import installer_vault_authority as subject
import installer_vault_plan as vault_plan

D = {"aws_account_id": "123456789012", "aws_region": "ap-northeast-1", "deployment_name": "node"}
ADMIN = vault_plan._ADMIN

def outputs(kms="kms"):
    values = {"deployment_account_id": D["aws_account_id"], "cluster_name": D["deployment_name"], "vault_unseal_key_arn": kms, "private_subnet_ids": ["subnet-1"], "private_gitops_ecr_repository_urls": {"vault": "repo", "vault_chart": "chart"}, "vault_role_arn": "role"}
    return {key: {"value": value, "sensitive": False} for key, value in values.items()}

def plan(phase):
    return {"format_version": "1.2", "terraform_version": "1.5.7", "resource_changes": [{"address": ADMIN, "mode": "managed", "change": {"actions": ["create" if phase == "grant" else "delete"]}}]}

class AuthorityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.root = Path(self.temp.name); os.chmod(self.root, 0o700)
        self.state = self.root / "state"; self.state.mkdir(mode=0o700)
        (self.state / "vault-authority-plans").mkdir(mode=0o700)
        (self.state / "infrastructure-inputs").mkdir(mode=0o700)
        self.write(self.state / "infrastructure-inputs/baseline.tfvars.json", {"aws_account_id": D["aws_account_id"], "aws_region": D["aws_region"], "name": D["deployment_name"]})
        work = self.state / "terraform-work"; work.mkdir(mode=0o700); self.write(work / "baseline-output.json", outputs())
        self.delta = self.state / "vault.tfvars.json"; self.write(self.delta, {"enable_vault_bootstrap_runner": True, "enable_vault_bootstrap_cluster_admin": False})
        self.bundle = self.root / "bundle"; self.bundle.mkdir()
    def tearDown(self): self.temp.cleanup()
    def write(self, path, value): path.write_text(json.dumps(value)); os.chmod(path, 0o600)
    def workspace(self, phase, action):
        path = self.state / f"vault-bootstrap-{phase}-{action}-work"; path.mkdir(mode=0o700); return path
    def mocks(self, phase, *, drift=False, invariant=None, apply_fail=False):
        calls=[]; workspaces=[]; current_output=json.dumps(invariant or outputs()).encode()
        def prepare(*args, **kwargs): return self.delta
        def workspace(*args, **kwargs):
            path=self.workspace(phase, "apply" if "apply" in kwargs.get("target_name", "") else "plan"); workspaces.append(path); return path
        def run(args, env, *, output=False):
            calls.append(args)
            if "-detailed-exitcode" in args: return SimpleNamespace(returncode=2 if drift else 0)
            if "output" in args: return SimpleNamespace(returncode=0, stdout=current_output)
            if "show" in args: return SimpleNamespace(returncode=0, stdout=json.dumps(plan(phase)).encode())
            if "apply" in args: return SimpleNamespace(returncode=1 if apply_fail else 0)
            out=next(value[5:] for value in args if value.startswith("-out=")); Path(out).write_bytes(b"reviewed"); return SimpleNamespace(returncode=0)
        target_names=[]
        def named_workspace(*args, **kwargs):
            target_names.append(kwargs["target_name"])
            return workspace(*args, **kwargs)
        return calls, workspaces, target_names, patch.multiple(subject, prepare_vault_inputs=prepare, prepare_vault_plan_workspace=named_workspace, _identity=lambda *x: None, _environment=lambda *x: {}, _run=run)
    def test_grant_and_revoke_success(self):
        for phase in ("grant", "revoke"):
            with self.subTest(phase=phase):
                calls, _, names, mocked = self.mocks(phase)
                with mocked: digest=subject.plan_vault_authority(self.bundle, self.state, D, "profile", self.delta, phase)
                self.assertEqual(len(digest), 64)
                _, _, apply_names, apply_mocked = self.mocks(phase)
                with apply_mocked: subject.apply_vault_authority(self.bundle, self.state, D, "profile", self.delta, phase, digest)
                self.assertEqual(names, [f"vault-bootstrap-{phase}-plan-work"])
                self.assertEqual(apply_names, [f"vault-bootstrap-{phase}-apply-work"])
                self.assertTrue((self.state / "vault-authority-plans" / f"{phase}-success.json").exists())
                if phase == "grant": shutil.rmtree(self.state / "vault-authority-plans" / phase); (self.state / "vault-authority-plans" / "grant-success.json").unlink()
    def test_stale_baseline_output_is_not_byte_compared_but_invariant_drift_stops(self):
        original = outputs(); original["obsolete_non_invariant"] = {"value": "old", "sensitive": False}
        self.write(self.state / "terraform-work/baseline-output.json", original)
        calls, _, _, mocked = self.mocks("grant")
        with mocked: subject.plan_vault_authority(self.bundle, self.state, D, "profile", self.delta, "grant")
        shutil.rmtree(self.state / "vault-authority-plans" / "grant")
        bad=outputs(kms="changed")
        with self.mocks("grant", invariant=bad)[3], self.assertRaises(subject.VaultAuthorityError): subject.plan_vault_authority(self.bundle, self.state, D, "profile", self.delta, "grant")
    def test_wrong_phase_drift_and_replacement_are_rejected(self):
        with self.assertRaises(subject.VaultAuthorityError): subject.plan_vault_authority(self.bundle, self.state, D, "p", self.delta, "bad")
        with self.mocks("grant", drift=True)[3], self.assertRaises(subject.VaultAuthorityError): subject.plan_vault_authority(self.bundle, self.state, D, "p", self.delta, "grant")
        replacement={**plan("grant"), "resource_changes": [{"address": ADMIN, "mode": "managed", "change": {"actions": ["delete", "create"]}}]}
        with self.assertRaises(vault_plan.VaultPlanError): vault_plan.validate_vault_plan(replacement, "grant")
    def test_tampered_receipt_hash_and_apply_failure_cannot_retry(self):
        with self.mocks("grant")[3]: digest=subject.plan_vault_authority(self.bundle, self.state, D, "p", self.delta, "grant")
        receipt=self.state / "vault-authority-plans/grant/receipt.json"; self.write(receipt, {"bad": True})
        with self.mocks("grant")[3], self.assertRaises(subject.VaultAuthorityError): subject.apply_vault_authority(self.bundle, self.state, D, "p", self.delta, "grant", digest)
        self.assertFalse((self.state / "vault-authority-plans/grant-apply-attempt.json").exists())
        scope=vault_plan.validate_vault_plan(plan("grant"), "grant"); self.write(receipt, {"schema_version":1,"phase":"grant","plan_sha256":digest,**D,"scope":scope,"applied":False})
        with self.mocks("grant", apply_fail=True)[3], self.assertRaises(subject.VaultAuthorityError): subject.apply_vault_authority(self.bundle, self.state, D, "p", self.delta, "grant", digest)
        self.assertTrue((self.state / "vault-authority-plans/grant-apply-attempt.json").exists())
        with self.mocks("grant")[3], self.assertRaises(subject.VaultAuthorityError): subject.apply_vault_authority(self.bundle, self.state, D, "p", self.delta, "grant", digest)

    def test_read_only_reconcile_uses_phase_specific_workspace(self):
        workspace = self.state / "vault-bootstrap-grant-reconcile-work"; workspace.mkdir(mode=0o700)
        names=[]
        def fresh(*args, **kwargs): names.append(kwargs["target_name"]); return workspace
        with patch.object(subject, "prepare_vault_inputs", return_value=self.delta), patch.object(subject, "prepare_vault_plan_workspace", side_effect=fresh), patch.object(subject, "_identity"), patch.object(subject, "_environment", return_value={}), patch.object(subject, "_reconcile") as reconcile:
            subject.reconcile_vault_authority(self.bundle, self.state, D, "p", self.delta, "grant")
        self.assertEqual(names, ["vault-bootstrap-grant-reconcile-work"]); reconcile.assert_called_once(); self.assertFalse(workspace.exists())

if __name__ == "__main__": unittest.main()
