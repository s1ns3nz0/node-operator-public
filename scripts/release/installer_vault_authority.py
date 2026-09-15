"""Guarded grant/revoke of the temporary Vault bootstrap EKS authority."""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import shutil
import tempfile

from installer_files import publish_directory
from installer_infrastructure import InfrastructureError, _read_object
from installer_ops_execution import _environment, _hash, _identity, _private, _safe_state
from installer_vault_execution import _create_private_json, _run, prepare_vault_plan_workspace
from installer_vault_inputs import prepare_vault_inputs
from installer_vault_plan import VaultPlanError, validate_vault_plan


class VaultAuthorityError(InfrastructureError):
    """A non-sensitive authority lifecycle error."""


_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_PHASES = frozenset({"grant", "revoke"})
_OUTPUTS = frozenset({"deployment_account_id", "cluster_name", "vault_unseal_key_arn", "private_subnet_ids", "private_gitops_ecr_repository_urls", "vault_role_arn"})


def _phase(phase: str) -> None:
    if phase not in _PHASES:
        raise VaultAuthorityError("Vault authority phase must be grant or revoke.")


def _value(outputs: dict, key: str):
    item = outputs.get(key)
    if not isinstance(item, dict) or item.get("sensitive") is not False or "value" not in item:
        raise VaultAuthorityError("Vault authority outputs are malformed.")
    return item["value"]


def _current_invariants(terraform: list[str], environment: dict, state_dir: Path, discovery: dict) -> dict:
    """Refresh only stable identity outputs; never compare stale output bytes."""
    result = _run(terraform + ["output", "-json"], environment, output=True)
    if result.returncode:
        raise VaultAuthorityError("Current Vault authority outputs could not be reconciled.")
    try:
        current = json.loads(result.stdout)
        original = _read_object(state_dir / "terraform-work/baseline-output.json")
        baseline = _read_object(state_dir / "infrastructure-inputs/baseline.tfvars.json")
    except (TypeError, ValueError, InfrastructureError) as error:
        raise VaultAuthorityError("Vault authority output evidence is malformed.") from error
    if (not isinstance(current, dict) or not isinstance(original, dict) or not isinstance(baseline, dict)
            or not _OUTPUTS <= set(current) or not _OUTPUTS <= set(original)
            or any(baseline.get(key) != discovery[field] for key, field in (("aws_account_id", "aws_account_id"), ("aws_region", "aws_region"), ("name", "deployment_name")))):
        raise VaultAuthorityError("Vault authority output invariants are missing.")
    try:
        expected = {key: _value(original, key) for key in _OUTPUTS}
        observed = {key: _value(current, key) for key in _OUTPUTS}
    except VaultAuthorityError:
        raise
    if (observed != expected or observed["deployment_account_id"] != discovery["aws_account_id"]
            or observed["cluster_name"] != discovery["deployment_name"]):
        raise VaultAuthorityError("Vault authority stable output invariants changed; reconcile before continuing.")
    return current


def _delta_value(path: Path, phase: str, *, current: bool) -> dict:
    try:
        value = _read_object(path)
    except InfrastructureError as error:
        raise VaultAuthorityError("Prepared Vault delta is unavailable or unsafe.") from error
    if not isinstance(value, dict) or value.get("enable_vault_bootstrap_runner") is not True:
        raise VaultAuthorityError("Prepared Vault delta does not enable the bootstrap runner.")
    expected_admin = (phase == "revoke") if current else (phase == "grant")
    if value.get("enable_vault_bootstrap_cluster_admin") is not False:
        raise VaultAuthorityError("Prepared Vault delta must preserve the non-admin baseline.")
    value["enable_vault_bootstrap_cluster_admin"] = expected_admin
    return value


def _delta(path: Path, phase: str, *, current: bool, directory: Path) -> Path:
    value = _delta_value(path, phase, current=current)
    result = directory / ("current.tfvars.json" if current else "desired.tfvars.json")
    fd = os.open(result, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump(value, handle, sort_keys=True, separators=(",", ":"))
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    return result


def _verified_delta(result: Path, source: Path, phase: str, *, current: bool) -> Path:
    try:
        value = _read_object(result)
    except InfrastructureError as error:
        raise VaultAuthorityError("Saved Vault authority delta is unavailable or unsafe.") from error
    if value != _delta_value(source, phase, current=current):
        raise VaultAuthorityError("Saved Vault authority delta differs from the reviewed composition.")
    return result


def _plans(state_dir: Path) -> Path:
    result = state_dir / "vault-authority-plans"
    if result.exists() or result.is_symlink():
        try:
            _private(result, "Vault authority plan directory is unsafe.")
        except InfrastructureError as error:
            raise VaultAuthorityError("Vault authority plan directory is unsafe.") from error
    else:
        result.mkdir(mode=0o700)
    return result


def _receipt(value: object, phase: str, discovery: dict, digest: str, scope: dict | None = None) -> dict:
    keys = {"schema_version", "phase", "plan_sha256", "aws_account_id", "aws_region", "deployment_name", "scope", "applied"}
    if not isinstance(value, dict) or set(value) != keys or value.get("schema_version") != 1 or value.get("phase") != phase:
        raise VaultAuthorityError("Vault authority receipt has an unexpected schema.")
    if value.get("plan_sha256") != digest or not _SHA256.fullmatch(digest):
        raise VaultAuthorityError("Vault authority receipt does not bind the reviewed plan.")
    if any(value.get(key) != discovery.get(key) for key in ("aws_account_id", "aws_region", "deployment_name")) or value.get("applied") is not False:
        raise VaultAuthorityError("Vault authority receipt does not bind the selected deployment.")
    if not isinstance(value.get("scope"), dict):
        raise VaultAuthorityError("Vault authority receipt scope is invalid.")
    if scope is not None and value["scope"] != scope:
        raise VaultAuthorityError("Vault authority receipt scope differs from the reviewed plan.")
    return value


def _reconcile(terraform: list[str], environment: dict, baseline: Path, current: Path, state_dir: Path, discovery: dict) -> dict:
    result = _run(terraform + ["plan", "-input=false", "-detailed-exitcode", f"-var-file={baseline}", f"-var-file={current}"], environment)
    if result.returncode != 0:
        raise VaultAuthorityError("Current composed Vault authority state has drift or pending changes.")
    return _current_invariants(terraform, environment, state_dir, discovery)


def _workspace(bundle_root: Path, state_dir: Path, discovery: dict, profile: str, phase: str, action: str) -> Path:
    return prepare_vault_plan_workspace(bundle_root, state_dir, discovery, profile, target_name=f"vault-bootstrap-{phase}-{action}-work")


def plan_vault_authority(bundle_root: Path, state_dir: Path, discovery: dict, profile: str, artifacts_path: Path, phase: str) -> str:
    """Save one reviewed grant/revoke plan after reconciling the prior composition."""
    _phase(phase); _safe_state(state_dir)
    delta = prepare_vault_inputs(state_dir, discovery, artifacts_path)
    _identity(discovery, profile); environment = _environment(profile, discovery)
    plans = _plans(state_dir); destination = plans / phase
    if destination.exists() or destination.is_symlink():
        raise VaultAuthorityError("A Vault authority plan already exists; nothing was overwritten.")
    module = _workspace(bundle_root, state_dir, discovery, profile, phase, "plan")
    stage = Path(tempfile.mkdtemp(prefix=f".{phase}-", dir=plans))
    try:
        terraform = ["terraform", f"-chdir={module}"]
        baseline = state_dir / "infrastructure-inputs/baseline.tfvars.json"
        current = _delta(delta, phase, current=True, directory=stage)
        desired = _delta(delta, phase, current=False, directory=stage)
        _reconcile(terraform, environment, baseline, current, state_dir, discovery)
        saved = stage / "plan.tfplan"
        fd = os.open(saved, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600); os.close(fd)
        result = _run(terraform + ["plan", "-input=false", f"-var-file={baseline}", f"-var-file={desired}", f"-out={saved}"], environment)
        if result.returncode:
            raise VaultAuthorityError("Vault authority plan failed; no apply was attempted.")
        digest = _hash(saved)
        shown = _run(terraform + ["show", "-json", str(saved)], environment, output=True)
        if shown.returncode:
            raise VaultAuthorityError("Vault authority saved plan could not be inspected.")
        scope = validate_vault_plan(json.loads(shown.stdout), phase)
        if scope["result"] != "scope_valid" or _hash(saved) != digest:
            raise VaultAuthorityError("Vault authority plan is empty or changed during validation.")
        receipt = {"schema_version": 1, "phase": phase, "plan_sha256": digest, **{key: discovery[key] for key in ("aws_account_id", "aws_region", "deployment_name")}, "scope": scope, "applied": False}
        _create_private_json(stage / "receipt.json", receipt, "Vault authority receipt could not be created safely.")
        _receipt(receipt, phase, discovery, digest, scope)
        publish_directory(stage, destination)
        return digest
    except (ValueError, VaultPlanError) as error:
        raise VaultAuthorityError("Vault authority plan is malformed or outside the approved phase.") from error
    finally:
        if stage.exists(): shutil.rmtree(stage)
        if module.exists(): shutil.rmtree(module)


def apply_vault_authority(bundle_root: Path, state_dir: Path, discovery: dict, profile: str, artifacts_path: Path, phase: str, expected_sha: str) -> None:
    """Apply only an exactly reviewed phase plan, then prove the desired state is clean."""
    _phase(phase)
    if not isinstance(expected_sha, str) or not _SHA256.fullmatch(expected_sha):
        raise VaultAuthorityError("Reviewed Vault authority plan digest is invalid.")
    delta = prepare_vault_inputs(state_dir, discovery, artifacts_path)
    _identity(discovery, profile); environment = _environment(profile, discovery)
    plans = _plans(state_dir)
    try:
        directory = plans / phase; _private(directory, "Vault authority saved plan directory is unsafe.")
    except InfrastructureError as error:
        raise VaultAuthorityError("Vault authority saved plan directory is unsafe.") from error
    saved, receipt_path = directory / "plan.tfplan", directory / "receipt.json"
    if _hash(saved) != expected_sha:
        raise VaultAuthorityError("Reviewed Vault authority plan digest does not match.")
    attempt, success = plans / f"{phase}-apply-attempt.json", plans / f"{phase}-success.json"
    if attempt.exists() or attempt.is_symlink() or success.exists() or success.is_symlink():
        raise VaultAuthorityError("Vault authority apply has existing evidence; do not retry blindly.")
    module = _workspace(bundle_root, state_dir, discovery, profile, phase, "apply")
    try:
        terraform = ["terraform", f"-chdir={module}"]
        baseline = state_dir / "infrastructure-inputs/baseline.tfvars.json"
        current = _verified_delta(directory / "current.tfvars.json", delta, phase, current=True)
        desired = _verified_delta(directory / "desired.tfvars.json", delta, phase, current=False)
        _reconcile(terraform, environment, baseline, current, state_dir, discovery)
        shown = _run(terraform + ["show", "-json", str(saved)], environment, output=True)
        if shown.returncode:
            raise VaultAuthorityError("Reviewed Vault authority plan could not be inspected.")
        scope = validate_vault_plan(json.loads(shown.stdout), phase)
        _receipt(_read_object(receipt_path), phase, discovery, expected_sha, scope)
        if _hash(saved) != expected_sha:
            raise VaultAuthorityError("Reviewed Vault authority plan changed before apply.")
        _create_private_json(attempt, {"schema_version": 1, "phase": phase, "plan_sha256": expected_sha}, "Vault authority apply marker could not be created safely.")
        if _run(terraform + ["apply", "-input=false", str(saved)], environment).returncode:
            raise VaultAuthorityError("Vault authority apply outcome is uncertain; preserve the attempt marker.")
        _reconcile(terraform, environment, baseline, desired, state_dir, discovery)
        _create_private_json(success, {"schema_version": 1, "phase": phase, "plan_sha256": expected_sha, "applied": True}, "Vault authority success record could not be created safely.")
    except (ValueError, VaultPlanError, InfrastructureError) as error:
        if isinstance(error, VaultAuthorityError): raise
        raise VaultAuthorityError("Vault authority receipt or plan is malformed.") from error
    finally:
        if module.exists() and not (attempt.exists() or attempt.is_symlink()): shutil.rmtree(module)


def reconcile_vault_authority(bundle_root: Path, state_dir: Path, discovery: dict, profile: str, artifacts_path: Path, phase: str) -> dict:
    """Read-only proof that the completed authority phase remains composed and clean."""
    _phase(phase); _safe_state(state_dir)
    delta = prepare_vault_inputs(state_dir, discovery, artifacts_path)
    _identity(discovery, profile); environment = _environment(profile, discovery)
    module = _workspace(bundle_root, state_dir, discovery, profile, phase, "reconcile")
    stage = Path(tempfile.mkdtemp(prefix=f".{phase}-reconcile-", dir=state_dir))
    try:
        terraform = ["terraform", f"-chdir={module}"]
        desired = _delta(delta, phase, current=False, directory=stage)
        return _reconcile(terraform, environment, state_dir / "infrastructure-inputs/baseline.tfvars.json", desired, state_dir, discovery)
    finally:
        shutil.rmtree(stage, ignore_errors=True)
        if module.exists(): shutil.rmtree(module)
