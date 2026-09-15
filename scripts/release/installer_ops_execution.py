"""Execute the isolated, reviewed ops-access Terraform lifecycle.

The caller owns checkpointing and consent.  This module neither opens an SSM
session nor claims that the private endpoint path is usable after apply.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile

from installer_infrastructure import InfrastructureError, _read_object
from installer_files import publish_directory
from installer_ops_access import prepare_ops_access
from installer_preflight import AWS_CREDENTIAL_OVERRIDES, aws_read, validate_inputs


class OpsExecutionError(InfrastructureError):
    """Controlled non-sensitive ops-access execution failure."""


_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_INSTANCE = re.compile(r"i-[0-9a-f]+\Z")


def _private(path: Path, message: str) -> None:
    try:
        info = path.lstat()
    except OSError as error:
        raise OpsExecutionError(message) from error
    if path.is_symlink() or not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700:
        raise OpsExecutionError(message)


def _safe_state(state_dir: Path) -> None:
    if not state_dir.is_absolute() or Path(os.path.normpath(str(state_dir))) != state_dir:
        raise OpsExecutionError("Installer state directory must be a normalized absolute path.")
    for parent in (state_dir.parent, *state_dir.parent.parents):
        try:
            info = parent.lstat()
        except OSError as error:
            raise OpsExecutionError("Installer state directory ancestors are unavailable or unsafe.") from error
        # macOS exposes fixed system aliases (/tmp and /var) through /private;
        # caller-controlled components still must be real directories.
        if parent not in (Path("/private"), Path("/var"), Path("/tmp")) and (parent.is_symlink() or not stat.S_ISDIR(info.st_mode)):
            raise OpsExecutionError("Installer state directory ancestors are unavailable or unsafe.")
    _private(state_dir, "Installer state directory must be a private regular directory.")


def _capable(bundle_root: Path) -> None:
    try:
        contract = _read_object(bundle_root / "source/release/hoodi-release-contract.json")
    except InfrastructureError as error:
        raise OpsExecutionError("Verified release capability contract could not be read safely.") from error
    bootstrap = contract.get("bootstrap")
    if (not isinstance(bootstrap, dict)
            or type(bootstrap.get("interactive_ops_access_schema")) is not int
            or bootstrap.get("interactive_ops_access_schema") != 1):
        raise OpsExecutionError("This release does not support guarded isolated ops-access execution.")


def _source_files(bundle_root: Path) -> dict[Path, tuple[bytes, int]]:
    root = bundle_root / "source"
    selected = (root / "infra/ops-access", root / "scripts/ci/check-ops-access-ssm-retention-plan.sh")
    result: dict[Path, tuple[bytes, int]] = {}
    for item in selected:
        if item.is_symlink() or not item.exists():
            raise OpsExecutionError("Verified release lacks the isolated ops-access source files.")
        paths = [item] if item.is_file() else list(item.rglob("*"))
        for path in paths:
            if path.is_dir():
                if path.is_symlink():
                    raise OpsExecutionError("Verified ops-access source tree contains a symlink.")
                continue
            info = path.lstat()
            if path.is_symlink() or not stat.S_ISREG(info.st_mode):
                raise OpsExecutionError("Verified ops-access source tree contains a non-regular file.")
            relative = path.relative_to(root)
            result[relative] = (path.read_bytes(), stat.S_IMODE(info.st_mode))
    return result


def _validate_work(work: Path, expected: dict[Path, tuple[bytes, int]]) -> None:
    _private(work, "Ops-access work directory must be an original private directory.")
    actual: set[Path] = set()
    terraform_metadata = Path("infra/ops-access/.terraform")
    for path in work.rglob("*"):
        relative = path.relative_to(work)
        if relative == terraform_metadata:
            info = path.lstat()
            if path.is_symlink() or not stat.S_ISDIR(info.st_mode):
                raise OpsExecutionError("Ops-access Terraform metadata directory is unsafe.")
            continue
        if terraform_metadata in relative.parents:
            continue
        info = path.lstat()
        if path.is_symlink() or (not path.is_dir() and not stat.S_ISREG(info.st_mode)):
            raise OpsExecutionError("Ops-access work directory contains an unsafe file.")
        if path.is_file():
            actual.add(relative)
            wanted = expected.get(relative)
            if wanted is None or path.read_bytes() != wanted[0] or stat.S_IMODE(info.st_mode) != wanted[1]:
                raise OpsExecutionError("Ops-access work files differ from the verified release.")
    if actual != set(expected):
        raise OpsExecutionError("Ops-access work files are missing or unexpected.")


def _work_directory(bundle_root: Path, state_dir: Path) -> Path:
    expected = _source_files(bundle_root)
    work = state_dir / "ops-access-work"
    if work.exists() or work.is_symlink():
        _validate_work(work, expected)
        return work
    stage = Path(tempfile.mkdtemp(prefix=".ops-access-work-", dir=state_dir)) / "work"
    try:
        stage.mkdir(mode=0o700)
        for relative, (content, mode) in expected.items():
            target = stage / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)
            os.chmod(target, mode)
        os.chmod(stage, 0o700)
        if work.exists() or work.is_symlink():
            raise OpsExecutionError("Ops-access work destination appeared during staging.")
        publish_directory(stage, work)
    except OSError as error:
        raise OpsExecutionError("Ops-access work directory could not be created safely.") from error
    finally:
        shutil.rmtree(stage.parent, ignore_errors=True)
    _validate_work(work, expected)
    return work


def _environment(profile: str, discovery: dict) -> dict[str, str]:
    environment = os.environ.copy()
    for key in list(environment):
        if key.startswith("TF_") or key in AWS_CREDENTIAL_OVERRIDES or key in ("BASH_ENV", "ENV"):
            environment.pop(key, None)
    environment.update(AWS_PROFILE=profile, AWS_REGION=discovery["aws_region"],
                       AWS_DEFAULT_REGION=discovery["aws_region"], AWS_PAGER="",
                       AWS_CLI_AUTO_PROMPT="off", AWS_EC2_METADATA_DISABLED="true")
    return environment


def _identity(discovery: dict, profile: str) -> None:
    validate_inputs(profile, discovery["aws_region"], discovery["deployment_name"])
    value = aws_read(profile, discovery["aws_region"], ["sts", "get-caller-identity"])
    if (not isinstance(value, dict) or value.get("Account") != discovery["aws_account_id"]
            or value.get("Arn") != discovery.get("principal_arn") or str(value.get("Arn", "")).endswith(":root")):
        raise OpsExecutionError("Execution identity changed after discovery; no ops-access Terraform command was started.")


def _plan_file(state_dir: Path) -> Path:
    plans = state_dir / "ops-access-plans"
    if plans.exists() or plans.is_symlink():
        _private(plans, "Ops-access plan directory must be private and original.")
    else:
        plans.mkdir(mode=0o700)
    return plans / "approved.tfplan"


def _validate_backend_metadata(work: Path, state_dir: Path) -> None:
    """Reject a retained Terraform cache whose backend differs from the handoff."""
    cache = work / "infra/ops-access/.terraform"
    if not cache.exists() and not cache.is_symlink():
        return
    metadata = cache / "terraform.tfstate"
    if not metadata.exists() or metadata.is_symlink():
        raise OpsExecutionError("Initialized ops-access Terraform cache lacks safe backend metadata.")
    try:
        handoff = _read_object(state_dir / "terraform-work/ops-access-handoff.json")
        value = _read_object(metadata)
    except InfrastructureError as error:
        raise OpsExecutionError("Ops-access Terraform backend metadata could not be read safely.") from error
    backend = handoff.get("backend") if isinstance(handoff, dict) else None
    configured = value.get("backend") if isinstance(value, dict) else None
    config = configured.get("config") if isinstance(configured, dict) else None
    if not (isinstance(backend, dict) and isinstance(config, dict)
            and configured.get("type") == "s3"
            and config.get("bucket") == backend.get("bucket")
            and config.get("key") == backend.get("key")
            and config.get("region") == backend.get("region")):
        raise OpsExecutionError("Ops-access Terraform backend metadata differs from the prepared isolated backend.")
    if not (config.get("encrypt") is True
            and config.get("dynamodb_table") == backend.get("dynamodb_table")
            and config.get("kms_key_id") == backend.get("kms_key_id")
            and config.get("endpoint") in (None, "") and config.get("endpoints") in (None, {})
            and config.get("workspace_key_prefix", "env:") == "env:"):
        raise OpsExecutionError("Ops-access Terraform backend metadata has unsafe custom storage settings.")


def _hash(path: Path) -> str:
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 64 * 1024 * 1024:
            os.close(descriptor)
            raise OpsExecutionError("Ops-access saved plan is unsafe.")
        digest = hashlib.sha256()
        with os.fdopen(descriptor, "rb") as handle:
            for block in iter(lambda: handle.read(65536), b""):
                digest.update(block)
        return digest.hexdigest()
    except OSError as error:
        raise OpsExecutionError("Ops-access saved plan could not be read safely.") from error


def _run(operation: str, bundle_root: Path, state_dir: Path, discovery: dict, profile: str,
         expected_sha: str | None = None) -> tuple[Path, Path]:
    _safe_state(state_dir)
    _capable(bundle_root)
    inputs = prepare_ops_access(bundle_root, state_dir, discovery, profile)
    work = _work_directory(bundle_root, state_dir)
    _validate_backend_metadata(work, state_dir)
    plan = _plan_file(state_dir)
    session = state_dir / "private-eks-session.json"
    if operation == "plan":
        if plan.exists() or plan.is_symlink():
            raise OpsExecutionError("Approved ops-access plan already exists; it was not overwritten.")
    else:
        if expected_sha is None or _SHA256.fullmatch(expected_sha) is None or _hash(plan) != expected_sha:
            raise OpsExecutionError("Reviewed ops-access plan digest does not match; no apply was started.")
        if session.exists() or session.is_symlink():
            raise OpsExecutionError("Private EKS session handoff already exists; no apply was started.")
    _identity(discovery, profile)
    wrapper = bundle_root / "source/scripts/release/node-operator-ops-access.sh"
    if wrapper.is_symlink() or not wrapper.is_file():
        raise OpsExecutionError("Verified release lacks the guarded ops-access command.")
    args = ["bash", str(wrapper), operation, "--root", str(work), "--inputs", str(inputs), "--plan-file", str(plan), "--allow-create"]
    if operation == "apply":
        args.extend(["--expected-sha", expected_sha or "", "--session-handoff", str(session)])
    try:
        result = subprocess.run(args, env=_environment(profile, discovery), check=False)
    except OSError as error:
        raise OpsExecutionError("Ops-access command could not start; preserve the isolated state directory.") from error
    if result.returncode:
        raise OpsExecutionError("Ops-access Terraform command did not complete; preserve state and reconcile before resuming.")
    return plan, session


def plan_ops_access(bundle_root: Path, state_dir: Path, discovery: dict, profile: str) -> str:
    """Create one non-overwritable reviewed plan and return its digest."""
    plan, _ = _run("plan", bundle_root, state_dir, discovery, profile)
    return _hash(plan)


def apply_ops_access(bundle_root: Path, state_dir: Path, discovery: dict, profile: str, expected_sha: str) -> dict:
    """Apply a reviewed plan and return only its validated private handoff."""
    _, session = _run("apply", bundle_root, state_dir, discovery, profile, expected_sha)
    try:
        value = _read_object(session)
    except InfrastructureError as error:
        raise OpsExecutionError("Ops-access apply did not produce a safe private session handoff.") from error
    if not (set(value) == {"schema_version", "aws_region", "cluster_name", "ssm_ops_instance_id"}
            and type(value.get("schema_version")) is int and value.get("schema_version") == 1
            and isinstance(value.get("aws_region"), str) and value.get("aws_region") == discovery["aws_region"]
            and isinstance(value.get("cluster_name"), str) and value.get("cluster_name") == discovery["deployment_name"]
            and isinstance(value.get("ssm_ops_instance_id"), str) and _INSTANCE.fullmatch(value["ssm_ops_instance_id"])):
        raise OpsExecutionError("Ops-access session handoff does not match the selected deployment.")
    return value
