"""Prepare and explicitly apply infrastructure through the verified release.

Preparation is local only. Apply creates infrastructure but never performs
Vault ceremonies, SSM setup or validator activation.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile

from installer_preflight import PreflightError, validate_inputs, aws_read, verify_execution_profile, AWS_CREDENTIAL_OVERRIDES
from installer_files import publish_directory


class InfrastructureError(RuntimeError):
    """Controlled non-sensitive preparation failure."""


def expected_inputs(destination: Path, discovery: dict, principal: str, managed_recorder_override: bool = False) -> dict:
    account = discovery["aws_account_id"]
    region = discovery["aws_region"]
    name = discovery["deployment_name"]
    validate_inputs(discovery["aws_profile"], region, name)
    if not re.fullmatch(r"[0-9]{12}", account):
        raise InfrastructureError("Infrastructure account is invalid.")
    if not re.fullmatch(r"arn:aws:iam::" + account + r":role/[A-Za-z0-9+=,.@_/-]+", principal):
        raise InfrastructureError("Provide an exact same-account backend IAM role ARN.")
    zones = discovery["availability_zones"]
    if (not isinstance(zones, list) or len(zones) != 2 or zones[0] == zones[1]
            or not all(isinstance(zone, str) and re.fullmatch(re.escape(region) + r"[a-z]", zone) for zone in zones)):
        raise InfrastructureError("Infrastructure preparation requires two verified target-region AZs.")
    recorder = discovery.get("configuration_recorder")
    if not isinstance(recorder, dict) or set(recorder) != {"result", "existing_count", "manage_config_recorder", "existing_recorder_adoption"}:
        raise InfrastructureError("AWS Config recorder observation is missing or invalid; no recorder ownership was assumed.")
    manage_recorder = recorder.get("manage_config_recorder")
    if (recorder.get("existing_recorder_adoption") != "not_authorized"
            or type(manage_recorder) is not bool
            or type(recorder.get("existing_count")) is not int):
        raise InfrastructureError("AWS Config recorder observation is missing or invalid; no recorder ownership was assumed.")
    if ((recorder.get("result") == "recorder_absent_verified" and recorder.get("existing_count") == 0 and manage_recorder is True)
            or (recorder.get("result") == "existing_recorder_verified" and recorder.get("existing_count") == 1 and manage_recorder is False)):
        pass
    else:
        raise InfrastructureError("AWS Config recorder observation is missing or invalid; no recorder ownership was assumed.")
    if managed_recorder_override:
        if not (recorder.get("result") == "existing_recorder_verified" and manage_recorder is False):
            raise InfrastructureError("Managed recorder resume evidence conflicts with fresh recorder observation.")
        manage_recorder = True
    return {
        "bootstrap-state.tfvars.json": {"aws_account_id": account, "aws_region": region, "name": name,
                                       "state_bucket_name": None, "backend_principal_arns": [principal]},
        "foundation-network.tfvars.json": {"aws_region": region, "name": name, "network_mode": "fresh", "availability_zones": zones},
        "baseline.tfvars.json": {
            "aws_account_id": account, "aws_region": region, "name": name,
            "terraform_apply_role_arn": principal,
            "audit_replica_region": "ap-northeast-2" if region == "ap-northeast-1" else "ap-northeast-1",
            "availability_zones": zones, "enable_gitops_client_ecr_publisher": True,
            "enable_validator_runtime_ecr_mirror": True,
            "enable_validator_client_ecr_mirror": True,
            "enable_validator_log_collector_ecr_mirror": True,
            "enable_vault_audit_relay_repository": True,
            "manage_config_recorder": manage_recorder,
            "enable_temporary_ssm_ops_host": False, "temporary_ssm_ops_host_termination_at": "",
            "enable_argocd_bootstrap_runner": False, "enable_argocd_bootstrap_cluster_admin": False,
            "enable_vault_bootstrap_runner": False, "enable_vault_bootstrap_cluster_admin": False,
        },
        "zero-resource-inputs.json": {"schema_version": 1, "aws_account_id": account, "aws_region": region,
                                     "availability_zones": zones, "name": name,
                                     "bootstrap_config": str(destination / "bootstrap-state.tfvars.json"),
                                     "foundation_config": str(destination / "foundation-network.tfvars.json"),
                                     "baseline_config": str(destination / "baseline.tfvars.json")},
    }


def verify_managed_recorder_resume(bundle_root: Path, state_dir: Path, destination: Path,
                                   discovery: dict) -> bool:
    """Return true only after the release wrapper re-reads exact remote state."""
    recorder = discovery["configuration_recorder"]
    saved = _read_object(destination / "baseline.tfvars.json")
    if saved.get("manage_config_recorder") is not True:
        return False
    if (recorder.get("result") == "recorder_absent_verified"
            and recorder.get("manage_config_recorder") is True):
        return False
    if not (recorder.get("result") == "existing_recorder_verified"
            and recorder.get("manage_config_recorder") is False):
        raise InfrastructureError("Saved recorder management conflicts with fresh recorder observation.")
    script = bundle_root / "source/scripts/release/node-operator-release.sh"
    inputs = destination / "zero-resource-inputs.json"
    work = state_dir / "terraform-work"
    if not script.is_file() or script.is_symlink() or not inputs.is_file() or inputs.is_symlink():
        raise InfrastructureError("Remote recorder ownership evidence is unavailable or unsafe.")
    if "execution_identity" in discovery:
        execution = discovery["execution_identity"]
        profile = execution.get("aws_profile") if isinstance(execution, dict) else None
        if not isinstance(profile, str):
            raise InfrastructureError("Verified execution profile is unavailable for recorder ownership verification.")
        try:
            verify_execution_profile(discovery, discovery["backend_role"], profile)
        except (PreflightError, KeyError) as error:
            raise InfrastructureError("Execution identity changed; recorder ownership was not verified.") from error
    else:
        profile = discovery["aws_profile"]
        identity = aws_read(profile, discovery["aws_region"], ["sts", "get-caller-identity"])
        if (not isinstance(identity, dict) or identity.get("Account") != discovery["aws_account_id"]
                or identity.get("Arn") != discovery.get("principal_arn") or str(identity.get("Arn", "")).endswith(":root")):
            raise InfrastructureError("Metadata execution identity changed; recorder ownership was not verified.")
    environment = os.environ.copy()
    for key in list(environment):
        if key.startswith("TF_VAR_") or key in AWS_CREDENTIAL_OVERRIDES + ("BASH_ENV", "ENV"):
            environment.pop(key, None)
    environment.update(AWS_PROFILE=profile, AWS_REGION=discovery["aws_region"], AWS_DEFAULT_REGION=discovery["aws_region"], AWS_PAGER="", AWS_CLI_AUTO_PROMPT="off", AWS_EC2_METADATA_DISABLED="true")
    try:
        result = subprocess.run(["bash", str(script), "zero", "verify-recorder", "--bundle-root", str(bundle_root),
                                 "--inputs", str(inputs), "--work-dir", str(work)], env=environment,
                                stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=60, check=False)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise InfrastructureError("Remote recorder ownership could not be verified; inputs were preserved.") from error
    if result.returncode:
        raise InfrastructureError("Remote recorder ownership was not proven; inputs were preserved.")
    return True


def _read_object(path: Path) -> dict:
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise InfrastructureError("Infrastructure input has duplicate fields.")
            value[key] = item
        return value
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(descriptor, "r", encoding="utf-8") as handle:
            info = os.fstat(handle.fileno())
            if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 65536:
                raise InfrastructureError("Infrastructure input is not a bounded private regular file.")
            result = json.load(handle, object_pairs_hook=unique)
    except (OSError, ValueError) as error:
        raise InfrastructureError("Infrastructure input could not be read safely.") from error
    if not isinstance(result, dict):
        raise InfrastructureError("Infrastructure input is not a JSON object.")
    return result


def _validate_tree(directory: Path, expected: dict) -> None:
    info = directory.lstat()
    if not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700:
        raise InfrastructureError("Infrastructure input directory must be private and not a symlink.")
    if {path.name for path in directory.iterdir()} != set(expected):
        raise InfrastructureError("Infrastructure input directory contains missing or unexpected files.")
    for name, value in expected.items():
        # Canonical JSON comparison also distinguishes booleans from numbers.
        if json.dumps(_read_object(directory / name), sort_keys=True) != json.dumps(value, sort_keys=True):
            raise InfrastructureError("Infrastructure inputs differ from the selected deployment context; nothing was overwritten.")


def prepare_inputs(bundle_root: Path, destination: Path, discovery: dict, principal: str, state_dir: Path | None = None) -> Path:
    expected = expected_inputs(destination, discovery, principal)
    if not destination.is_absolute() or Path(os.path.normpath(str(destination))) != destination:
        raise InfrastructureError("Infrastructure input directory must be a normalized absolute path.")
    for path in (destination.parent, *destination.parent.parents):
        if path.is_symlink() or not path.is_dir():
            raise InfrastructureError("Infrastructure input ancestors must be existing regular directories.")
    if destination.exists() or destination.is_symlink():
        if state_dir is not None and verify_managed_recorder_resume(bundle_root, state_dir, destination, discovery):
            expected = expected_inputs(destination, discovery, principal, managed_recorder_override=True)
        _validate_tree(destination, expected)
        return destination / "zero-resource-inputs.json"
    script = bundle_root / "source/scripts/release/prepare-zero-resource-inputs.sh"
    if not script.is_file() or script.is_symlink():
        raise InfrastructureError("Verified release lacks its infrastructure input preparation command.")
    environment = os.environ.copy()
    for key in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_SECURITY_TOKEN", "BASH_ENV", "ENV"):
        environment.pop(key, None)
    environment.update(AWS_PROFILE=discovery["aws_profile"], AWS_REGION=discovery["aws_region"], AWS_DEFAULT_REGION=discovery["aws_region"])
    stage = Path(tempfile.mkdtemp(prefix=".infrastructure-inputs-", dir=destination.parent))
    generated = stage / "generated"
    try:
        args = ["bash", str(script), "--aws-account-id", discovery["aws_account_id"],
                "--aws-region", discovery["aws_region"], "--name", discovery["deployment_name"],
                "--backend-principal-arn", principal, "--manage-config-recorder",
                str(expected["baseline.tfvars.json"]["manage_config_recorder"]).lower(),
                "--output-dir", str(generated)]
        for zone in discovery["availability_zones"]:
            args.extend(["--availability-zone", zone])
        result = subprocess.run(args, env=environment, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=30, check=False)
        if result.returncode:
            raise InfrastructureError("Release input preparation failed; no infrastructure was applied.")
        _validate_tree(generated, expected_inputs(generated, discovery, principal))
        # The release command emitted absolute staging paths; bind those paths
        # to the final private directory before publishing it atomically.
        (generated / "zero-resource-inputs.json").write_text(json.dumps(expected["zero-resource-inputs.json"], sort_keys=True) + "\n")
        _validate_tree(generated, expected)
        if destination.exists() or destination.is_symlink():
            raise InfrastructureError("Infrastructure input destination appeared during preparation.")
        publish_directory(generated, destination)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise InfrastructureError("Infrastructure preparation could not complete; no resources were applied.") from error
    finally:
        shutil.rmtree(stage)
    return destination / "zero-resource-inputs.json"


def apply_infrastructure(bundle_root: Path, state_dir: Path, discovery: dict,
                         principal: str, execution_profile: str) -> None:
    """Invoke only a capable verified release; caller owns lock and approval.

    Do not use an old release's unguarded migration implementation. The local
    preparation and release verification must be repeated immediately before
    this call. The release wrapper owns Terraform-state reconciliation.
    """
    validate_inputs(execution_profile, discovery["aws_region"], discovery["deployment_name"])
    inputs_dir = state_dir / "infrastructure-inputs"
    expected = expected_inputs(inputs_dir, discovery, principal)
    if verify_managed_recorder_resume(bundle_root, state_dir, inputs_dir, discovery):
        expected = expected_inputs(inputs_dir, discovery, principal, managed_recorder_override=True)
    _validate_tree(inputs_dir, expected)
    contract = _read_object(bundle_root / "source/release/hoodi-release-contract.json")
    bootstrap = contract.get("bootstrap")
    if not isinstance(bootstrap, dict) or type(bootstrap.get("interactive_infrastructure_schema")) is not int or bootstrap["interactive_infrastructure_schema"] != 1:
        raise InfrastructureError("This release does not support guarded installer apply; download a new verified installer release.")
    work_dir = state_dir / "terraform-work"
    if work_dir.is_symlink() or (work_dir.exists() and (not work_dir.is_dir() or stat.S_IMODE(work_dir.stat().st_mode) != 0o700)):
        raise InfrastructureError("Terraform work directory must be an original private directory.")
    # An empty/pre-created directory is not ownership evidence for collisions.
    continuation = any(path.is_file() and not path.is_symlink() for path in
                       (work_dir / "bootstrap-output.json", work_dir / "bootstrap-state/terraform.tfstate"))
    if not continuation:
        if (discovery["cluster_name_present"]
                or discovery["backend_collisions"]["account_owned_bucket_conflicts"]
                or discovery["backend_collisions"]["regional_table_conflicts"]
                or discovery["iam_role_collisions"]["deployment_role_name_conflicts"]):
            raise InfrastructureError("Fresh infrastructure names collide with existing resources; no adoption or apply was authorized.")
        if discovery["elastic_ip_headroom"]["result"] != "sufficient_at_observation":
            raise InfrastructureError("Fresh infrastructure lacks observed Elastic IP capacity; no apply was started.")
    if discovery["local_prerequisites"]["missing_by_stage"]["infrastructure"]:
        raise InfrastructureError("Infrastructure prerequisites are missing; install the reported tools before apply.")
    if "execution_identity" in discovery:
        verify_execution_profile(discovery, discovery["backend_role"], execution_profile)
    else:
        identity = aws_read(execution_profile, discovery["aws_region"], ["sts", "get-caller-identity"])
        if (not isinstance(identity, dict) or identity.get("Account") != discovery["aws_account_id"]
                or identity.get("Arn") != discovery.get("principal_arn") or str(identity.get("Arn", "")).endswith(":root")):
            raise InfrastructureError("Execution identity changed after discovery; no apply was started.")
    environment = os.environ.copy()
    for key in list(environment):
        if key.startswith("TF_VAR_") or key in AWS_CREDENTIAL_OVERRIDES or key in ("BASH_ENV", "ENV"):
            environment.pop(key, None)
    environment.update(AWS_PROFILE=execution_profile, AWS_REGION=discovery["aws_region"], AWS_DEFAULT_REGION=discovery["aws_region"], AWS_PAGER="", AWS_CLI_AUTO_PROMPT="off", AWS_EC2_METADATA_DISABLED="true")
    script = bundle_root / "source/scripts/release/node-operator-release.sh"
    try:
        result = subprocess.run(["bash", str(script), "zero", "apply", "--bundle-root", str(bundle_root),
                                 "--inputs", str(inputs_dir / "zero-resource-inputs.json"), "--work-dir", str(work_dir)],
                                env=environment, check=False)
    except OSError as error:
        raise InfrastructureError("Infrastructure command could not start; preserve the original state directory.") from error
    if result.returncode:
        raise InfrastructureError("Infrastructure apply did not complete. Preserve this state directory and reconcile before resuming; do not deploy into a new directory.")
    output = _read_object(work_dir / "baseline-output.json")
    if (not isinstance(output.get("deployment_account_id"), dict) or not isinstance(output.get("cluster_name"), dict)
            or output["deployment_account_id"].get("value") != discovery["aws_account_id"]
            or output["cluster_name"].get("value") != discovery["deployment_name"]):
        raise InfrastructureError("Infrastructure output does not match the selected deployment; completion was not recorded.")
