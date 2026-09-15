"""Prepare isolated SSM ops-access inputs from a completed baseline handoff.

This adapter performs only read-only AWS checks and local input generation.  It
does not plan, apply, open an SSM session, or collapse ops-access state into
the baseline Terraform state.
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

from installer_files import publish_directory
from installer_infrastructure import InfrastructureError, _read_object
from installer_preflight import AWS_CREDENTIAL_OVERRIDES, aws_read, validate_inputs


class OpsAccessError(InfrastructureError):
    """A controlled, non-sensitive ops-access preparation failure."""


_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_VPC = re.compile(r"vpc-[0-9a-f]+\Z")
_SUBNET = re.compile(r"subnet-[0-9a-f]+\Z")
_SECURITY_GROUP = re.compile(r"sg-[0-9a-f]+\Z")
_DYNAMODB_TABLE = re.compile(r"[A-Za-z0-9_.-]{3,255}\Z")


def _private_directory(path: Path, message: str) -> None:
    try:
        info = path.lstat()
    except OSError as error:
        raise OpsAccessError(message) from error
    if path.is_symlink() or not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700:
        raise OpsAccessError(message)


def _safe_state_directory(path: Path) -> None:
    if not path.is_absolute() or Path(os.path.normpath(str(path))) != path:
        raise OpsAccessError("Installer state directory must be a normalized absolute path.")
    for ancestor in (path.parent, *path.parent.parents):
        try:
            info = ancestor.lstat()
        except OSError as error:
            raise OpsAccessError("Installer state directory ancestors are unavailable or unsafe.") from error
        if ancestor.is_symlink() or not stat.S_ISDIR(info.st_mode):
            raise OpsAccessError("Installer state directory ancestors are unavailable or unsafe.")


def _handoff(path: Path, discovery: dict) -> dict:
    try:
        value = _read_object(path)
    except InfrastructureError as error:
        raise OpsAccessError("Baseline ops-access handoff could not be read safely.") from error
    account, region, name = (discovery[key] for key in ("aws_account_id", "aws_region", "deployment_name"))
    backend = value.get("backend")
    kms = backend.get("kms_key_id") if isinstance(backend, dict) else None
    valid = (
        value.get("schema_version") == "v1"
        and value.get("aws_account_id") == account and _ACCOUNT.fullmatch(account or "") is not None
        and value.get("aws_region") == region and region in {"ap-northeast-1", "ap-northeast-2"}
        and value.get("cluster_name") == name
        and isinstance(value.get("vpc_id"), str) and _VPC.fullmatch(value["vpc_id"]) is not None
        and isinstance(value.get("subnet_id"), str) and _SUBNET.fullmatch(value["subnet_id"]) is not None
        and isinstance(backend, dict)
        and isinstance(backend.get("bucket"), str) and re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]", backend["bucket"]) is not None
        and isinstance(backend.get("dynamodb_table"), str) and _DYNAMODB_TABLE.fullmatch(backend["dynamodb_table"]) is not None
        and backend.get("region") == region
        and backend.get("key") == "node-operator/ops-access/terraform.tfstate"
        and isinstance(kms, str)
        and re.fullmatch(rf"arn:aws:kms:{re.escape(region)}:{re.escape(account)}:key/[A-Za-z0-9-]+", kms) is not None
    )
    if not valid:
        raise OpsAccessError("Baseline ops-access handoff does not bind the selected deployment and isolated state.")
    return value


def _cluster(discovery: dict, handoff: dict, profile: str) -> str:
    account, region, name = (discovery[key] for key in ("aws_account_id", "aws_region", "deployment_name"))
    result = aws_read(profile, region, ["eks", "describe-cluster", "--name", name])
    cluster = result.get("cluster") if isinstance(result, dict) else None
    network = cluster.get("resourcesVpcConfig") if isinstance(cluster, dict) else None
    arn = f"arn:aws:eks:{region}:{account}:cluster/{name}"
    subnets = network.get("subnetIds") if isinstance(network, dict) else None
    security_group = network.get("clusterSecurityGroupId") if isinstance(network, dict) else None
    if not (
        isinstance(cluster, dict) and cluster.get("name") == name and cluster.get("arn") == arn
        and isinstance(network, dict) and network.get("vpcId") == handoff["vpc_id"]
        and isinstance(subnets, list) and handoff["subnet_id"] in subnets
        and isinstance(security_group, str) and _SECURITY_GROUP.fullmatch(security_group) is not None
    ):
        raise OpsAccessError("Live EKS cluster does not bind to the selected baseline VPC, subnet, and account.")
    return security_group


def _expected(directory: Path, handoff_path: Path, handoff: dict, security_group: str) -> dict[str, object]:
    config = {
        "aws_region": handoff["aws_region"], "name": handoff["cluster_name"], "vpc_id": handoff["vpc_id"],
        "subnet_id": handoff["subnet_id"], "cluster_security_group_id": security_group,
        "existing_ssm_endpoint_security_group_id": None, "manage_cluster_ingress_rule": True,
        "manage_existing_endpoint_ingress_rule": False, "retained_host_instance_id": None, "ebs_optimized": True,
    }
    backend = handoff["backend"]
    # jq -r writes its own record newline after the string emitted by the
    # bundled script, whose HCL template itself ends in a newline.
    backend_text = (f'bucket = "{backend["bucket"]}"\nkey = "{backend["key"]}"\nregion = "{backend["region"]}"\n'
                    f'dynamodb_table = "{backend["dynamodb_table"]}"\nencrypt = true\nkms_key_id = "{backend["kms_key_id"]}"\n\n')
    return {
        "ops-access.tfvars.json": config,
        "ops-access.backend.hcl": backend_text,
        "ops-access-inputs.json": {
            "schema_version": 1, "ops_access_handoff": str(handoff_path), "cluster_name": handoff["cluster_name"],
            "cluster_security_group_id": security_group, "config": str(directory / "ops-access.tfvars.json"),
            "backend_config": str(directory / "ops-access.backend.hcl"),
        },
    }


def _validate_tree(directory: Path, expected: dict[str, object]) -> None:
    _private_directory(directory, "Ops-access input directory must be a private regular directory.")
    try:
        children = {child.name for child in directory.iterdir()}
    except OSError as error:
        raise OpsAccessError("Ops-access input directory could not be inspected safely.") from error
    if children != set(expected):
        raise OpsAccessError("Ops-access inputs differ from the selected deployment; nothing was overwritten.")
    for name, value in expected.items():
        path = directory / name
        if isinstance(value, str):
            try:
                descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
                info = os.fstat(descriptor)
                if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 65536:
                    raise OpsAccessError("Ops-access backend input could not be read safely.")
                with os.fdopen(descriptor, "r", encoding="utf-8") as handle:
                    descriptor = -1
                    actual = handle.read()
            except OSError as error:
                raise OpsAccessError("Ops-access backend input could not be read safely.") from error
            finally:
                if 'descriptor' in locals() and descriptor != -1:
                    os.close(descriptor)
            if actual != value:
                raise OpsAccessError("Ops-access inputs differ from the selected deployment; nothing was overwritten.")
        elif json.dumps(_read_object(path), sort_keys=True) != json.dumps(value, sort_keys=True):
            raise OpsAccessError("Ops-access inputs differ from the selected deployment; nothing was overwritten.")


def prepare_ops_access(bundle_root: Path, state_dir: Path, discovery: dict, execution_profile: str) -> Path:
    """Atomically prepare, or safely revalidate, the isolated ops-access inputs."""
    validate_inputs(execution_profile, discovery["aws_region"], discovery["deployment_name"])
    _safe_state_directory(state_dir)
    _private_directory(state_dir, "Installer state directory must be a private regular directory.")
    work_dir = state_dir / "terraform-work"
    _private_directory(work_dir, "Baseline Terraform work directory is unavailable or unsafe.")
    handoff_path = work_dir / "ops-access-handoff.json"
    handoff = _handoff(handoff_path, discovery)
    security_group = _cluster(discovery, handoff, execution_profile)
    destination = state_dir / "ops-access-inputs"
    expected = _expected(destination, handoff_path, handoff, security_group)
    if destination.exists() or destination.is_symlink():
        _validate_tree(destination, expected)
        return destination / "ops-access-inputs.json"
    script = bundle_root / "source/scripts/release/prepare-ops-access-inputs.sh"
    if script.is_symlink() or not script.is_file():
        raise OpsAccessError("Verified release lacks the ops-access input preparation command.")
    environment = os.environ.copy()
    for key in list(environment):
        if key in AWS_CREDENTIAL_OVERRIDES or key in ("BASH_ENV", "ENV"):
            environment.pop(key, None)
    environment.update(AWS_PROFILE=execution_profile, AWS_REGION=discovery["aws_region"],
                       AWS_DEFAULT_REGION=discovery["aws_region"], AWS_PAGER="", AWS_CLI_AUTO_PROMPT="off",
                       AWS_EC2_METADATA_DISABLED="true")
    stage = Path(tempfile.mkdtemp(prefix=".ops-access-inputs-", dir=state_dir))
    generated = stage / "generated"
    try:
        result = subprocess.run(["bash", str(script), "--handoff", str(handoff_path), "--output-dir", str(generated)],
                                env=environment, stdin=subprocess.DEVNULL, capture_output=True, text=True,
                                timeout=30, check=False)
        if result.returncode:
            raise OpsAccessError("Ops-access input preparation failed; no Terraform plan or apply was started.")
        _validate_tree(generated, _expected(generated, handoff_path, handoff, security_group))
        (generated / "ops-access-inputs.json").write_text(json.dumps(expected["ops-access-inputs.json"], sort_keys=True) + "\n", encoding="utf-8")
        os.chmod(generated / "ops-access-inputs.json", 0o600)
        _validate_tree(generated, expected)
        if destination.exists() or destination.is_symlink():
            raise OpsAccessError("Ops-access input destination appeared during preparation.")
        publish_directory(generated, destination)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise OpsAccessError("Ops-access preparation could not complete safely; no Terraform plan or apply was started.") from error
    finally:
        shutil.rmtree(stage)
    return destination / "ops-access-inputs.json"
