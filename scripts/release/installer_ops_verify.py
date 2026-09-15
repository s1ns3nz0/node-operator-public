"""Bounded read-only verification of the private ops-access path."""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import signal
import subprocess

from installer_infrastructure import InfrastructureError, _read_object
from installer_ops_execution import _environment, _identity, _private, _safe_state
from installer_preflight import AWS_CREDENTIAL_OVERRIDES, aws_read


class OpsVerifyError(InfrastructureError):
    """Controlled non-sensitive failure; it never asserts EKS readiness."""


_INSTANCE = re.compile(r"i-[0-9a-f]+\Z")
_VPC = re.compile(r"vpc-[0-9a-f]+\Z")
_SUBNET = re.compile(r"subnet-[0-9a-f]+\Z")


def _object(path: Path, message: str) -> dict:
    try:
        return _read_object(path)
    except InfrastructureError as error:
        raise OpsVerifyError(message) from error


def _capable(bundle_root: Path) -> None:
    contract = _object(bundle_root / "source/release/hoodi-release-contract.json", "Verified release capability contract could not be read safely.")
    bootstrap = contract.get("bootstrap")
    if (not isinstance(bootstrap, dict) or type(bootstrap.get("interactive_ops_verify_schema")) is not int
            or bootstrap.get("interactive_ops_verify_schema") != 1):
        raise OpsVerifyError("This release does not support guarded private ops-access verification.")


def _context(state_dir: Path, discovery: dict) -> tuple[dict, dict]:
    session = _object(state_dir / "private-eks-session.json", "Private EKS session handoff could not be read safely.")
    handoff = _object(state_dir / "terraform-work/ops-access-handoff.json", "Infrastructure ops-access handoff could not be read safely.")
    if not (set(session) == {"schema_version", "aws_region", "cluster_name", "ssm_ops_instance_id"}
            and type(session.get("schema_version")) is int and session["schema_version"] == 1
            and isinstance(session.get("aws_region"), str) and session["aws_region"] == discovery["aws_region"]
            and isinstance(session.get("cluster_name"), str) and session["cluster_name"] == discovery["deployment_name"]
            and isinstance(session.get("ssm_ops_instance_id"), str) and _INSTANCE.fullmatch(session["ssm_ops_instance_id"])):
        raise OpsVerifyError("Private EKS session handoff does not match the selected deployment.")
    _private(state_dir / "terraform-work", "Infrastructure Terraform work directory is unavailable or unsafe.")
    if not (handoff.get("schema_version") == "v1" and handoff.get("aws_account_id") == discovery["aws_account_id"] and handoff.get("aws_region") == discovery["aws_region"]
            and handoff.get("cluster_name") == discovery["deployment_name"] and isinstance(handoff.get("vpc_id"), str)
            and _VPC.fullmatch(handoff["vpc_id"]) and isinstance(handoff.get("subnet_id"), str) and _SUBNET.fullmatch(handoff["subnet_id"])):
        raise OpsVerifyError("Infrastructure ops-access handoff does not bind the selected account, cluster, and network.")
    return session, handoff


def _live(discovery: dict, profile: str, session: dict, handoff: dict) -> None:
    region, account, name = discovery["aws_region"], discovery["aws_account_id"], discovery["deployment_name"]
    instance_id = session["ssm_ops_instance_id"]
    information = aws_read(profile, region, ["ssm", "describe-instance-information", "--filters", f"Key=InstanceIds,Values={instance_id}"])
    entries = information.get("InstanceInformationList") if isinstance(information, dict) else None
    if not (isinstance(entries, list) and len(entries) == 1 and isinstance(entries[0], dict)
            and entries[0].get("InstanceId") == instance_id and entries[0].get("PingStatus") == "Online"
            and entries[0].get("PlatformType") == "Linux" and entries[0].get("ResourceType") == "EC2Instance"):
        raise OpsVerifyError("Ops instance is not online in SSM; wait and retry without marking verification complete.")
    ec2 = aws_read(profile, region, ["ec2", "describe-instances", "--instance-ids", instance_id])
    reservations = ec2.get("Reservations") if isinstance(ec2, dict) else None
    instances = [item for reservation in reservations or [] if isinstance(reservation, dict) for item in reservation.get("Instances", []) if isinstance(item, dict)]
    if not (isinstance(reservations, list) and len(instances) == 1 and instances[0].get("InstanceId") == instance_id
            and isinstance(instances[0].get("State"), dict) and instances[0]["State"].get("Name") == "running"
            and instances[0].get("VpcId") == handoff["vpc_id"] and instances[0].get("SubnetId") == handoff["subnet_id"]
            and not instances[0].get("PublicIpAddress")):
        raise OpsVerifyError("Ops instance does not match the private selected VPC and subnet.")
    response = aws_read(profile, region, ["eks", "describe-cluster", "--name", name])
    cluster = response.get("cluster") if isinstance(response, dict) else None
    network = cluster.get("resourcesVpcConfig") if isinstance(cluster, dict) else None
    arn = f"arn:aws:eks:{region}:{account}:cluster/{name}"
    if not (isinstance(cluster, dict) and cluster.get("name") == name and cluster.get("arn") == arn
            and isinstance(network, dict) and network.get("vpcId") == handoff["vpc_id"]
            and network.get("endpointPublicAccess") is False and network.get("endpointPrivateAccess") is True):
        raise OpsVerifyError("Live EKS cluster does not match the selected private endpoint context.")


def _environment_for_verify(profile: str, discovery: dict, session: dict) -> dict[str, str]:
    environment = _environment(profile, discovery)
    for key in list(environment):
        if key in AWS_CREDENTIAL_OVERRIDES or key in ("PRIVATE_EKS_SESSION", "KUBECONFIG", "BASH_ENV", "ENV"):
            environment.pop(key, None)
    environment.update(AWS_PROFILE=profile, AWS_REGION=discovery["aws_region"], AWS_DEFAULT_REGION=discovery["aws_region"],
                       EKS_CLUSTER_NAME=discovery["deployment_name"], SSM_OPS_INSTANCE_ID=session["ssm_ops_instance_id"],
                       AWS_EC2_METADATA_DISABLED="true")
    return environment


def _namespace(command: list[str], environment: dict[str, str]) -> None:
    try:
        process = subprocess.Popen(command, env=environment, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, text=True, start_new_session=True)
    except OSError as error:
        raise OpsVerifyError("Private EKS verification command could not start.") from error
    def stop() -> None:
        try:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except OSError:
                pass
            process.communicate(timeout=30)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except OSError:
                pass
            try:
                process.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                pass

    try:
        stdout, _ = process.communicate(timeout=150)
    except subprocess.TimeoutExpired:
        stop()
        raise OpsVerifyError("Private EKS namespace verification timed out; session cleanup was requested and completion was not recorded.")
    except BaseException:
        stop()
        raise
    if process.returncode:
        raise OpsVerifyError("Private EKS verification command failed or its cleanup failed; completion was not recorded.")
    try:
        value = json.loads(stdout)
    except (TypeError, ValueError) as error:
        raise OpsVerifyError("Private EKS verification did not return the expected namespace result.") from error
    if not (isinstance(value, dict) and value.get("kind") == "Namespace"
            and isinstance(value.get("metadata"), dict) and value["metadata"].get("name") == "kube-system"):
        raise OpsVerifyError("Private EKS verification did not confirm the kube-system namespace.")


def verify_ops_access(bundle_root: Path, state_dir: Path, discovery: dict, profile: str) -> None:
    """Verify only the bounded private path; caller records completion separately."""
    _safe_state(state_dir)
    _capable(bundle_root)
    session, handoff = _context(state_dir, discovery)
    _identity(discovery, profile)
    _live(discovery, profile, session, handoff)
    wrapper = bundle_root / "source/scripts/ops/with-private-eks.sh"
    if wrapper.is_symlink() or not wrapper.is_file():
        raise OpsVerifyError("Verified release lacks the private EKS wrapper.")
    _namespace(["bash", str(wrapper), "--", "kubectl", "--request-timeout=20s", "get", "namespace", "kube-system", "-o", "json"],
               _environment_for_verify(profile, discovery, session))
