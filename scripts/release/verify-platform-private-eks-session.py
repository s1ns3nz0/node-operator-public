#!/usr/bin/env python3
"""Read-only binding check before platform TLS uses the private EKS tunnel.

This adapts the public interactive layout (``deployment-work`` beside the
session handoff) to the canonical live checks in ``installer_ops_verify``.  It
does not initialise Terraform, open an SSM tunnel, or create cloud resources.
"""
from __future__ import annotations

import argparse
from pathlib import Path
import re
import sys

from installer_infrastructure import InfrastructureError, _read_object
from installer_ops_execution import _safe_state
from installer_ops_verify import OpsVerifyError, _live
from installer_preflight import PreflightError, aws_read, validate_inputs


class PlatformSessionError(RuntimeError):
    """A controlled, non-sensitive platform session verification failure."""


_INSTANCE = re.compile(r"i-[0-9a-f]+\Z")
_VPC = re.compile(r"vpc-[0-9a-f]+\Z")
_SUBNET = re.compile(r"subnet-[0-9a-f]+\Z")


def _object(path: Path, message: str) -> dict:
    try:
        value = _read_object(path)
    except InfrastructureError as error:
        raise PlatformSessionError(message) from error
    if not isinstance(value, dict):
        raise PlatformSessionError(message)
    return value


def verify(work_dir: Path, baseline_config: Path, session_path: Path, account: str,
           region: str, profile: str) -> dict:
    """Bind the public work/session layout to the selected live private EKS path."""
    try:
        _safe_state(work_dir)
    except InfrastructureError as error:
        raise PlatformSessionError("Platform Terraform work directory is unsafe.") from error
    expected_session = work_dir.parent / "private-eks-session.json"
    if session_path != expected_session or session_path.is_symlink() or not session_path.is_file():
        raise PlatformSessionError("Private EKS session handoff is not the selected deployment handoff.")
    if baseline_config.is_symlink() or not baseline_config.is_file():
        raise PlatformSessionError("Baseline configuration is unsafe.")
    handoff_path = work_dir / "ops-access-handoff.json"
    if handoff_path.is_symlink() or not handoff_path.is_file():
        raise PlatformSessionError("Ops-access handoff is missing or unsafe.")
    session = _object(session_path, "Private EKS session handoff could not be read safely.")
    handoff = _object(handoff_path, "Ops-access handoff could not be read safely.")
    baseline = _object(baseline_config, "Baseline configuration could not be read safely.")
    name = baseline.get("name")
    if not isinstance(name, str):
        raise PlatformSessionError("Baseline configuration does not bind a deployment name.")
    try:
        validate_inputs(profile, region, name)
    except PreflightError as error:
        raise PlatformSessionError("Selected profile, Region, or deployment name is invalid.") from error
    if not (baseline.get("aws_account_id") == account and baseline.get("aws_region") == region):
        raise PlatformSessionError("Baseline configuration does not bind the selected account and Region.")
    if not (set(session) == {"schema_version", "aws_region", "cluster_name", "ssm_ops_instance_id"}
            and type(session.get("schema_version")) is int and session["schema_version"] == 1
            and session.get("aws_region") == region and session.get("cluster_name") == name
            and isinstance(session.get("ssm_ops_instance_id"), str)
            and _INSTANCE.fullmatch(session["ssm_ops_instance_id"])):
        raise PlatformSessionError("Private EKS session handoff does not match the selected deployment.")
    if not (handoff.get("schema_version") == "v1" and handoff.get("aws_account_id") == account
            and handoff.get("aws_region") == region and handoff.get("cluster_name") == name
            and isinstance(handoff.get("vpc_id"), str) and _VPC.fullmatch(handoff["vpc_id"])
            and isinstance(handoff.get("subnet_id"), str) and _SUBNET.fullmatch(handoff["subnet_id"])):
        raise PlatformSessionError("Ops-access handoff does not bind the selected account, cluster, and network.")
    try:
        identity = aws_read(profile, region, ["sts", "get-caller-identity"])
        if not isinstance(identity, dict) or identity.get("Account") != account:
            raise PlatformSessionError("Current AWS identity does not match the selected account.")
        _live({"aws_account_id": account, "aws_region": region, "deployment_name": name}, profile,
              session, handoff)
    except (PreflightError, OpsVerifyError) as error:
        raise PlatformSessionError("Private EKS session is not currently bound to the selected live deployment.") from error
    return session


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--work-dir", required=True, type=Path)
    parser.add_argument("--baseline-config", required=True, type=Path)
    parser.add_argument("--session", required=True, type=Path)
    parser.add_argument("--account", required=True)
    parser.add_argument("--region", required=True)
    parser.add_argument("--profile", required=True)
    args = parser.parse_args()
    try:
        session = verify(args.work_dir, args.baseline_config, args.session, args.account, args.region, args.profile)
    except PlatformSessionError as error:
        print(str(error), file=sys.stderr)
        return 65
    print(f'{session["cluster_name"]}\t{session["ssm_ops_instance_id"]}')
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
