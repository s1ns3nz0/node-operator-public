#!/usr/bin/env python3
"""Fail-closed Fluent Bit collector installation for the interactive release.

This command performs live read checks before applying collector objects and
rebinding exactly one existing Kyverno ClusterPolicy image exception.
It deliberately does not accept an image, endpoint, or ConfigMap on the CLI:
those values are bound to the verified release, selected AWS account/VPC, and
private EKS session respectively.
"""
from __future__ import annotations

import argparse
from collections.abc import Mapping
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
from typing import Any, Callable

from installer_full_artifact_mirror import FullMirrorError, verify as verify_full_mirror


ROOT = Path(__file__).resolve().parents[2]
_SHA = re.compile(r"[0-9a-f]{40}\Z")
_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_REGION = re.compile(r"[a-z]{2}-[a-z0-9-]+-[1-9][0-9]*\Z")
_NAME = re.compile(r"[a-z][a-z0-9-]{1,38}[a-z0-9]\Z")
_SET = re.compile(r"hoodi-[a-z0-9][a-z0-9-]*\Z")
_VPC = re.compile(r"vpc-[0-9a-f]+\Z")
_IMAGE = re.compile(r"([0-9]{12})\.dkr\.ecr\.([a-z0-9-]+)\.amazonaws\.com/[a-z0-9][a-z0-9._/-]*@sha256:[0-9a-f]{64}\Z")


class CollectorInstallError(RuntimeError):
    pass


def _is_aws_endpoint_url_override(name: str) -> bool:
    return name == "AWS_ENDPOINT_URL" or name.startswith("AWS_ENDPOINT_URL_")


def _has_aws_endpoint_url_override(environ: Mapping[str, str]) -> bool:
    return any(_is_aws_endpoint_url_override(name) for name in environ)


def _module(name: str, path: Path):
    try:
        info = path.lstat()
        if path.is_symlink() or not stat.S_ISREG(info.st_mode): raise OSError
    except OSError as error:
        raise CollectorInstallError("verified release module is unavailable") from error
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise CollectorInstallError("release collector dependency is unavailable")
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def _bound_sources(bundle_root: Path, release_sha: str) -> Path:
    """Verify every bundle-owned file before importing or parsing it."""
    manifest = _safe_object(bundle_root / "bundle-manifest.json", "bundle manifest is unavailable")
    if manifest.get("source_revision") != release_sha or not isinstance(manifest.get("entries"), list):
        raise CollectorInstallError("bundle manifest does not bind the selected release revision")
    required = (
        "source/scripts/release/verify-platform-private-eks-session.py",
        "source/scripts/release/validator_log_collector.py",
        "source/scripts/release/validator_log_collector_policy.py",
        "source/deploy/observability/fluent-bit-config.yaml",
        "source/deploy/kyverno/policies/node-operator-project-workload-baseline.yaml",
        "source/scripts/ops/with-private-eks.sh",
    )
    entries = manifest["entries"]
    for relative in required:
        rows = [row for row in entries if isinstance(row, dict) and row.get("path") == relative]
        if len(rows) != 1 or not isinstance(rows[0].get("sha256"), str) or re.fullmatch(r"[0-9a-f]{64}", rows[0]["sha256"]) is None:
            raise CollectorInstallError("bundle manifest source entry is absent or ambiguous")
        path = bundle_root / relative
        try:
            info = path.lstat()
            if path.is_symlink() or not stat.S_ISREG(info.st_mode) or hashlib.sha256(path.read_bytes()).hexdigest() != rows[0]["sha256"]: raise OSError
        except OSError as error:
            raise CollectorInstallError("bundle source file differs from its verified manifest entry") from error
    return bundle_root / "source"


def _safe_object(path: Path, message: str) -> dict[str, Any]:
    try:
        info = path.lstat()
        if path.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_size > 1024 * 1024:
            raise OSError
        value = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as error:
        raise CollectorInstallError(message) from error
    if not isinstance(value, dict):
        raise CollectorInstallError(message)
    return value


def _run(runner: Callable[..., subprocess.CompletedProcess[str]], command: list[str], *, env: dict[str, str], input: str | None = None) -> subprocess.CompletedProcess[str]:
    try:
        result = runner(command, check=False, capture_output=True, text=True, env=env, input=input, timeout=180)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise CollectorInstallError("collector verification command failed") from error
    if result.returncode:
        raise CollectorInstallError("collector verification command failed")
    return result


def _release_config(source_root: Path) -> dict[str, str]:
    path = source_root / "deploy/observability/fluent-bit-config.yaml"
    try:
        info = path.lstat()
        if path.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_size > 1024 * 1024:
            raise OSError
        text = path.read_text()
        fluent = text.split("  fluent-bit.conf: |\n", 1)[1].split("  parsers.conf: |\n", 1)[0]
        parsers = text.split("  parsers.conf: |\n", 1)[1]
    except (OSError, IndexError) as error:
        raise CollectorInstallError("release-owned Fluent Bit ConfigMap data is unavailable") from error
    data = {
        "fluent-bit.conf": "\n".join(line[4:] for line in fluent.splitlines()) + "\n",
        "parsers.conf": "\n".join(line[4:] for line in parsers.splitlines()) + "\n",
    }
    if not all(data.values()):
        raise CollectorInstallError("release-owned Fluent Bit ConfigMap data is invalid")
    return data


def _artifact(receipt: dict[str, Any], account: str, region: str) -> str:
    rows = receipt.get("artifacts")
    matches = [row for row in rows if isinstance(row, dict) and row.get("component") == "validator-log-collector"] if isinstance(rows, list) else []
    if len(matches) != 1 or set(matches[0]) != {"component", "image_ref", "tag", "manifest_digest"}:
        raise CollectorInstallError("verified Fluent Bit artifact is absent or ambiguous")
    image = matches[0]["image_ref"]
    digest = matches[0]["manifest_digest"]
    found = _IMAGE.fullmatch(image) if isinstance(image, str) else None
    if found is None or found.group(1) != account or found.group(2) != region or digest != image.rsplit("@", 1)[1]:
        raise CollectorInstallError("verified Fluent Bit artifact is not the selected private ECR digest")
    return image


def _logs_ips(runner: Callable[..., subprocess.CompletedProcess[str]], env: dict[str, str], account: str, region: str, vpc: str) -> list[str]:
    endpoints = _run(runner, ["aws", "ec2", "describe-vpc-endpoints", "--region", region, "--filters", f"Name=vpc-id,Values={vpc}", f"Name=service-name,Values=com.amazonaws.{region}.logs", "--output", "json"], env=env)
    try:
        decoded = json.loads(endpoints.stdout)
        rows = decoded.get("VpcEndpoints") if isinstance(decoded, dict) and "NextToken" not in decoded else None
    except json.JSONDecodeError as error:
        raise CollectorInstallError("CloudWatch Logs endpoint response is malformed") from error
    if not isinstance(rows, list) or len(rows) != 1 or not isinstance(rows[0], dict):
        raise CollectorInstallError("selected VPC has no unique CloudWatch Logs endpoint")
    endpoint = rows[0]
    ids = endpoint.get("NetworkInterfaceIds")
    subnets = endpoint.get("SubnetIds")
    if (endpoint.get("VpcId") != vpc or endpoint.get("OwnerId") != account or endpoint.get("ServiceName") != f"com.amazonaws.{region}.logs"
            or endpoint.get("VpcEndpointType") != "Interface" or endpoint.get("State") != "available" or endpoint.get("PrivateDnsEnabled") is not True
            or not isinstance(ids, list) or not ids or any(not isinstance(x, str) for x in ids) or len(set(ids)) != len(ids)
            or not isinstance(subnets, list) or not subnets or any(not isinstance(x, str) for x in subnets) or len(set(subnets)) != len(subnets)):
        raise CollectorInstallError("CloudWatch Logs endpoint is not bound to the selected VPC")
    enis = _run(runner, ["aws", "ec2", "describe-network-interfaces", "--region", region, "--network-interface-ids", *ids, "--output", "json"], env=env)
    try:
        decoded = json.loads(enis.stdout)
        interfaces = decoded.get("NetworkInterfaces") if isinstance(decoded, dict) and "NextToken" not in decoded else None
    except json.JSONDecodeError as error:
        raise CollectorInstallError("CloudWatch Logs endpoint ENI response is malformed") from error
    if not isinstance(interfaces, list) or len(interfaces) != len(ids):
        raise CollectorInstallError("CloudWatch Logs endpoint ENIs are incomplete")
    values: list[str] = []; eni_ids: set[str] = set(); eni_subnets: set[str] = set()
    for item in interfaces:
        ip = item.get("PrivateIpAddress") if isinstance(item, dict) else None
        if (not isinstance(item, dict) or item.get("NetworkInterfaceId") not in ids or item.get("VpcId") != vpc
                or item.get("OwnerId") != account or item.get("SubnetId") not in subnets or item.get("RequesterManaged") is not True or item.get("InterfaceType") != "vpc_endpoint"
                or not isinstance(ip, str)):
            raise CollectorInstallError("CloudWatch Logs endpoint ENI is outside the selected account or VPC")
        try:
            parsed = ipaddress.ip_address(ip)
        except ValueError as error:
            raise CollectorInstallError("CloudWatch Logs endpoint ENI address is invalid") from error
        if parsed.version != 4 or not parsed.is_private:
            raise CollectorInstallError("CloudWatch Logs endpoint ENI address is not private IPv4")
        values.append(str(parsed))
        eni_ids.add(item["NetworkInterfaceId"]); eni_subnets.add(item["SubnetId"])
    if eni_ids != set(ids) or eni_subnets != set(subnets) or len(set(values)) != len(values):
        raise CollectorInstallError("CloudWatch Logs endpoint ENI addresses are ambiguous")
    return sorted(values)


def _kubernetes_service_ip(runner: Callable[..., subprocess.CompletedProcess[str]], env: dict[str, str], source_root: Path) -> str:
    tunnel = source_root / "scripts/ops/with-private-eks.sh"
    if not tunnel.is_file() or tunnel.is_symlink():
        raise CollectorInstallError("release private EKS tunnel helper is unavailable")
    result = _run(runner, ["bash", str(tunnel), "--", "env", "PRIVATE_EKS_SESSION=1", "kubectl", "-n", "default", "get", "service", "kubernetes", "-o", "json"], env=env)
    try:
        value = json.loads(result.stdout)
        ip = value["spec"]["clusterIP"]
        parsed = ipaddress.ip_address(ip)
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
        raise CollectorInstallError("private Kubernetes service response is invalid") from error
    if parsed.version != 4 or not parsed.is_private:
        raise CollectorInstallError("private Kubernetes service IP is invalid")
    return str(parsed)


def _rebound_policy(runner: Callable[..., subprocess.CompletedProcess[str]], env: dict[str, str], source_root: Path, policy_module: Any, image: str) -> dict[str, Any]:
    path = source_root / "deploy/kyverno/policies/node-operator-project-workload-baseline.yaml"
    if not path.is_file() or path.is_symlink():
        raise CollectorInstallError("release-owned collector policy is unavailable")
    tunnel = source_root / "scripts/ops/with-private-eks.sh"
    parsed = _run(runner, ["bash", str(tunnel), "--", "env", "PRIVATE_EKS_SESSION=1", "kubectl", "create", "--dry-run=client", "-f", str(path), "-o", "json"], env=env)
    try:
        value = json.loads(parsed.stdout)
    except json.JSONDecodeError as error:
        raise CollectorInstallError("release-owned collector policy is not valid Kubernetes JSON") from error
    try:
        rebound = policy_module.render(value, image)
    except Exception as error:
        raise CollectorInstallError("collector policy cannot be rebound to the verified image") from error
    if not isinstance(rebound, dict) or rebound.get("kind") != "ClusterPolicy" or rebound.get("metadata", {}).get("name") != "node-operator-project-workload-baseline":
        raise CollectorInstallError("collector policy rebinding produced an unsafe object")
    live = _run(runner, ["bash", str(tunnel), "--", "env", "PRIVATE_EKS_SESSION=1", "kubectl", "get", "clusterpolicy", "node-operator-project-workload-baseline", "-o", "json"], env=env)
    try:
        current = json.loads(live.stdout)
        ready = current.get("status", {}).get("conditions", [])
    except (AttributeError, json.JSONDecodeError) as error:
        raise CollectorInstallError("live collector policy response is invalid") from error
    # Compare serialized specs to avoid trusting server metadata/status, which
    # are expected to differ from the reviewed source representation.
    if (not isinstance(current, dict)
            or json.dumps(current.get("spec"), sort_keys=True) not in {json.dumps(value.get("spec"), sort_keys=True), json.dumps(rebound.get("spec"), sort_keys=True)}):
        raise CollectorInstallError("live collector policy differs from the reviewed policy")
    if not isinstance(ready, list) or not any(isinstance(row, dict) and row.get("type") == "Ready" and str(row.get("status")).casefold() == "true" for row in ready):
        raise CollectorInstallError("live collector policy is not Ready")
    return rebound


def install(*, bundle_root: Path, state_dir: Path, work_dir: Path, inputs_dir: Path, session: Path, baseline_config: Path, account: str, region: str, deployment: str, validator_set: str, profile: str, release_sha: str, runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run) -> None:
    """Verify all authorities, then apply and roll out only renderer-owned objects."""
    if _has_aws_endpoint_url_override(os.environ):
        raise CollectorInstallError("AWS endpoint URL environment overrides are prohibited")
    if not (_ACCOUNT.fullmatch(account) and _REGION.fullmatch(region) and _NAME.fullmatch(deployment) and _SET.fullmatch(validator_set) and _SHA.fullmatch(release_sha)):
        raise CollectorInstallError("collector release identity is invalid")
    source_root = _bound_sources(bundle_root, release_sha)
    try:
        discovery = {"aws_account_id": account, "aws_region": region, "deployment_name": deployment}
        receipt = verify_full_mirror(state_dir, bundle_root, discovery, profile, release_sha, work_dir=work_dir, inputs_dir=inputs_dir, runner=runner)
    except (FullMirrorError, RuntimeError) as error:
        raise CollectorInstallError("private EKS session or full artifact mirror is not verified") from error
    image = _artifact(receipt, account, region)
    session_helper = _module("platform_session", source_root / "scripts/release/verify-platform-private-eks-session.py")
    collector = _module("validator_log_collector", source_root / "scripts/release/validator_log_collector.py")
    policy_module = _module("validator_log_collector_policy", source_root / "scripts/release/validator_log_collector_policy.py")
    try: selected_session = session_helper.verify(work_dir, baseline_config, session, account, region, profile)
    except RuntimeError as error: raise CollectorInstallError("private EKS session is not verified") from error
    handoff = _safe_object(work_dir / "ops-access-handoff.json", "selected VPC handoff is unavailable")
    vpc = handoff.get("vpc_id")
    if not isinstance(vpc, str) or _VPC.fullmatch(vpc) is None:
        raise CollectorInstallError("selected VPC handoff is invalid")
    if selected_session.get("cluster_name") != deployment or selected_session.get("aws_region") != region:
        raise CollectorInstallError("verified private EKS session does not match the selected deployment")
    env = dict(os.environ, AWS_PROFILE=profile, AWS_REGION=region, AWS_DEFAULT_REGION=region, AWS_EC2_METADATA_DISABLED="true", EKS_CLUSTER_NAME=deployment, SSM_OPS_INSTANCE_ID=selected_session["ssm_ops_instance_id"])
    for name in tuple(env):
        if _is_aws_endpoint_url_override(name):
            env.pop(name)
    for name in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_SECURITY_TOKEN", "AWS_ACCESS_KEY", "AWS_SECRET_KEY", "AWS_DEFAULT_PROFILE", "AWS_WEB_IDENTITY_TOKEN_FILE", "AWS_ROLE_ARN", "AWS_ROLE_SESSION_NAME", "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "AWS_CONTAINER_CREDENTIALS_FULL_URI", "AWS_CONTAINER_AUTHORIZATION_TOKEN", "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE", "KUBECONFIG", "PRIVATE_EKS_SESSION", "BASH_ENV", "ENV"):
        env.pop(name, None)
    logs = _logs_ips(runner, env, account, region, vpc)
    api = _kubernetes_service_ip(runner, env, source_root)
    policy = _rebound_policy(runner, env, source_root, policy_module, image)
    try:
        rendered = collector.render(account=account, region=region, deployment=deployment, validator_set=validator_set, image_ref=image, logs_endpoint_ipv4s=logs, kubernetes_api_service_ipv4=api, fluent_bit_config=_release_config(source_root))
    except Exception as error:
        raise CollectorInstallError("collector rendering rejected verified inputs") from error
    items = rendered.get("items") if isinstance(rendered, dict) else None
    allowed = {("Namespace", "validator-observability"), ("ServiceAccount", "validator-log-collector"), ("ClusterRole", "validator-log-collector-metadata"), ("ClusterRoleBinding", "validator-log-collector-metadata"), ("ClusterPolicy", "node-operator-project-workload-baseline"), ("DaemonSet", "validator-log-collector"), ("NetworkPolicy", "default-deny-ingress-egress"), ("NetworkPolicy", "allow-collector-dns-and-private-aws-endpoints")}
    observed = {(x.get("kind"), x.get("metadata", {}).get("name")) for x in items if isinstance(x, dict)} if isinstance(items, list) else set()
    configs = {item for item in observed if item[0] == "ConfigMap" and isinstance(item[1], str) and re.fullmatch(r"validator-log-collector-config-[0-9a-f]{12}", item[1])}
    if not isinstance(items, list) or len(items) != 8 or len(configs) != 1 or observed != (allowed - {("ClusterPolicy", "node-operator-project-workload-baseline")}) | configs:
        raise CollectorInstallError("renderer produced objects outside the collector allowlist")
    for item in items:
        kind, metadata = item.get("kind"), item.get("metadata", {})
        namespace = metadata.get("namespace") if isinstance(metadata, dict) else None
        if kind in {"ClusterRole", "ClusterRoleBinding", "Namespace"}:
            if namespace is not None: raise CollectorInstallError("renderer produced a cluster object with a namespace")
        elif namespace != "validator-observability":
            raise CollectorInstallError("renderer produced an object outside the collector namespace")
    early = [item for item in items if item["kind"] in {"Namespace", "NetworkPolicy"}]
    remaining = [item for item in items if item not in early]
    try:
        fd, temporary = tempfile.mkstemp(prefix=".validator-log-collector-", suffix=".json", dir=state_dir)
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w") as handle:
            json.dump({"apiVersion": "v1", "kind": "List", "items": early}, handle, separators=(",", ":")); handle.write("\n")
        remaining_fd, remaining_file = tempfile.mkstemp(prefix=".validator-log-collector-objects-", suffix=".json", dir=state_dir)
        os.fchmod(remaining_fd, 0o600)
        with os.fdopen(remaining_fd, "w") as handle:
            json.dump({"apiVersion": "v1", "kind": "List", "items": remaining}, handle, separators=(",", ":")); handle.write("\n")
        policy_fd, policy_file = tempfile.mkstemp(prefix=".validator-log-collector-policy-", suffix=".json", dir=state_dir)
        os.fchmod(policy_fd, 0o600)
        with os.fdopen(policy_fd, "w") as handle:
            json.dump(policy, handle, separators=(",", ":")); handle.write("\n")
        tunnel = ["bash", str(source_root / "scripts/ops/with-private-eks.sh"), "--", "env", "PRIVATE_EKS_SESSION=1", "kubectl"]
        _run(runner, [*tunnel, "apply", "--server-side", "--dry-run=server", "-f", policy_file], env=env)
        _run(runner, [*tunnel, "apply", "-f", policy_file], env=env)
        _run(runner, [*tunnel, "wait", "--for=condition=Ready", "clusterpolicy/node-operator-project-workload-baseline", "--timeout=180s"], env=env)
        _run(runner, [*tunnel, "apply", "-f", temporary], env=env)
        _run(runner, [*tunnel, "apply", "-f", remaining_file], env=env)
        _run(runner, ["bash", str(source_root / "scripts/ops/with-private-eks.sh"), "--", "env", "PRIVATE_EKS_SESSION=1", "kubectl", "-n", "validator-observability", "rollout", "status", "daemonset/validator-log-collector", "--timeout=180s"], env=env)
    finally:
        try: os.unlink(temporary)
        except (FileNotFoundError, UnboundLocalError): pass
        try: os.unlink(policy_file)
        except (FileNotFoundError, UnboundLocalError): pass
        try: os.unlink(remaining_file)
        except (FileNotFoundError, UnboundLocalError): pass


def main() -> int:
    parser = argparse.ArgumentParser()
    for name in ("bundle-root", "state-dir", "work-dir", "inputs-dir", "session", "baseline-config"):
        parser.add_argument("--" + name, required=True, type=Path)
    for name in ("account", "region", "deployment", "validator-set", "profile", "release-sha"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    try:
        install(bundle_root=args.bundle_root, state_dir=args.state_dir, work_dir=args.work_dir, inputs_dir=args.inputs_dir, session=args.session, baseline_config=args.baseline_config, account=args.account, region=args.region, deployment=args.deployment, validator_set=args.validator_set, profile=args.profile, release_sha=args.release_sha)
    except CollectorInstallError as error:
        print(str(error), file=sys.stderr); return 65
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
