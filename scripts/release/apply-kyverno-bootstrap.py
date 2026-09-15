#!/usr/bin/env python3
"""Install the release-bound Kyverno chart before dependent policy consumers.

Only the verified full private mirror supplies the chart and runtime images.
The command deliberately has no chart, registry, or migration-disable flags.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
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

_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_REGION = re.compile(r"[a-z]{2}-[a-z0-9-]+-[1-9][0-9]*\Z")
_NAME = re.compile(r"[a-z][a-z0-9-]{1,38}[a-z0-9]\Z")
_SHA = re.compile(r"[0-9a-f]{40}\Z")


class KyvernoBootstrapError(RuntimeError):
    pass


def _aws_override(name: str) -> bool:
    return name == "AWS_ENDPOINT_URL" or name.startswith("AWS_ENDPOINT_URL_")


def _object(path: Path, message: str) -> dict[str, Any]:
    try:
        info = path.lstat()
        if path.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_size > 1024 * 1024:
            raise OSError
        value = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as error:
        raise KyvernoBootstrapError(message) from error
    if not isinstance(value, dict):
        raise KyvernoBootstrapError(message)
    return value


def _module(name: str, path: Path) -> Any:
    try:
        info = path.lstat()
        if path.is_symlink() or not stat.S_ISREG(info.st_mode):
            raise OSError
    except OSError as error:
        raise KyvernoBootstrapError("verified release module is unavailable") from error
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise KyvernoBootstrapError("verified release module is unavailable")
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def _bound_source(bundle_root: Path, release_sha: str) -> Path:
    manifest = _object(bundle_root / "bundle-manifest.json", "bundle manifest is unavailable")
    entries = manifest.get("entries")
    if manifest.get("source_revision") != release_sha or not isinstance(entries, list):
        raise KyvernoBootstrapError("bundle manifest does not bind the selected release revision")
    required = (
        "source/scripts/release/verify-platform-private-eks-session.py",
        "source/scripts/release/kyverno_bootstrap_inputs.py",
        "source/scripts/ops/with-private-eks.sh",
        "source/deploy/kyverno/policies/node-operator-project-workload-baseline.yaml",
    )
    for relative in required:
        rows = [row for row in entries if isinstance(row, dict) and row.get("path") == relative]
        path = bundle_root / relative
        try:
            info = path.lstat()
            if len(rows) != 1 or path.is_symlink() or not stat.S_ISREG(info.st_mode) or not isinstance(rows[0].get("sha256"), str) or hashlib.sha256(path.read_bytes()).hexdigest() != rows[0]["sha256"]:
                raise OSError
        except OSError as error:
            raise KyvernoBootstrapError("bundle source differs from its verified manifest entry") from error
    return bundle_root / "source"


def _run(runner: Callable[..., subprocess.CompletedProcess[str]], command: list[str], env: dict[str, str], *, input: str | None = None) -> subprocess.CompletedProcess[str]:
    try:
        # Helm is allowed five minutes and an atomic failure may still need to
        # roll back.  Keep the parent deadline beyond that operation so it
        # cannot terminate Helm in the middle of its cleanup.
        result = runner(command, check=False, capture_output=True, text=True, env=env, input=input, timeout=660)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise KyvernoBootstrapError("Kyverno bootstrap command failed") from error
    if result.returncode:
        raise KyvernoBootstrapError("Kyverno bootstrap command failed")
    return result


def install(*, bundle_root: Path, state_dir: Path, work_dir: Path, inputs_dir: Path, session: Path, baseline_config: Path, account: str, region: str, deployment: str, profile: str, release_sha: str, runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run) -> None:
    """Verify all authorities, install private Kyverno, then establish policy readiness."""
    if any(_aws_override(name) for name in os.environ):
        raise KyvernoBootstrapError("AWS endpoint URL environment overrides are prohibited")
    if not (_ACCOUNT.fullmatch(account) and _REGION.fullmatch(region) and _NAME.fullmatch(deployment) and _SHA.fullmatch(release_sha)):
        raise KyvernoBootstrapError("Kyverno release identity is invalid")
    source = _bound_source(bundle_root, release_sha)
    try:
        receipt = verify_full_mirror(state_dir, bundle_root, {"aws_account_id": account, "aws_region": region, "deployment_name": deployment}, profile, release_sha, work_dir=work_dir, inputs_dir=inputs_dir, runner=runner)
    except (FullMirrorError, RuntimeError) as error:
        raise KyvernoBootstrapError("full private artifact mirror is not verified") from error
    inputs = _module("kyverno_bootstrap_inputs", source / "scripts/release/kyverno_bootstrap_inputs.py")
    session_helper = _module("platform_session", source / "scripts/release/verify-platform-private-eks-session.py")
    try:
        rendered = inputs.render(receipt, account, region, deployment)
        selected = session_helper.verify(work_dir, baseline_config, session, account, region, profile)
    except Exception as error:
        raise KyvernoBootstrapError("Kyverno bootstrap inputs or private EKS session are invalid") from error
    if selected.get("cluster_name") != deployment or selected.get("aws_region") != region or not isinstance(selected.get("ssm_ops_instance_id"), str):
        raise KyvernoBootstrapError("verified private EKS session does not match the selected deployment")
    chart = rendered.get("chart_ref") if isinstance(rendered, dict) else None
    values = rendered.get("values") if isinstance(rendered, dict) else None
    crds = values.get("crds") if isinstance(values, dict) else None
    migration = crds.get("migration") if isinstance(crds, dict) else None
    if not isinstance(chart, str) or not chart.startswith("oci://") or "@sha256:" not in chart or not isinstance(values, dict) or not isinstance(migration, dict) or migration.get("enabled") is not True:
        raise KyvernoBootstrapError("Kyverno chart is not immutable or CRD migration is disabled")
    env = dict(os.environ, AWS_PROFILE=profile, AWS_REGION=region, AWS_DEFAULT_REGION=region, AWS_EC2_METADATA_DISABLED="true", EKS_CLUSTER_NAME=deployment, SSM_OPS_INSTANCE_ID=selected["ssm_ops_instance_id"])
    for name in tuple(env):
        if _aws_override(name) or name in {"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_SECURITY_TOKEN", "AWS_ACCESS_KEY", "AWS_SECRET_KEY", "AWS_DEFAULT_PROFILE", "AWS_WEB_IDENTITY_TOKEN_FILE", "AWS_ROLE_ARN", "AWS_ROLE_SESSION_NAME", "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "AWS_CONTAINER_CREDENTIALS_FULL_URI", "AWS_CONTAINER_AUTHORIZATION_TOKEN", "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE", "KUBECONFIG", "PRIVATE_EKS_SESSION", "BASH_ENV", "ENV"}:
            env.pop(name, None)
    policy = source / "deploy/kyverno/policies/node-operator-project-workload-baseline.yaml"
    tunnel = ["bash", str(source / "scripts/ops/with-private-eks.sh"), "--", "env", "PRIVATE_EKS_SESSION=1"]
    try:
        values_fd, values_path = tempfile.mkstemp(prefix=".kyverno-values-", suffix=".json", dir=state_dir); os.fchmod(values_fd, 0o600)
        with os.fdopen(values_fd, "w") as handle: json.dump(values, handle, separators=(",", ":")); handle.write("\n")
        _run(runner, [*tunnel, "helm", "upgrade", "--install", "kyverno", chart, "--namespace", "kyverno", "--create-namespace", "--values", values_path, "--wait", "--timeout", "5m", "--atomic"], env)
        # ClusterPolicy is a Kyverno CRD.  Client-side resource mapping before
        # Helm would reject a fresh cluster because discovery has not seen that
        # CRD yet.  Render only after Helm establishes it; retain the stronger
        # server-side dry run before any policy is persisted.
        policy_json = _run(runner, [*tunnel, "kubectl", "create", "--dry-run=client", "-f", str(policy), "-o", "json"], env).stdout
        policy_value = json.loads(policy_json)
        metadata = policy_value.get("metadata") if isinstance(policy_value, dict) else None
        if not isinstance(policy_value, dict) or policy_value.get("kind") != "ClusterPolicy" or not isinstance(metadata, dict) or metadata.get("name") != "node-operator-project-workload-baseline":
            raise KyvernoBootstrapError("release Kyverno policy rendering is invalid")
        _run(runner, [*tunnel, "kubectl", "apply", "--server-side", "--dry-run=server", "-f", "-"], env, input=policy_json)
        _run(runner, [*tunnel, "kubectl", "apply", "--server-side", "-f", "-"], env, input=policy_json)
        _run(runner, [*tunnel, "kubectl", "wait", "--for=condition=Ready", "clusterpolicy/node-operator-project-workload-baseline", "--timeout=180s"], env)
    except (json.JSONDecodeError, OSError) as error:
        raise KyvernoBootstrapError("Kyverno policy rendering is invalid") from error
    finally:
        if "values_path" in locals():
            try: os.unlink(values_path)
            except FileNotFoundError: pass


def main() -> int:
    parser = argparse.ArgumentParser()
    for name in ("bundle-root", "state-dir", "work-dir", "inputs-dir", "session", "baseline-config"):
        parser.add_argument("--" + name, required=True, type=Path)
    for name in ("account", "region", "deployment", "profile", "release-sha"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    try:
        install(bundle_root=args.bundle_root, state_dir=args.state_dir, work_dir=args.work_dir, inputs_dir=args.inputs_dir, session=args.session, baseline_config=args.baseline_config, account=args.account, region=args.region, deployment=args.deployment, profile=args.profile, release_sha=args.release_sha)
    except KyvernoBootstrapError as error:
        print(str(error), file=sys.stderr); return 65
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
