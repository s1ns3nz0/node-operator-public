"""Interactive deployment entrypoint: discovery and guarded infrastructure/SSM steps.

Infrastructure and separate SSM apply require terminal confirmation; later adapters remain unimplemented.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
from pathlib import Path
import stat
import sys

from installer_preflight import PreflightError, discover, validate_inputs, verify_backend_role, verify_execution_profile, bootstrap_permission_probe
from installer_state import CheckpointStore, StateError, STAGE_NAMES
from installer_infrastructure import InfrastructureError, prepare_inputs, apply_infrastructure
from installer_artifact_receipt import validate as validate_artifact_receipt, ReceiptError


_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


def _guided_receipt(path: Path, discovery: dict, phase: str, applied: bool) -> str | None:
    """Read one fixed private receipt; absence is the only unstarted state."""
    if not path.exists() and not path.is_symlink():
        return None
    from installer_infrastructure import _read_object
    try:
        value = _read_object(path)
    except InfrastructureError as error:
        raise StateError("Vault platform receipt is unavailable or unsafe; reconcile before advancing.") from error
    fields = {"schema_version", "phase", "plan_sha256", "aws_account_id", "aws_region", "deployment_name", "scope", "applied"}
    if not isinstance(value, dict) or set(value) != fields or value.get("schema_version") != 1 or value.get("phase") != phase or value.get("applied") is not applied or not _SHA256.fullmatch(value.get("plan_sha256", "")) or not isinstance(value.get("scope"), dict) or any(value.get(key) != discovery[key] for key in ("aws_account_id", "aws_region", "deployment_name")):
        raise StateError("Vault platform receipt is malformed or belongs to another deployment; reconcile before advancing.")
    return value["plan_sha256"]


def _guided_success(path: Path, discovery: dict, phase: str, digest: str) -> bool:
    if not path.exists() and not path.is_symlink():
        return False
    from installer_infrastructure import _read_object
    try:
        value = _read_object(path)
    except InfrastructureError as error:
        raise StateError("Vault authority success evidence is unavailable or unsafe; reconcile before advancing.") from error
    if value != {"schema_version": 1, "phase": phase, "plan_sha256": digest, "applied": True}:
        raise StateError("Vault authority success evidence does not bind the reviewed plan; reconcile before advancing.")
    return True


def _guided_platform_success(path: Path, discovery: dict, grant_sha: str) -> bool:
    if not path.exists() and not path.is_symlink():
        return False
    from installer_infrastructure import _read_object
    try:
        value = _read_object(path)
    except InfrastructureError as error:
        raise StateError("Vault platform success evidence is unavailable or unsafe; reconcile before revoking authority.") from error
    required = {"schema_version", "aws_account_id", "aws_region", "deployment_name", "grant_plan_sha256", "artifact_index_sha256", "project_contract_sha256", "project", "image_ref", "build_id", "status"}
    if not isinstance(value, dict) or set(value) != required or value.get("schema_version") != 1 or value.get("status") != "succeeded" or value.get("grant_plan_sha256") != grant_sha or any(value.get(key) != discovery[key] for key in ("aws_account_id", "aws_region", "deployment_name")) or not _SHA256.fullmatch(value.get("artifact_index_sha256", "")) or not _SHA256.fullmatch(value.get("project_contract_sha256", "")) or not isinstance(value.get("project"), str) or not isinstance(value.get("image_ref"), str) or not isinstance(value.get("build_id"), str):
        raise StateError("Vault platform success evidence is malformed or does not bind the completed grant; reconcile before revoking authority.")
    return True


def _guided_platform_failure(path: Path, discovery: dict, grant_sha: str) -> bool:
    if not path.exists() and not path.is_symlink():
        return False
    from installer_infrastructure import _read_object
    try:
        value = _read_object(path)
    except InfrastructureError as error:
        raise StateError("Vault platform failure evidence is unavailable or unsafe; reconcile before recovery.") from error
    required = {"schema_version", "aws_account_id", "aws_region", "deployment_name", "grant_plan_sha256", "artifact_index_sha256", "project_contract_sha256", "project", "image_ref", "build_id", "status"}
    terminal = {"FAILED", "FAULT", "STOPPED", "TIMED_OUT"}
    if not isinstance(value, dict) or set(value) != required or value.get("schema_version") != 1 or value.get("status") not in terminal or value.get("grant_plan_sha256") != grant_sha or any(value.get(key) != discovery[key] for key in ("aws_account_id", "aws_region", "deployment_name")) or not _SHA256.fullmatch(value.get("artifact_index_sha256", "")) or not _SHA256.fullmatch(value.get("project_contract_sha256", "")) or not isinstance(value.get("project"), str) or not isinstance(value.get("image_ref"), str) or not isinstance(value.get("build_id"), str):
        raise StateError("Vault platform failure evidence is malformed or does not bind the completed grant; reconcile before recovery.")
    return True


def _guided_mirror_ready(state_dir: Path, bundle_root: Path, discovery: dict, release_sha: str) -> bool:
    path = state_dir / "vault-artifact-mirror-receipt.json"
    if not path.exists() and not path.is_symlink():
        return False
    from installer_infrastructure import _read_object
    try:
        receipt = _read_object(path)
        index_path = bundle_root / "rendered" / "installer-artifact-index.json"
        index = _read_object(index_path)
        baseline = _read_object(state_dir / "terraform-work" / "baseline-output.json")
        validate_artifact_receipt(index, receipt, baseline, discovery, index_path.read_bytes())
    except (InfrastructureError, OSError, ReceiptError) as error:
        raise StateError("Vault mirror evidence or materialized release index is unavailable or unsafe.") from error
    if not isinstance(index, dict) or index.get("release_revision") != release_sha:
        raise StateError("Vault mirror receipt is malformed or does not bind the selected materialized release.")
    return True


def _advance_vault_platform(bundle_root: Path, state_dir: Path, discovery: dict, profile: str, release_sha: str) -> tuple[str, str]:
    """Perform exactly one durable, reviewable Vault platform action."""
    if not _guided_mirror_ready(state_dir, bundle_root, discovery, release_sha):
        confirmation = f"MIRROR VAULT ARTIFACTS {discovery['aws_account_id']} {discovery['aws_region']} {discovery['deployment_name']}"
        if prompt(None, "Type exactly " + confirmation) != confirmation:
            raise StateError("Artifact mirroring cancelled; no copy was requested.")
        from installer_artifact_mirror import mirror
        mirror(state_dir, bundle_root, discovery, profile, release_sha)
        return "vault_artifacts_mirrored", "review and create the Vault preparation plan"
    artifact = state_dir / "vault-artifact-manifest.json"
    prepare_receipt = state_dir / "vault-plans" / "prepare" / "receipt.json"
    prepare_sha = _guided_receipt(prepare_receipt, discovery, "prepare", False)
    if prepare_sha is None:
        from installer_vault_execution import plan_vault_prepare
        digest = plan_vault_prepare(bundle_root, state_dir, discovery, profile, artifact)
        return "vault_prepare_plan_ready", f"review preparation plan {digest} and advance to apply"
    if not _guided_success(state_dir / "vault-plans" / "prepare-success.json", discovery, "prepare", prepare_sha):
        confirmation = f"APPLY VAULT PREPARE {discovery['aws_account_id']} {discovery['aws_region']} {discovery['deployment_name']} {prepare_sha}"
        if prompt(None, "Type exactly " + confirmation) != confirmation:
            raise StateError("Vault preparation apply cancelled; no resource changes requested.")
        from installer_vault_execution import apply_vault_prepare
        apply_vault_prepare(bundle_root, state_dir, discovery, profile, artifact, prepare_sha)
        return "vault_prepare_applied", "review and create the temporary cluster-admin grant plan"
    grant_receipt = state_dir / "vault-authority-plans" / "grant" / "receipt.json"
    grant_sha = _guided_receipt(grant_receipt, discovery, "grant", False)
    if grant_sha is None:
        from installer_vault_authority import plan_vault_authority
        digest = plan_vault_authority(bundle_root, state_dir, discovery, profile, artifact, "grant")
        return "vault_grant_plan_ready", f"review grant plan {digest} and advance to apply"
    if not _guided_success(state_dir / "vault-authority-plans" / "grant-success.json", discovery, "grant", grant_sha):
        confirmation = f"APPLY VAULT GRANT {discovery['aws_account_id']} {discovery['aws_region']} {discovery['deployment_name']} {grant_sha}"
        if prompt(None, "Type exactly " + confirmation) != confirmation:
            raise StateError("Vault authority grant cancelled; no resource changes requested.")
        from installer_vault_authority import apply_vault_authority
        apply_vault_authority(bundle_root, state_dir, discovery, profile, artifact, "grant", grant_sha)
        return "vault_grant_applied", "advance to start or reconcile the exact Vault platform build"
    platform_success = state_dir / "vault-platform-success.json"
    platform_failure = state_dir / "vault-platform-failure.json"
    succeeded = _guided_platform_success(platform_success, discovery, grant_sha)
    failed = _guided_platform_failure(platform_failure, discovery, grant_sha)
    if succeeded and failed:
        raise StateError("Conflicting Vault platform terminal receipts require reconciliation before authority changes.")
    if not succeeded and not failed:
        intent = state_dir / "vault-platform-intent.json"
        if not intent.exists() and not intent.is_symlink():
            confirmation = f"START VAULT PLATFORM {discovery['aws_account_id']} {discovery['aws_region']} {discovery['deployment_name']}"
            if prompt(None, "Type exactly " + confirmation) != confirmation:
                raise StateError("Vault platform start cancelled; no build was requested.")
        from installer_vault_platform import run as run_platform
        outcome = run_platform(bundle_root, state_dir, discovery, profile)
        if outcome.get("status") in {"FAILED", "FAULT", "STOPPED", "TIMED_OUT"}:
            return "vault_platform_failed", "terminal platform failure is recorded; advance to reconcile it before planning recovery revoke"
        return "vault_platform_reconciled", "advance only after the exact platform build records SUCCEEDED"
    # A local success receipt is not sufficient to revoke authority. The
    # adapter rechecks the exact grant, project, image/buildspec and build ID;
    # its existing-success path never starts another build.
    from installer_vault_platform import run as run_platform
    outcome = run_platform(bundle_root, state_dir, discovery, profile)
    if failed and outcome.get("status") not in {"FAILED", "FAULT", "STOPPED", "TIMED_OUT"}:
        raise StateError("Platform failure receipt did not reconcile to the exact terminal build; authority remains granted.")
    revoke_receipt = state_dir / "vault-authority-plans" / "revoke" / "receipt.json"
    revoke_sha = _guided_receipt(revoke_receipt, discovery, "revoke", False)
    if revoke_sha is None:
        from installer_vault_authority import plan_vault_authority
        digest = plan_vault_authority(bundle_root, state_dir, discovery, profile, artifact, "revoke")
        prefix = "platform failure recovery: " if failed else ""
        return "vault_recovery_revoke_plan_ready" if failed else "vault_revoke_plan_ready", f"{prefix}review revoke plan {digest} and advance to apply"
    if not _guided_success(state_dir / "vault-authority-plans" / "revoke-success.json", discovery, "revoke", revoke_sha):
        confirmation = f"APPLY VAULT REVOKE {discovery['aws_account_id']} {discovery['aws_region']} {discovery['deployment_name']} {revoke_sha}"
        if prompt(None, "Type exactly " + confirmation) != confirmation:
            raise StateError("Vault authority revoke cancelled; no resource changes requested.")
        from installer_vault_authority import apply_vault_authority
        apply_vault_authority(bundle_root, state_dir, discovery, profile, artifact, "revoke", revoke_sha)
        return "vault_recovery_revoke_applied" if failed else "vault_revoke_applied", "Vault platform failed; recovery is required and Vault remains incomplete." if failed else "Vault remains incomplete: operator initialization, audit, authentication, and root-token revocation are required"
    return "vault_platform_failed_authority_revoked" if failed else "vault_platform_sealed_authority_revoked", "Vault platform failed; recovery is required and Vault remains incomplete." if failed else "Vault remains incomplete: operator initialization, audit, authentication, and root-token revocation are required"


def _continue_vault_platform(bundle_root: Path, state_dir: Path, discovery: dict, profile: str, release_sha: str) -> tuple[str, str]:
    """Bounded guided continuation; primitive actions retain their own consent."""
    terminal = {"vault_platform_failed", "vault_platform_failed_authority_revoked", "vault_platform_sealed_authority_revoked"}
    for _ in range(12):
        result, next_action = _advance_vault_platform(bundle_root, state_dir, discovery, profile, release_sha)
        if result in terminal:
            return result, next_action
    raise StateError("Guided Vault platform continuation exceeded its bounded action limit; reconcile before resuming.")


def load_context(directory: Path) -> dict:
    # No symlink traversal at the state-directory or checkpoint boundary.
    value = directory.lstat()
    if not stat.S_ISDIR(value.st_mode) or stat.S_IMODE(value.st_mode) != 0o700:
        raise StateError("State directory must be a private regular directory.")
    fd = os.open(directory / "checkpoint.json", os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "r", encoding="utf-8") as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 65536:
            raise StateError("Checkpoint is not a bounded private regular file.")
        data = json.load(handle)
    if not isinstance(data, dict) or not isinstance(data.get("context"), dict):
        raise StateError("Checkpoint context is invalid.")
    # Full strict JSON/state validation is performed again under the store lock.
    return data["context"]


def prompt(value: str | None, label: str, default: str | None = None) -> str:
    if value is not None:
        return value
    if not sys.stdin.isatty():
        raise StateError("Missing input requires a terminal or an explicit command option.")
    answer = input(label + (f" [{default}]" if default else "") + ": ").strip()
    return answer or default or ""


def run(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Start/status/resume discovery and separately confirmed infrastructure/SSM execution.")
    parser.add_argument("command", choices=("start", "status", "resume"))
    parser.add_argument("--state-dir", required=True, type=Path)
    parser.add_argument("--release-dir", type=Path, help="Downloaded release asset directory; required for start/resume")
    parser.add_argument("--aws-profile")
    parser.add_argument("--aws-region")
    parser.add_argument("--name")
    parser.add_argument("--prepare-infrastructure", action="store_true", help="Materialize verified release and generate local Terraform inputs; does not apply")
    parser.add_argument("--prepare-ops-access", action="store_true", help="Prepare separate SSM inputs after infrastructure completion; never plans, applies or opens a session")
    parser.add_argument("--prepare-vault", action="store_true", help="Prepare local Vault bootstrap inputs from reviewed artifacts; no apply or initialization")
    parser.add_argument("--mirror-vault-artifacts", action="store_true", help="Mirror the release-bound Vault artifacts after terminal confirmation; does not deploy Vault")
    parser.add_argument("--advance-vault-platform", action="store_true", help="Guided resume: perform exactly the next reviewed Vault platform action")
    parser.add_argument("--plan-vault", action="store_true", help="Reconcile the baseline and save a Vault runner preparation plan; never apply")
    parser.add_argument("--apply-vault", action="store_true", help="Apply the reviewed Vault runner plan after terminal confirmation; does not initialize Vault")
    parser.add_argument("--vault-plan-sha", help="Exact reviewed Vault preparation plan SHA-256; required for apply")
    parser.add_argument("--vault-artifacts", type=Path, help="Private reviewed Vault image/chart manifest; required for Vault prepare, plan and apply")
    parser.add_argument("--plan-ops-access", action="store_true", help="Create a separate private SSM saved plan; does not apply")
    parser.add_argument("--apply-ops-access", action="store_true", help="Apply the separately reviewed SSM plan after terminal confirmation")
    parser.add_argument("--verify-ops-access", action="store_true", help="Verify SSM Online and private EKS access through a temporary session; no Terraform apply")
    parser.add_argument("--ops-plan-sha", help="Exact SHA-256 from the reviewed SSM plan; required for SSM apply")
    parser.add_argument("--apply-infrastructure", action="store_true", help="Prepare and apply infrastructure after terminal confirmation; does not set up SSM/Vault/workloads")
    parser.add_argument("--backend-principal-arn", help="Exact same-account backend IAM role for infrastructure preparation")
    parser.add_argument("--execution-profile", help="Optional existing AWS role profile to verify and use for infrastructure execution")
    args = parser.parse_args(argv)
    ops_requested = args.prepare_ops_access or args.plan_ops_access or args.apply_ops_access or args.verify_ops_access
    vault_requested = args.prepare_vault or args.plan_vault or args.apply_vault
    mirror_requested = args.mirror_vault_artifacts
    guided_vault_requested = args.advance_vault_platform
    if guided_vault_requested and (args.command != "resume" or not sys.stdin.isatty() or mirror_requested or vault_requested or ops_requested or args.prepare_infrastructure or args.apply_infrastructure or args.backend_principal_arn or args.execution_profile or args.vault_artifacts is not None or args.vault_plan_sha is not None or args.ops_plan_sha is not None or args.aws_profile or args.aws_region or args.name):
        raise StateError("Guided Vault platform advancement is a terminal-only resume operation with no expert or context override flags.")
    if mirror_requested and (args.command != "resume" or guided_vault_requested or vault_requested or ops_requested or args.prepare_infrastructure or args.apply_infrastructure or args.backend_principal_arn or args.execution_profile or not sys.stdin.isatty()):
        raise StateError("Artifact mirroring is a separate interactive resume operation.")
    if vault_requested and (args.command != "resume" or ops_requested or args.prepare_infrastructure or args.apply_infrastructure or args.backend_principal_arn or args.execution_profile or args.vault_artifacts is None or sum((args.prepare_vault, args.plan_vault, args.apply_vault)) != 1):
        raise StateError("Vault preparation is a separate resume operation requiring --vault-artifacts.")
    if args.vault_plan_sha is not None and not args.apply_vault:
        raise StateError("--vault-plan-sha is accepted only with --apply-vault.")
    if args.apply_vault and (not sys.stdin.isatty() or not re.fullmatch(r"[0-9a-f]{64}", args.vault_plan_sha or "")):
        raise StateError("Vault apply requires an interactive terminal and the reviewed 64-character plan SHA-256.")
    if args.vault_artifacts is not None and not vault_requested:
        raise StateError("--vault-artifacts requires --prepare-vault, --plan-vault or --apply-vault.")
    if ops_requested and (args.command != "resume" or args.prepare_infrastructure or args.apply_infrastructure or args.backend_principal_arn or args.execution_profile or sum((args.prepare_ops_access, args.plan_ops_access, args.apply_ops_access, args.verify_ops_access)) != 1):
        raise StateError("SSM is a separate resume operation; choose one preparation, plan or apply step without infrastructure options.")
    if args.ops_plan_sha and not args.apply_ops_access:
        raise StateError("--ops-plan-sha is accepted only with --apply-ops-access.")
    if args.apply_ops_access and (not sys.stdin.isatty() or not re.fullmatch(r"[0-9a-f]{64}", args.ops_plan_sha or "")):
        raise StateError("SSM apply requires an interactive terminal and the reviewed 64-character plan SHA-256.")
    if args.apply_infrastructure:
        if not sys.stdin.isatty():
            raise StateError("Infrastructure apply requires an interactive terminal and deployment-scope confirmation.")
        args.prepare_infrastructure = True
    if not args.state_dir.is_absolute():
        raise StateError("Use an absolute state directory.")
    if args.command == "status":
        if args.release_dir or args.aws_profile or args.aws_region or args.name or args.prepare_infrastructure or args.backend_principal_arn or args.execution_profile:
            raise StateError("status accepts only --state-dir; it does not query AWS.")
        context = load_context(args.state_dir)
        store = CheckpointStore(args.state_dir, context)
        with store.lock():
            checkpoint = store.resume()
        print(json.dumps({"context": context, "stages": checkpoint["stages"], "deployment_complete": False}, sort_keys=True))
        return 0
    if args.backend_principal_arn and not args.prepare_infrastructure:
        raise StateError("--backend-principal-arn requires --prepare-infrastructure.")
    if args.execution_profile and not args.prepare_infrastructure:
        raise StateError("--execution-profile requires --prepare-infrastructure.")
    if args.release_dir is None:
        raise StateError("start/resume requires --release-dir with verified release assets.")
    from installer_bundle import verify_release
    release = verify_release(args.release_dir)
    if args.command == "resume":
        original = load_context(args.state_dir)
        profile = args.aws_profile or original["aws_profile"]
        region = args.aws_region or original["aws_region"]
        name = args.name or original["deployment_name"]
    else:
        if args.state_dir.exists() or args.state_dir.is_symlink():
            raise StateError("State path already exists. Use resume; no state was overwritten.")
        profile = prompt(args.aws_profile, "AWS profile", "default")
        region = prompt(args.aws_region, "AWS Region", "ap-northeast-2")
        name = prompt(args.name, "Deployment name")
    validate_inputs(profile, region, name)
    discovery = discover(profile, region, name)
    context = {key: discovery[key] for key in ("aws_profile", "aws_region", "aws_account_id", "deployment_name")}
    context.update(release_sha=release["release_sha"], bundle_digest=release["bundle_digest"])
    store = CheckpointStore(args.state_dir, context)
    ops_result = None
    ops_plan_sha = None
    vault_plan_sha = None
    with store.lock():
        checkpoint = store.resume()
        if any(stage["status"] == "running" for stage in checkpoint["stages"].values()):
            raise StateError("An interrupted stage requires reconciliation. No stage was retried or marked complete.")
        if not ops_requested and not guided_vault_requested:
            for stage in sorted(STAGE_NAMES):
                if stage not in checkpoint["stages"]:
                    store.set_stage(stage, "pending")
        # Read-only discovery is useful but does not prove permissions, quotas,
        # all-resource collision safety or provisioning readiness.
        if not ops_requested and not vault_requested and not guided_vault_requested:
            store.set_stage("preflight", "awaiting_input")
        if guided_vault_requested:
            if any(checkpoint["stages"].get(stage, {}).get("status") != "complete" for stage in ("infrastructure", "ops_access")):
                raise StateError("Guided Vault platform advancement requires completed infrastructure and verified private access.")
            from installer_bundle import materialize_release
            bundle_root = materialize_release(args.release_dir, args.state_dir / "release", release["release_sha"], release["bundle_digest"])
            ops_result, guided_next = _continue_vault_platform(bundle_root, args.state_dir, discovery, profile, release["release_sha"])
        if mirror_requested:
            if any(checkpoint["stages"].get(stage, {}).get("status") != "complete" for stage in ("infrastructure", "ops_access")):
                raise StateError("Artifact mirroring requires completed infrastructure and verified private access.")
            confirmation = f"MIRROR VAULT ARTIFACTS {discovery['aws_account_id']} {region} {name}"
            print("This copies only release-indexed artifacts to existing private ECR repositories. It does not deploy or initialize Vault.", file=sys.stderr)
            if prompt(None, "Type exactly " + confirmation) != confirmation:
                raise StateError("Artifact mirroring cancelled; no copy was requested.")
            from installer_bundle import materialize_release
            bundle_root = materialize_release(args.release_dir, args.state_dir / "release", release["release_sha"], release["bundle_digest"])
            from installer_artifact_mirror import mirror
            mirror(args.state_dir, bundle_root, discovery, profile, release["release_sha"])
            ops_result = "vault_artifact_mirroring_ready_for_reconciliation"
        if vault_requested:
            if any(checkpoint["stages"].get(stage, {}).get("status") != "complete" for stage in ("infrastructure", "ops_access")):
                raise StateError("Vault preparation requires completed infrastructure and verified private access.")
            if checkpoint["stages"].get("vault", {}).get("status") == "complete":
                raise StateError("Vault is already complete; preparation cannot reset its status.")
            if args.prepare_vault:
                from installer_vault_inputs import prepare_vault_inputs
                prepare_vault_inputs(args.state_dir, discovery, args.vault_artifacts)
                ops_result = "vault_bootstrap_inputs_ready"
            else:
                from installer_bundle import materialize_release
                bundle_root = materialize_release(args.release_dir, args.state_dir / "release", release["release_sha"], release["bundle_digest"])
                if args.apply_vault:
                    confirmation = f"APPLY VAULT PREPARE {discovery['aws_account_id']} {region} {name} {args.vault_plan_sha}"
                    print("This provisions only the reviewed Vault bootstrap runner resources. It does not grant cluster-admin access, deploy or initialize Vault.", file=sys.stderr)
                    if prompt(None, "Type exactly " + confirmation) != confirmation:
                        raise StateError("Vault apply cancelled; no resource changes requested.")
                store.set_stage("vault", "running")
                try:
                    if args.apply_vault:
                        from installer_vault_execution import apply_vault_prepare
                        apply_vault_prepare(bundle_root, args.state_dir, discovery, profile, args.vault_artifacts, args.vault_plan_sha)
                        ops_result = "vault_bootstrap_provisioned"
                    else:
                        from installer_vault_execution import plan_vault_prepare
                        vault_plan_sha = plan_vault_prepare(bundle_root, args.state_dir, discovery, profile, args.vault_artifacts)
                        ops_result = "vault_bootstrap_plan_ready"
                finally:
                    store.set_stage("vault", "awaiting_input")
            store.set_stage("vault", "awaiting_input")
        if ops_requested:
            if checkpoint["stages"].get("infrastructure", {}).get("status") != "complete":
                raise StateError("SSM operations require completed infrastructure in this original state directory.")
            if checkpoint["stages"].get("ops_access", {}).get("status") == "complete" and not args.verify_ops_access:
                raise StateError("SSM access is already complete; preparation cannot reset its status.")
            if args.verify_ops_access:
                store.set_stage("ops_access", "running")
                try:
                    from installer_bundle import materialize_release
                    bundle_root = materialize_release(args.release_dir, args.state_dir / "release",
                                                      release["release_sha"], release["bundle_digest"])
                    from installer_ops_verify import verify_ops_access
                    verify_ops_access(bundle_root, args.state_dir, discovery, profile)
                except (Exception, KeyboardInterrupt):
                    store.set_stage("ops_access", "awaiting_input")
                    raise
                store.set_stage("ops_access", "complete")
                ops_result = "ops_access_ready"
            else:
                from installer_bundle import materialize_release
                bundle_root = materialize_release(args.release_dir, args.state_dir / "release",
                                                  release["release_sha"], release["bundle_digest"])
            if args.prepare_ops_access:
                from installer_ops_access import prepare_ops_access
                prepare_ops_access(bundle_root, args.state_dir, discovery, profile)
                store.set_stage("ops_access", "awaiting_input")
                ops_result = "ops_access_inputs_ready"
            elif not args.verify_ops_access:
                from installer_ops_execution import plan_ops_access, apply_ops_access
                if args.apply_ops_access:
                    confirmation = f"APPLY SSM {discovery['aws_account_id']} {region} {name} node-operator/ops-access/terraform.tfstate {args.ops_plan_sha}"
                    print("This applies only the separately reviewed SSM access plan. A successful apply does not prove session or private EKS readiness.", file=sys.stderr)
                    if prompt(None, "Type exactly " + confirmation) != confirmation:
                        raise StateError("SSM apply cancelled; no resource changes requested.")
                store.set_stage("ops_access", "running")
                try:
                    if args.plan_ops_access:
                        ops_plan_sha = plan_ops_access(bundle_root, args.state_dir, discovery, profile)
                        ops_result = "ops_access_plan_ready"
                    else:
                        apply_ops_access(bundle_root, args.state_dir, discovery, profile, args.ops_plan_sha)
                        ops_result = "ops_access_provisioned"
                except (InfrastructureError, PreflightError):
                    store.set_stage("ops_access", "failed")
                    raise
                # Provisioning alone does not prove SSM Online or private EKS access.
                store.set_stage("ops_access", "awaiting_input")
        if args.prepare_infrastructure:
            from installer_bundle import materialize_release
            principal = prompt(args.backend_principal_arn, "Same-account Terraform backend IAM role ARN")
            # Validate the role/context before writing the release tree.
            from installer_infrastructure import expected_inputs
            inputs_dir = args.state_dir / "infrastructure-inputs"
            expected_inputs(inputs_dir, discovery, principal)
            discovery["backend_role"] = verify_backend_role(discovery, principal)
            if args.execution_profile:
                discovery["execution_identity"] = verify_execution_profile(discovery, discovery["backend_role"], args.execution_profile)
                discovery["bootstrap_permission_probe"] = bootstrap_permission_probe(discovery, discovery["backend_role"])
            bundle_root = materialize_release(args.release_dir, args.state_dir / "release",
                                              release["release_sha"], release["bundle_digest"])
            prepare_inputs(bundle_root, inputs_dir, discovery, principal, args.state_dir)
            store.set_stage("infrastructure", "awaiting_input")
            if args.apply_infrastructure:
                if args.execution_profile and discovery["bootstrap_permission_probe"]["result"] != "limited_checks_passed":
                    raise StateError("Execution role prerequisites need permission review; no infrastructure apply was started.")
                replica_region = "ap-northeast-2" if region == "ap-northeast-1" else "ap-northeast-1"
                confirmation = f"APPLY {discovery['aws_account_id']} {region} {name} AUDIT {replica_region}"
                print("This provisions infrastructure and audit-replica resources in the displayed Regions. Full permission/quota clearance is not proven. Existing state is preserved on failure.", file=sys.stderr)
                if prompt(None, "Type exactly " + confirmation) != confirmation:
                    raise StateError("Infrastructure apply cancelled; no resource changes requested.")
                store.set_stage("infrastructure", "running")
                try:
                    apply_infrastructure(bundle_root, args.state_dir, discovery, principal, args.execution_profile or profile)
                except (InfrastructureError, PreflightError):
                    store.set_stage("infrastructure", "failed")
                    raise
                store.set_stage("infrastructure", "complete")
    remaining = "Infrastructure apply and later deployment stages remain required."
    if ops_requested or args.apply_infrastructure:
        remaining = "SSM session/private EKS readiness, Vault, secrets, GitOps, workloads, custody, deposit, activation, duty and E2E remain required."
    if args.verify_ops_access:
        remaining = "Vault, secrets, GitOps, workloads, custody, deposit, activation, duty and E2E remain required."
    if vault_requested or guided_vault_requested:
        remaining = "Vault readiness is unproven. Artifact mirroring, TLS, sealed deployment, initialization, secrets, workloads and E2E remain required."
    print(json.dumps({"result": ops_result or ("infrastructure_ready" if args.apply_infrastructure else ("infrastructure_inputs_ready" if args.prepare_infrastructure else "discovery_complete")), "discovery": discovery,
                      "ops_plan_sha256": ops_plan_sha,
                      "vault_plan_sha256": vault_plan_sha,
                      "deployment_complete": False,
                      "remaining": remaining,
                      "next_action": guided_next if guided_vault_requested else None}, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(run())
    except (StateError, PreflightError, InfrastructureError) as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1)
    except (OSError, ValueError, KeyError, KeyboardInterrupt):
        print("Installer input/state failed or execution was interrupted. Preserve this state directory; resources may exist and must be reconciled before retrying.", file=sys.stderr)
        raise SystemExit(1)
