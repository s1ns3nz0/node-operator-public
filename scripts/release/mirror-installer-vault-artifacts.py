#!/usr/bin/env python3
"""Operate an explicitly selected pre-EKS installer artifact subset."""
from __future__ import annotations

import argparse
import re
import sys
sys.dont_write_bytecode = True
from pathlib import Path

from installer_artifact_mirror import MirrorError, mirror, verify_pre_eks_vault_mirror


ACCOUNT = re.compile(r"^[0-9]{12}$")
REGION = re.compile(r"^[a-z]{2}-[a-z0-9-]+-[0-9]+$")
NAME = re.compile(r"^[a-z][a-z0-9-]{1,18}[a-z0-9]$")
SHA = re.compile(r"^[0-9a-f]{40}$")
PROFILE = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")


class CLIError(ValueError):
    pass


def _directory(value: str, label: str) -> Path:
    path = Path(value)
    if not path.is_absolute() or path.is_symlink() or not path.is_dir():
        raise CLIError(f"{label} must be an existing absolute directory")
    try:
        return path.resolve(strict=True)
    except OSError as error:
        raise CLIError(f"{label} is unavailable") from error


def _context(args: argparse.Namespace) -> tuple[Path, Path, Path, Path, dict[str, str]]:
    bundle = _directory(args.bundle_root, "bundle root")
    state = _directory(args.state_dir, "state directory")
    work = _directory(args.work_dir, "work directory")
    inputs = _directory(args.inputs_dir, "inputs directory")
    try:
        work.relative_to(state)
    except ValueError as error:
        raise CLIError("work directory must be below state directory") from error
    if not ACCOUNT.fullmatch(args.account) or not REGION.fullmatch(args.region) or not NAME.fullmatch(args.deployment_name) or not SHA.fullmatch(args.release_sha) or not PROFILE.fullmatch(args.profile):
        raise CLIError("selected deployment context is invalid")
    return bundle, state, work, inputs, {"aws_account_id": args.account, "aws_region": args.region, "deployment_name": args.deployment_name}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    for command in ("mirror", "verify", "resume"):
        item = sub.add_parser(command)
        item.add_argument("--scope", choices=("vault", "non-vault"), default="vault")
        item.add_argument("--bundle-root", required=True)
        item.add_argument("--state-dir", required=True)
        item.add_argument("--work-dir", required=True)
        item.add_argument("--inputs-dir", required=True)
        item.add_argument("--account", required=True)
        item.add_argument("--region", required=True)
        item.add_argument("--deployment-name", required=True)
        item.add_argument("--profile", required=True)
        item.add_argument("--release-sha", required=True)
        item.add_argument("--oci-payload-dir", help="Downloaded release OCI assets directory")
        item.add_argument("--verified-bundle-manifest-sha256", help="Manifest hash from the authenticated release context, not an untrusted download")
    args = parser.parse_args(argv)
    try:
        bundle, state, work, inputs, discovery = _context(args)
        payload_kwargs = {}
        if args.oci_payload_dir is not None or args.verified_bundle_manifest_sha256 is not None:
            if args.command == "verify" or not args.oci_payload_dir or not re.fullmatch(r"[a-f0-9]{64}", args.verified_bundle_manifest_sha256 or ""):
                raise CLIError("mirror requires both release payload and authenticated manifest hash")
            payload_kwargs = {"payload_dir": _directory(args.oci_payload_dir, "OCI payload directory"),
                              "authenticated_bundle_manifest_sha256": args.verified_bundle_manifest_sha256}
        if args.scope == "vault":
            if args.command in ("mirror", "resume"):
                kwargs = {"prerequisites_path": work / "artifact-prerequisites.json", "inputs_dir": inputs, "work_dir": work}
                if args.command == "resume":
                    kwargs["resume"] = True
                mirror(state, bundle, discovery, args.profile, args.release_sha, **kwargs, **payload_kwargs)
            else:
                verify_pre_eks_vault_mirror(state, bundle, discovery, args.profile, args.release_sha,
                                            inputs_dir=inputs, work_dir=work)
        else:
            # Keep the public adapter limited to an explicitly named subset. The
            # full helper itself also re-verifies the Vault receipt; it does not
            # replace it or imply that the overall installer has been activated.
            from installer_full_artifact_mirror import mirror as non_vault_mirror, verify as non_vault_verify
            if args.command == "verify":
                non_vault_verify(state, bundle, discovery, args.profile, args.release_sha,
                                 work_dir=work, inputs_dir=inputs)
            else:
                non_vault_mirror(state, bundle, discovery, args.profile, args.release_sha,
                                 work_dir=work, inputs_dir=inputs, resume=args.command == "resume", **payload_kwargs)
    except (CLIError, MirrorError, RuntimeError, OSError, ValueError):
        print(("Vault" if args.scope == "vault" else "Non-Vault") + " pre-EKS artifact operation failed; no full installer artifact gate is implied.", file=sys.stderr)
        return 2
    print(("Vault subset" if args.scope == "vault" else "Non-Vault subset") + " pre-EKS artifact operation completed; this is not the full installer artifact gate.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
