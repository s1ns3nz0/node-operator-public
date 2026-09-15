#!/usr/bin/env python3
"""Bind OCI transport bytes to a previously authenticated release bundle.

The caller supplies the bundle-manifest hash from its verified release context,
not from the untrusted download being checked. This module does not establish
that root of trust, download assets, or grant permission to activate a validator.
"""
from __future__ import annotations

import hashlib
from contextlib import contextmanager
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import tempfile

from installer_artifact_inventory import build_inventory
from installer_oci_selection import approved_roots
from installer_oci_payload import verify_payload

PAYLOAD_MEMBER = "rendered/installer-oci-payload-manifest.json"
HEX = re.compile(r"[a-f0-9]{64}\Z")


class BindingError(ValueError):
    pass


def _file(root: Path, relative: str) -> Path:
    if not isinstance(relative, str):
        raise BindingError("bundle member path is invalid")
    parts = PurePosixPath(relative)
    if parts.is_absolute() or str(parts) != relative or "\\" in relative or any(p in (".", "..") for p in parts.parts):
        raise BindingError("bundle member path is unsafe")
    path = root
    for part in parts.parts:
        path = path / part
        if path.is_symlink():
            raise BindingError("bundle member uses a symlink")
    if not stat.S_ISREG(path.stat().st_mode):
        raise BindingError("bundle member is not regular")
    return path


def _hash(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _object(path: Path) -> dict:
    if path.stat().st_size > 4 * 1024 * 1024:
        raise BindingError("bundle metadata is too large")
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise BindingError("duplicate bundle metadata key")
            result[key] = value
        return result
    value = json.loads(path.read_text(), object_pairs_hook=unique)
    if not isinstance(value, dict):
        raise BindingError("bundle metadata must be an object")
    return value


def verify_bound_payload(bundle_root: Path, release_sha: str, payload_dir: Path, *,
                         expected_bundle_manifest_sha256: str, account: str, region: str,
                         deployment_name: str, reconstruct_dir: Path | None = None) -> dict:
    """Recheck release-owned inputs before permitting any OCI reconstruction.

    Input trees must remain private and quiescent during verification. No AWS,
    GitHub, registry, credential, or shell-environment operation is performed.
    """
    if not isinstance(expected_bundle_manifest_sha256, str) or not HEX.fullmatch(expected_bundle_manifest_sha256):
        raise BindingError("authenticated bundle manifest hash is required")
    if not bundle_root.is_absolute() or bundle_root.is_symlink() or not bundle_root.is_dir():
        raise BindingError("bundle root is unsafe")
    manifest_path = _file(bundle_root, "bundle-manifest.json")
    if _hash(manifest_path) != expected_bundle_manifest_sha256:
        raise BindingError("bundle manifest differs from authenticated release context")
    manifest = _object(manifest_path)
    if (manifest.get("schema_version") != "v1" or manifest.get("source_revision") != release_sha
            or not isinstance(manifest.get("entries"), list)):
        raise BindingError("bundle manifest does not bind the selected revision")
    seen = set()
    for entry in manifest["entries"]:
        if not isinstance(entry, dict) or set(entry) != {"path", "sha256", "size"}:
            raise BindingError("bundle entry schema is invalid")
        relative = entry["path"]
        if not isinstance(relative, str) or relative in seen or not isinstance(entry["sha256"], str) or not HEX.fullmatch(entry["sha256"]) or type(entry["size"]) is not int or entry["size"] < 0:
            raise BindingError("bundle entry is invalid or duplicated")
        seen.add(relative)
        path = _file(bundle_root, relative)
        if path.stat().st_size != entry["size"] or _hash(path) != entry["sha256"]:
            raise BindingError("bundle member differs from authenticated manifest")
    if PAYLOAD_MEMBER not in seen:
        raise BindingError("release has no bound OCI payload manifest")
    # Inventory parsers must never consume an extra, unbound approval file.
    # A release tree is immutable: even caches belong outside this directory.
    actual = set()
    for directory, directories, filenames in os.walk(bundle_root, followlinks=False):
        for name in directories:
            if (Path(directory) / name).is_symlink():
                raise BindingError("bundle directory uses a symlink")
        for name in filenames:
            relative = (Path(directory) / name).relative_to(bundle_root).as_posix()
            _file(bundle_root, relative)
            actual.add(relative)
    # The existing public installer places operator configuration at root/env.
    # It is not release authority; source/rendered inputs remain fully bound.
    allowed_local = {"env"} if "env" in actual and "env" not in seen else set()
    if actual != seen | {"bundle-manifest.json"} | allowed_local:
        raise BindingError("bundle contains unbound or missing members")
    approved_manifest = _file(bundle_root, PAYLOAD_MEMBER)
    downloaded_manifest = _file(payload_dir, "payload-manifest.json")
    if _hash(approved_manifest) != _hash(downloaded_manifest):
        raise BindingError("downloaded payload manifest differs from release")
    inventory = build_inventory(bundle_root, release_sha, account, region, deployment_name, require_signer_probe=True)
    value = verify_payload(payload_dir, expected_roots=approved_roots(inventory), reconstruct_dir=reconstruct_dir)
    return {"release_revision": release_sha, "payload_manifest_sha256": _hash(approved_manifest),
            "verified_roots": len(value["roots"]), "scope": "release-bound OCI transport only"}


@contextmanager
def payload_context(bundle_root: Path, release_sha: str, discovery: dict, state_dir: Path,
                    payload_dir: Path | None, authenticated_manifest_sha256: str | None):
    """Keep verified OCI layouts private for exactly one mirror operation.

    A payload-enabled release cannot silently fall back to its old registry.
    The caller remains responsible for obtaining an authenticated manifest hash.
    """
    required = (bundle_root / PAYLOAD_MEMBER).exists() or (bundle_root / PAYLOAD_MEMBER).is_symlink()
    if payload_dir is None:
        if required or authenticated_manifest_sha256 is not None:
            raise BindingError("release OCI payload and authenticated manifest hash are required")
        yield None
        return
    if not authenticated_manifest_sha256:
        raise BindingError("authenticated release manifest hash is required")
    if not state_dir.is_absolute() or state_dir.is_symlink() or not state_dir.is_dir() or stat.S_IMODE(state_dir.stat().st_mode) != 0o700:
        raise BindingError("private payload workspace is unsafe")
    with tempfile.TemporaryDirectory(prefix=".release-oci-", dir=state_dir) as temporary:
        reconstructed = Path(temporary) / "verified"
        verify_bound_payload(bundle_root, release_sha, payload_dir,
            expected_bundle_manifest_sha256=authenticated_manifest_sha256,
            account=discovery["aws_account_id"], region=discovery["aws_region"],
            deployment_name=discovery["deployment_name"], reconstruct_dir=reconstructed)
        yield reconstructed / "oci"
