#!/usr/bin/env python3
"""Select preserved OCI bytes using the existing release authority inventory.

Check objective: Never promote archive contents into image approval authority.
This module only locates candidates. installer_oci_payload independently checks
every descriptor and byte before packaging. Neither helper signs a release.
"""
from __future__ import annotations

import os
from pathlib import Path
import re
import stat
from typing import Any

DIGEST = re.compile(r"sha256:[a-f0-9]{64}\Z")
NAME = re.compile(r"[a-z0-9][a-z0-9-]{0,99}\Z")


class SelectionError(ValueError):
    pass


def approved_roots(inventory: dict[str, Any]) -> dict[str, str]:
    """Consume build_inventory output from the caller's verified release bundle.

    A caller-supplied arbitrary dictionary is not proof of release authenticity.
    All required components, including bootstrap tooling, must be represented.
    """
    if (inventory.get("schema_version") != 1 or inventory.get("complete") is not True
            or inventory.get("unresolved_authority") != []):
        raise SelectionError("release artifact authority is incomplete")
    artifacts = inventory.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        raise SelectionError("release artifact inventory is empty")
    result: dict[str, str] = {}
    for item in artifacts:
        if not isinstance(item, dict):
            raise SelectionError("release artifact entry is invalid")
        name = item.get("component")
        if (not isinstance(name, str) or not NAME.fullmatch(name) or name in result
                or item.get("required") is not True
                or item.get("status") != "source-approved" or not item.get("authority")):
            raise SelectionError("release artifact identity or authority is invalid")
        refs = [item.get(field) for field in ("source", "destination")
                if item.get(field) is not None]
        digests = []
        for ref in refs:
            if not isinstance(ref, str) or ref.count("@") != 1:
                raise SelectionError("release artifact reference is not immutable")
            digest = ref.rsplit("@", 1)[1]
            if not DIGEST.fullmatch(digest):
                raise SelectionError("release artifact digest is invalid")
            digests.append(digest)
        if not digests or len(set(digests)) != 1:
            raise SelectionError("release source and destination digests differ")
        result[name] = digests[0]
    return dict(sorted(result.items()))


def select_layouts(inventory: dict[str, Any], archive_root: Path) -> dict[str, tuple[Path, str]]:
    """Locate deterministic same-layout candidates without reading layer data.

    Unrelated historical manifests and credentials are never selected. Missing
    bytes must be recovered from approved sources, not replaced with new tags.
    The first candidate is deliberate: corruption detected by the payload
    verifier aborts rather than silently hiding a damaged preservation copy.
    """
    roots = approved_roots(inventory)
    if not archive_root.is_absolute() or archive_root.is_symlink() or not archive_root.is_dir():
        raise SelectionError("archive root must be an absolute non-symlink directory")
    root = archive_root.resolve(strict=True)
    layouts: list[Path] = []
    for current, directories, files in os.walk(root, followlinks=False):
        directories[:] = sorted(name for name in directories
                                if name != "blobs" and not (Path(current) / name).is_symlink())
        if "oci-layout" in files:
            path = Path(current)
            marker = path / "oci-layout"
            if marker.is_symlink() or not marker.is_file():
                raise SelectionError("OCI layout marker is unsafe")
            layouts.append(path)
    selected: dict[str, tuple[Path, str]] = {}
    for name, digest in roots.items():
        for layout in sorted(layouts):
            blob = layout / "blobs" / "sha256" / digest[7:]
            if (layout / "blobs").is_symlink() or (layout / "blobs" / "sha256").is_symlink():
                raise SelectionError("OCI blob directory is unsafe")
            if blob.is_symlink():
                raise SelectionError("OCI manifest blob is unsafe")
            try:
                info = blob.stat()
            except FileNotFoundError:
                continue
            if not stat.S_ISREG(info.st_mode):
                raise SelectionError("OCI manifest blob is not a regular file")
            selected[name] = (layout, digest)
            break
        if name not in selected:
            raise SelectionError(f"approved OCI bytes are missing for {name}: {digest}")
    return selected


def main() -> int:
    import argparse
    import json
    from installer_artifact_inventory import InventoryError, build_inventory
    from installer_oci_payload import OciPayloadError, prepare_payload, verify_payload

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle-root", required=True, type=Path)
    parser.add_argument("--release-sha", required=True)
    parser.add_argument("--aws-account-id", required=True)
    parser.add_argument("--aws-region", required=True)
    parser.add_argument("--deployment-name", required=True)
    parser.add_argument("--archive-root", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()
    try:
        inventory = build_inventory(args.bundle_root, args.release_sha, args.aws_account_id,
                                    args.aws_region, args.deployment_name, require_signer_probe=True)
        roots = approved_roots(inventory)
        manifest = prepare_payload(select_layouts(inventory, args.archive_root), args.output_dir)
        verify_payload(args.output_dir, expected_roots=roots)
    except (InventoryError, SelectionError, OciPayloadError, OSError) as error:
        parser.exit(1, f"OCI payload preparation failed: {error}\n")
    print(json.dumps({"status": "verified-offline", "release_revision": args.release_sha,
                      "roots": len(roots), "chunks": len(manifest["chunks"]),
                      "bytes": sum(row["size"] for row in manifest["chunks"]),
                      "remaining": "bind payload manifest to signed release; publish and test installer import"},
                     sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
