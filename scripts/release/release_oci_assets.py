#!/usr/bin/env python3
"""List uploadable OCI chunks bound to the independently approved bundle digest.

Check objective: Reject missing, substituted or corrupt OCI release assets before
GitHub publication. This is a publication-stage byte gate, not a signature or
source-approval authority. The workflow must still run its signing gate first.
Inputs and their directories must remain private and quiescent through upload.
"""
from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import re
import sys
import tarfile

from installer_oci_binding import PAYLOAD_MEMBER
from installer_oci_payload import MAX_METADATA_BYTES, verify_payload
from installer_release_signature import _json


def assets(bundle: Path, approved_digest: str, payload: Path | None) -> list[Path]:
    if not re.fullmatch(r"sha256:[a-f0-9]{64}", approved_digest):
        raise ValueError("independently approved bundle digest is required")
    if not bundle.is_absolute() or bundle.is_symlink() or not bundle.is_file():
        raise ValueError("regular absolute release bundle required")
    digest = hashlib.sha256()
    with bundle.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    if "sha256:" + digest.hexdigest() != approved_digest:
        raise ValueError("bundle differs from approved reproducibility digest")
    bound = None
    with tarfile.open(bundle, "r:") as archive:
        for member in archive:
            if member.name == PAYLOAD_MEMBER:
                if bound is not None or not member.isfile() or not 0 < member.size <= MAX_METADATA_BYTES:
                    raise ValueError("bound OCI manifest is duplicate or unsafe")
                source = archive.extractfile(member)
                if source is None:
                    raise ValueError("bound OCI manifest unavailable")
                bound = source.read(MAX_METADATA_BYTES + 1)
    if bound is None:
        if payload is not None:
            raise ValueError("OCI assets supplied for bundle without OCI binding")
        return []  # Historical bundle publication remains supported.
    if payload is None or not payload.is_absolute() or payload.is_symlink() or not payload.is_dir():
        raise ValueError("bound release requires absolute OCI payload directory")
    path = payload / "payload-manifest.json"
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_METADATA_BYTES or path.read_bytes() != bound:
        raise ValueError("OCI manifest differs from approved bundle member")
    manifest = _json(bound)
    roots = manifest.get("roots")
    if not isinstance(roots, dict) or not roots or any(not isinstance(value, dict) for value in roots.values()):
        raise ValueError("OCI root inventory invalid")
    chunks = manifest.get("chunks")
    if not isinstance(chunks, list) or not 0 < len(chunks) <= 994:
        raise ValueError("release asset count exceeds limit")
    names = set()
    total = 0
    for chunk in chunks:
        if not isinstance(chunk, dict) or not isinstance(chunk.get("name"), str) or chunk["name"] in names or type(chunk.get("size")) is not int or not 0 < chunk["size"] < 2 * 1024**3:
            raise ValueError("invalid or duplicate release chunk")
        names.add(chunk["name"])
        total += chunk["size"]
    if total > 32 * 1024**3:
        raise ValueError("release payload exceeds download limit")
    verify_payload(payload, expected_roots={name: value.get("root_digest") for name, value in roots.items()})
    result = [payload / chunk["name"] for chunk in chunks]
    if any(any(character in str(path) for character in "\n\r#") for path in result):
        raise ValueError("asset path is not line-safe")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", required=True, type=Path)
    parser.add_argument("--approved-digest", required=True)
    parser.add_argument("--payload", type=Path)
    args = parser.parse_args()
    try:
        # The private signer gate ran upstream. This preflight binds companion
        # metadata to its bundle; it does not replace signature verification.
        directory = args.bundle.parent
        companions = [directory / name for name in (
            "node-operator-release-bundle.sha256", "manifest.json", "sbom.cyclonedx.json",
            "provenance-input.json", "signer-output/release-verification.json")]
        for path in companions:
            if path.is_symlink() or path.parent.is_symlink() or not path.is_file() or path.stat().st_size > MAX_METADATA_BYTES:
                raise ValueError("release companion asset unavailable")
        checksum, metadata, sbom, provenance, verification = companions
        if checksum.read_text().strip() != args.approved_digest + "  node-operator-release-bundle.tar":
            raise ValueError("release checksum mismatch")
        if _json(metadata.read_bytes()).get("artifact", {}).get("digest") != args.approved_digest or _json(sbom.read_bytes()).get("metadata", {}).get("component", {}).get("version") != args.approved_digest:
            raise ValueError("release manifest or SBOM mismatch")
        statement = _json(provenance.read_bytes())
        if statement.get("subject") != [{"name": args.bundle.name, "digest": {"sha256": args.approved_digest.removeprefix("sha256:")}}]:
            raise ValueError("provenance subject mismatch")
        result = _json(verification.read_bytes())
        if result.get("artifact") != {"name": args.bundle.name, "digest": args.approved_digest} or result.get("provenance", {}).get("sha256") != "sha256:" + hashlib.sha256(provenance.read_bytes()).hexdigest():
            raise ValueError("signer result mismatch")
        paths = assets(args.bundle, args.approved_digest, args.payload)
    except (ValueError, OSError, TypeError, AttributeError, tarfile.TarError):
        print("OCI release asset validation failed; publication must not proceed.", file=sys.stderr)
        return 65
    for path in paths:
        print(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
