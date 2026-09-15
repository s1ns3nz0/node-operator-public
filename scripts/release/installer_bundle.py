#!/usr/bin/env python3
"""Read-only verification for a downloaded node-operator release bundle.

This module deliberately does not extract archives or verify a Vault Transit
signature.  The latter happens in the private signing boundary; here we only
check that its recorded, already-verified result is bound to the downloaded
bytes and provenance.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import tarfile
import tempfile
from typing import Any


ARCHIVE_NAME = "node-operator-release-bundle.tar"
RELEASE_FILES = frozenset(
    {
        ARCHIVE_NAME,
        "node-operator-release-bundle.sha256",
        "manifest.json",
        "provenance-input.json",
        "release-verification.json",
        "sbom.cyclonedx.json",
    }
)
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
SHA40_RE = re.compile(r"^[0-9a-f]{40}$")
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
TRANSIT_SIGNATURE_RE = re.compile(r"^vault:v[0-9]+:[A-Za-z0-9+/=_-]+$")
MAX_JSON_BYTES = 4 * 1024 * 1024
MAX_MANIFEST_ENTRIES = 10_000
MAX_TAR_MEMBERS = 10_001  # manifest plus the maximum number of listed files
MAX_TAR_MEMBER_BYTES = 64 * 1024 * 1024
MAX_TAR_TOTAL_BYTES = 256 * 1024 * 1024
COPY_CHUNK_BYTES = 1024 * 1024


class ReleaseVerificationError(ValueError):
    """The downloaded evidence is malformed or does not describe its bytes."""


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ReleaseVerificationError("duplicate JSON object key")
        result[key] = value
    return result


def _load_json(path: Path) -> Any:
    try:
        size = path.lstat().st_size
    except OSError as error:
        raise ReleaseVerificationError(f"cannot read {path.name}: {error}") from error
    if size > MAX_JSON_BYTES:
        raise ReleaseVerificationError(f"JSON file is too large: {path.name}")
    try:
        data = path.read_bytes()
    except OSError as error:
        raise ReleaseVerificationError(f"cannot read {path.name}: {error}") from error
    if len(data) > MAX_JSON_BYTES:
        raise ReleaseVerificationError(f"JSON file is too large: {path.name}")
    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError, ReleaseVerificationError) as error:
        raise ReleaseVerificationError(f"invalid JSON in {path.name}: {error}") from error


def _canonical_digest(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _require_regular(path: Path) -> None:
    try:
        mode = path.lstat().st_mode
    except FileNotFoundError as error:
        raise ReleaseVerificationError(f"missing required file: {path.name}") from error
    if not stat.S_ISREG(mode):
        raise ReleaseVerificationError(f"required path is not a regular file: {path.name}")


def _safe_name(name: object) -> str:
    if not isinstance(name, str) or not name or "\x00" in name or "\\" in name:
        raise ReleaseVerificationError("entry path must be a non-empty POSIX relative path")
    path = PurePosixPath(name)
    if path.is_absolute() or any(part in ("", ".", "..") for part in path.parts):
        raise ReleaseVerificationError("unsafe entry path")
    if str(path) != name:
        raise ReleaseVerificationError("non-canonical entry path")
    return name


def _exact_object(value: Any, keys: set[str], description: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise ReleaseVerificationError(f"{description} has an unexpected schema")
    return value


def _validate_manifest(manifest: Any, *, outer: bool) -> dict[str, Any]:
    required = {"schema_version", "artifact", "source_revision", "entries"}
    if not isinstance(manifest, dict) or set(manifest) != required:
        raise ReleaseVerificationError("manifest has an unexpected schema")
    if manifest["schema_version"] != "v1" or not isinstance(manifest["source_revision"], str) or not SHA40_RE.fullmatch(manifest["source_revision"]):
        raise ReleaseVerificationError("manifest schema version or source revision is invalid")
    artifact_keys = {"name", "media_type", "digest"} if outer else {"name", "media_type"}
    artifact = _exact_object(manifest["artifact"], artifact_keys, "manifest artifact")
    if artifact["name"] != ARCHIVE_NAME or artifact["media_type"] != "application/x-tar":
        raise ReleaseVerificationError("manifest artifact identity is invalid")
    if outer and (not isinstance(artifact["digest"], str) or not DIGEST_RE.fullmatch(artifact["digest"])):
        raise ReleaseVerificationError("manifest artifact digest is invalid")
    if not isinstance(manifest["entries"], list):
        raise ReleaseVerificationError("manifest entries is not a list")
    if len(manifest["entries"]) > MAX_MANIFEST_ENTRIES:
        raise ReleaseVerificationError("manifest has too many entries")
    paths: set[str] = set()
    for entry in manifest["entries"]:
        entry = _exact_object(entry, {"path", "sha256", "size"}, "manifest entry")
        name = _safe_name(entry["path"])
        if name in paths:
            raise ReleaseVerificationError("duplicate manifest entry")
        paths.add(name)
        if not isinstance(entry["sha256"], str) or not SHA256_RE.fullmatch(entry["sha256"]):
            raise ReleaseVerificationError("manifest entry has an invalid SHA-256")
        if not isinstance(entry["size"], int) or isinstance(entry["size"], bool) or entry["size"] < 0:
            raise ReleaseVerificationError("manifest entry has an invalid size")
        if entry["size"] > MAX_TAR_MEMBER_BYTES:
            raise ReleaseVerificationError("manifest entry is too large")
    return manifest


def _validate_tar(archive: Path, manifest: dict[str, Any]) -> None:
    expected_entries = {entry["path"]: entry for entry in manifest["entries"]}
    manifest_bytes: bytes | None = None
    seen: set[str] = set()
    total_size = 0
    try:
        with tarfile.open(archive, "r:") as tar:
            for member in tar:
                if len(seen) >= MAX_TAR_MEMBERS:
                    raise ReleaseVerificationError("tar has too many members")
                name = _safe_name(member.name)
                if name in seen:
                    raise ReleaseVerificationError("duplicate tar entry")
                seen.add(name)
                if not member.isfile():
                    raise ReleaseVerificationError("tar contains a non-regular entry")
                if member.size > MAX_TAR_MEMBER_BYTES:
                    raise ReleaseVerificationError("tar member is too large")
                total_size += member.size
                if total_size > MAX_TAR_TOTAL_BYTES:
                    raise ReleaseVerificationError("tar contents are too large")
                extracted = tar.extractfile(member)
                if extracted is None:
                    raise ReleaseVerificationError("cannot inspect tar entry")
                digest_state = hashlib.sha256()
                contents = bytearray() if name == "bundle-manifest.json" else None
                for chunk in iter(lambda: extracted.read(1024 * 1024), b""):
                    digest_state.update(chunk)
                    if contents is not None:
                        contents.extend(chunk)
                digest = digest_state.hexdigest()
                if name == "bundle-manifest.json":
                    manifest_bytes = bytes(contents or b"")
                    continue
                expected = expected_entries.get(name)
                if expected is None or member.size != expected["size"] or digest != expected["sha256"]:
                    raise ReleaseVerificationError("tar entry does not match manifest")
    except (tarfile.TarError, OSError) as error:
        raise ReleaseVerificationError(f"invalid tar archive: {error}") from error
    if seen != set(expected_entries) | {"bundle-manifest.json"}:
        raise ReleaseVerificationError("tar entries do not exactly match the manifest")
    if manifest_bytes is None:
        raise ReleaseVerificationError("tar is missing bundle-manifest.json")
    if len(manifest_bytes) > MAX_JSON_BYTES:
        raise ReleaseVerificationError("embedded bundle manifest is too large")
    try:
        embedded = json.loads(manifest_bytes.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError, ReleaseVerificationError) as error:
        raise ReleaseVerificationError(f"invalid embedded bundle manifest: {error}") from error
    embedded = _validate_manifest(embedded, outer=False)
    if (embedded["source_revision"] != manifest["source_revision"] or embedded["entries"] != manifest["entries"] or
            embedded["artifact"] != {"name": ARCHIVE_NAME, "media_type": "application/x-tar"}):
        raise ReleaseVerificationError("embedded bundle manifest is not bound to outer manifest")


def verify_bundle(archive: str | Path, manifest: dict[str, Any], expected_bundle_digest: str | None = None) -> dict[str, Any]:
    """Verify original tar contents against the outer manifest without extraction."""
    archive_path = Path(archive)
    _require_regular(archive_path)
    actual_digest = "sha256:" + _sha256_file(archive_path)
    if expected_bundle_digest is not None and actual_digest != expected_bundle_digest:
        raise ReleaseVerificationError("tar digest does not match the outer manifest")
    _validate_tar(archive_path, manifest)
    return {"source_revision": manifest["source_revision"], "bundle_digest": actual_digest, "manifest": manifest}


def verify_release(download_dir: str | Path) -> dict[str, Any]:
    """Verify the complete fresh downloaded release evidence and tar contents.

    This checks recorded signer evidence bindings only; it does *not* perform
    offline cryptographic verification of the Transit signature.
    """
    directory = Path(download_dir)
    if directory.is_symlink() or not directory.is_dir():
        raise ReleaseVerificationError("download directory must be a non-symlink directory")
    present = {item.name for item in directory.iterdir()}
    if present != RELEASE_FILES:
        raise ReleaseVerificationError("download directory must contain exactly the six release assets")
    for name in RELEASE_FILES:
        _require_regular(directory / name)
    outer = _validate_manifest(_load_json(directory / "manifest.json"), outer=True)
    archive = directory / ARCHIVE_NAME
    checksum = (directory / "node-operator-release-bundle.sha256").read_text(encoding="utf-8")
    expected_checksum = f"{outer['artifact']['digest']}  {ARCHIVE_NAME}\n"
    if checksum != expected_checksum:
        raise ReleaseVerificationError("checksum file is not the canonical manifest-bound record")
    provenance = _load_json(directory / "provenance-input.json")
    verification = _load_json(directory / "release-verification.json")
    sbom = _load_json(directory / "sbom.cyclonedx.json")
    digest = outer["artifact"]["digest"]
    source_revision = outer["source_revision"]
    dependency = {"uri": "git+node-operator", "digest": {"gitCommit": source_revision}}
    try:
        dependencies = provenance["predicate"]["buildDefinition"]["resolvedDependencies"]
        subject = provenance["subject"]
        builder = provenance["predicate"]["runDetails"]["builder"]["id"]
    except (KeyError, TypeError) as error:
        raise ReleaseVerificationError("provenance has an unexpected schema") from error
    if (provenance.get("_type") != "https://in-toto.io/Statement/v1" or provenance.get("predicateType") != "https://slsa.dev/provenance/v1" or
            subject != [{"name": ARCHIVE_NAME, "digest": {"sha256": digest[7:]}}] or dependency not in dependencies or
            builder != "local://node-operator/scripts/ci/build-release-bundle.sh"):
        raise ReleaseVerificationError("provenance is not bound to the manifest")
    provenance_digest = "sha256:" + _sha256_file(directory / "provenance-input.json")
    try:
        valid_record = (verification["schema_version"] == "v1" and verification["artifact"] == {"name": ARCHIVE_NAME, "digest": digest} and
                        verification["provenance"]["sha256"] == provenance_digest and verification["provenance"]["subject_digest"] == digest and
                        verification["provenance"]["source_revision"] == source_revision and verification["provenance"]["builder_id"] == builder and
                        verification["transit"]["key"] == "node-operator-release" and verification["transit"]["verified"] is True and
                        isinstance(verification["transit"]["signature"], str) and TRANSIT_SIGNATURE_RE.fullmatch(verification["transit"]["signature"]) and
                        verification["signer"] == {"auth_method": "aws", "vault_role": "release-signer"} and
                        isinstance(verification["codebuild"]["build_id"], str) and bool(verification["codebuild"]["build_id"]))
    except (KeyError, TypeError):
        valid_record = False
    if not valid_record:
        raise ReleaseVerificationError("release verification record is not bound to this release")
    try:
        sbom_component = sbom["metadata"]["component"]
    except (KeyError, TypeError) as error:
        raise ReleaseVerificationError("SBOM has an unexpected schema") from error
    if sbom.get("bomFormat") != "CycloneDX" or sbom_component.get("name") != ARCHIVE_NAME or sbom_component.get("version") != digest:
        raise ReleaseVerificationError("SBOM is not bound to the manifest artifact")
    verify_bundle(archive, outer, digest)
    return {"release_sha": source_revision, "bundle_digest": digest, "manifest_digest": _canonical_digest(outer), "manifest": outer}


def _require_normalized_absolute_destination(destination: Path) -> None:
    if not destination.is_absolute() or Path(os.path.normpath(str(destination))) != destination:
        raise ReleaseVerificationError("destination must be a normalized absolute path")


def _require_safe_destination(destination: Path) -> None:
    """Require a new, absolute destination below existing real directories."""
    _require_normalized_absolute_destination(destination)
    try:
        destination.lstat()
    except FileNotFoundError:
        pass
    else:
        raise ReleaseVerificationError("destination already exists")
    # Do not let a harmless-looking output path walk through a symlink.  The
    # destination itself is deliberately absent, so inspect its ancestors.
    for ancestor in (destination.parent, *destination.parents):
        try:
            mode = ancestor.lstat().st_mode
        except OSError as error:
            raise ReleaseVerificationError(f"cannot inspect destination ancestor: {error}") from error
        if stat.S_ISLNK(mode) or not stat.S_ISDIR(mode):
            raise ReleaseVerificationError("destination has an unsafe ancestor")


def _copy_with_expected_digest(source: Path, target: Path, expected_digest: str) -> None:
    """Copy bytes once and bind the staging copy to the expected digest."""
    digest = hashlib.sha256()
    try:
        with source.open("rb") as reader, target.open("xb") as writer:
            for chunk in iter(lambda: reader.read(COPY_CHUNK_BYTES), b""):
                digest.update(chunk)
                writer.write(chunk)
        os.chmod(target, 0o600)
    except OSError as error:
        raise ReleaseVerificationError(f"cannot copy release bundle: {error}") from error
    if "sha256:" + digest.hexdigest() != expected_digest:
        raise ReleaseVerificationError("release bundle changed while it was being copied")


def _materialization_plan(archive: Path, manifest: dict[str, Any]) -> dict[str, tuple[int, str, int]]:
    """Return the exact files and normalized modes permitted in an output tree."""
    # This complete streaming validation also makes the archive metadata safe
    # to use as the source of executable semantics.
    _validate_tar(archive, manifest)
    plan: dict[str, tuple[int, str, int]] = {}
    try:
        with tarfile.open(archive, "r:") as tar:
            for member in tar:
                name = _safe_name(member.name)
                if not member.isfile():
                    raise ReleaseVerificationError("tar contains a non-regular entry")
                executable = bool(member.mode & 0o111)
                mode = 0o700 if executable else 0o600
                if name == "bundle-manifest.json":
                    extracted = tar.extractfile(member)
                    if extracted is None:
                        raise ReleaseVerificationError("cannot inspect embedded bundle manifest")
                    digest = hashlib.sha256()
                    for chunk in iter(lambda: extracted.read(COPY_CHUNK_BYTES), b""):
                        digest.update(chunk)
                    plan[name] = (member.size, digest.hexdigest(), mode)
                else:
                    entry = next((item for item in manifest["entries"] if item["path"] == name), None)
                    if entry is None:
                        raise ReleaseVerificationError("tar entry does not match manifest")
                    plan[name] = (entry["size"], entry["sha256"], mode)
    except (tarfile.TarError, OSError) as error:
        raise ReleaseVerificationError(f"invalid tar archive: {error}") from error
    for name in plan:
        parent = PurePosixPath(name).parent
        while str(parent) != ".":
            if str(parent) in plan:
                raise ReleaseVerificationError("tar has a file/directory path collision")
            parent = parent.parent
    return plan


def _private_parent(root: Path, relative: str) -> Path:
    """Create private output parents using only validated relative path parts."""
    parent = root
    for part in PurePosixPath(relative).parent.parts:
        if part == ".":
            continue
        parent = parent / part
        try:
            mode = parent.lstat().st_mode
        except FileNotFoundError:
            try:
                parent.mkdir(mode=0o700)
            except OSError as error:
                raise ReleaseVerificationError(f"cannot create output directory: {error}") from error
        else:
            if stat.S_ISLNK(mode) or not stat.S_ISDIR(mode):
                raise ReleaseVerificationError("unsafe output directory")
        os.chmod(parent, 0o700)
    return parent


def _extract_validated_tree(archive: Path, tree: Path, plan: dict[str, tuple[int, str, int]]) -> None:
    """Stream tar members to exclusive regular files; never call extractall."""
    seen: set[str] = set()
    try:
        with tarfile.open(archive, "r:") as tar:
            for member in tar:
                name = _safe_name(member.name)
                if name in seen or name not in plan or not member.isfile():
                    raise ReleaseVerificationError("tar changed during materialization")
                seen.add(name)
                expected_size, expected_hash, output_mode = plan[name]
                if member.size != expected_size:
                    raise ReleaseVerificationError("tar changed during materialization")
                parent = _private_parent(tree, name)
                output = parent / PurePosixPath(name).name
                flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
                if hasattr(os, "O_NOFOLLOW"):
                    flags |= os.O_NOFOLLOW
                descriptor = os.open(output, flags, output_mode)
                try:
                    digest = hashlib.sha256()
                    extracted = tar.extractfile(member)
                    if extracted is None:
                        raise ReleaseVerificationError("cannot extract tar entry")
                    written = 0
                    with os.fdopen(descriptor, "wb", closefd=False) as writer:
                        for chunk in iter(lambda: extracted.read(COPY_CHUNK_BYTES), b""):
                            written += len(chunk)
                            if written > expected_size:
                                raise ReleaseVerificationError("tar entry exceeds manifest size")
                            digest.update(chunk)
                            writer.write(chunk)
                    if written != expected_size or digest.hexdigest() != expected_hash:
                        raise ReleaseVerificationError("tar entry changed during materialization")
                    os.chmod(output, output_mode)
                finally:
                    os.close(descriptor)
    except (tarfile.TarError, OSError) as error:
        raise ReleaseVerificationError(f"cannot materialize release bundle: {error}") from error
    if seen != set(plan):
        raise ReleaseVerificationError("tar changed during materialization")


def _verify_materialized_tree(destination: Path, plan: dict[str, tuple[int, str, int]], manifest: dict[str, Any]) -> None:
    """Verify an idempotently reused tree has no unrecorded files or links."""
    if destination.is_symlink() or not destination.is_dir():
        raise ReleaseVerificationError("materialized destination is not a real directory")
    observed: set[str] = set()
    expected_directories = {str(parent) for name in plan for parent in PurePosixPath(name).parents if str(parent) != "."}
    for current, directories, files in os.walk(destination, topdown=True, followlinks=False):
        current_path = Path(current)
        if stat.S_IMODE(current_path.lstat().st_mode) != 0o700:
            raise ReleaseVerificationError("materialized directory has unsafe permissions")
        for name in directories[:]:
            child = current_path / name
            if child.is_symlink() or child.relative_to(destination).as_posix() not in expected_directories:
                raise ReleaseVerificationError("materialized tree contains an unexpected directory or symlink")
        for name in files:
            path = current_path / name
            relative = path.relative_to(destination).as_posix()
            try:
                mode = path.lstat().st_mode
            except OSError as error:
                raise ReleaseVerificationError(f"cannot inspect materialized file: {error}") from error
            if stat.S_ISLNK(mode) or not stat.S_ISREG(mode) or relative not in plan:
                raise ReleaseVerificationError("materialized tree contains an unexpected path")
            size, expected_hash, expected_mode = plan[relative]
            if path.stat().st_size != size or stat.S_IMODE(mode) != expected_mode or _sha256_file(path) != expected_hash:
                raise ReleaseVerificationError("materialized file does not match release bundle")
            observed.add(relative)
    if observed != set(plan):
        raise ReleaseVerificationError("materialized tree is incomplete")
    embedded = _load_json(destination / "bundle-manifest.json")
    embedded = _validate_manifest(embedded, outer=False)
    if (embedded["source_revision"] != manifest["source_revision"] or embedded["entries"] != manifest["entries"] or
            embedded["artifact"] != {"name": ARCHIVE_NAME, "media_type": "application/x-tar"}):
        raise ReleaseVerificationError("materialized embedded manifest is not bound to release")


def materialize_release(download_dir: str | Path, destination: str | Path, expected_release_sha: str,
                        expected_bundle_digest: str) -> Path:
    """Safely unpack a verified release into a new private absolute directory.

    Existing output is never overwritten.  A previously published output may
    be returned only after its complete tree is revalidated against the fresh,
    trusted release evidence and archive.
    """
    from installer_files import publish_directory
    if not isinstance(expected_release_sha, str) or not SHA40_RE.fullmatch(expected_release_sha):
        raise ReleaseVerificationError("expected release SHA is invalid")
    if not isinstance(expected_bundle_digest, str) or not DIGEST_RE.fullmatch(expected_bundle_digest):
        raise ReleaseVerificationError("expected bundle digest is invalid")
    context = verify_release(download_dir)
    if context["release_sha"] != expected_release_sha or context["bundle_digest"] != expected_bundle_digest:
        raise ReleaseVerificationError("release context does not match caller expectations")
    destination_path = Path(destination)
    _require_normalized_absolute_destination(destination_path)
    reuse = destination_path.exists() or destination_path.is_symlink()
    if reuse:
        # Reuse is intentionally narrower than normal destination acceptance:
        # a symlink must not turn idempotency into a path escape.
        if destination_path.is_symlink():
            raise ReleaseVerificationError("destination must not be a symlink")
        for ancestor in destination_path.parents:
            if ancestor.is_symlink() or not ancestor.is_dir():
                raise ReleaseVerificationError("destination has an unsafe ancestor")
    else:
        _require_safe_destination(destination_path)
    stage: Path | None = None
    try:
        stage = Path(tempfile.mkdtemp(prefix=".node-operator-materialize-", dir=destination_path.parent))
        os.chmod(stage, 0o700)
        staged_archive = stage / ARCHIVE_NAME
        _copy_with_expected_digest(Path(download_dir) / ARCHIVE_NAME, staged_archive, expected_bundle_digest)
        # Revalidate the immutable private copy, rather than trusting bytes read
        # before the copy completed.
        verify_bundle(staged_archive, context["manifest"], expected_bundle_digest)
        plan = _materialization_plan(staged_archive, context["manifest"])
        if reuse:
            _verify_materialized_tree(destination_path, plan, context["manifest"])
            return destination_path
        tree = stage / "tree"
        tree.mkdir(mode=0o700)
        _extract_validated_tree(staged_archive, tree, plan)
        _verify_materialized_tree(tree, plan, context["manifest"])
        try:
            destination_path.lstat()
        except FileNotFoundError:
            pass
        else:
            raise ReleaseVerificationError("destination appeared during materialization")
        publish_directory(tree, destination_path)
        return destination_path
    except OSError as error:
        raise ReleaseVerificationError(f"cannot publish materialized release: {error}") from error
    finally:
        if stage is not None:
            shutil.rmtree(stage, ignore_errors=True)


def main() -> int:
    parser = argparse.ArgumentParser(description="Read-only node-operator release bundle verifier")
    parser.add_argument("download_dir")
    arguments = parser.parse_args()
    try:
        context = verify_release(arguments.download_dir)
    except ReleaseVerificationError as error:
        parser.error(str(error))
    print(json.dumps({key: value for key, value in context.items() if key != "manifest"}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
