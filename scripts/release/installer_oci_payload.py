#!/usr/bin/env python3
"""Create and verify a small, digest-preserving OCI release payload.

This is deliberately an offline transport helper.  Its input digest is an
approval *claim* supplied by its caller; this module never discovers or
approves an image, verifies a release signature, contacts a registry, or
imports into ECR.  A caller must bind ``payload-manifest.json`` and chunks to
signed release metadata before trusting a download.

Input trees and output parents must be access-controlled and quiescent for the
operation. This helper is not a sandbox against concurrent same-user writers.
Blobs shared across different named layouts are currently transported once per
layout; this version does not claim cross-layout storage deduplication.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import tarfile
import tempfile
from typing import Any, Mapping

MAX_METADATA_BYTES = 4 * 1024 * 1024
MAX_ENTRIES = 100_000
MAX_CHUNK_BYTES = 2 * 1024 * 1024 * 1024 - 1
DEFAULT_CHUNK_BYTES = 1024 * 1024 * 1024
COPY_BYTES = 1024 * 1024
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
OCI_INDEX_TYPES = {"application/vnd.oci.image.index.v1+json", "application/vnd.docker.distribution.manifest.list.v2+json"}
OCI_MANIFEST_TYPES = {"application/vnd.oci.image.manifest.v1+json", "application/vnd.docker.distribution.manifest.v2+json"}


class OciPayloadError(ValueError):
    pass


def _duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value = {}
    for key, item in pairs:
        if key in value:
            raise OciPayloadError("duplicate JSON object key")
        value[key] = item
    return value


def _sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(COPY_BYTES), b""):
            digest.update(block)
    return digest.hexdigest()


def _regular(path: Path, what: str) -> os.stat_result:
    try:
        info = path.lstat()
    except OSError as error:
        raise OciPayloadError(f"missing {what}") from error
    if not stat.S_ISREG(info.st_mode):
        raise OciPayloadError(f"{what} is not a regular file")
    return info


def _json_bytes(raw: bytes, what: str) -> dict[str, Any]:
    if len(raw) > MAX_METADATA_BYTES:
        raise OciPayloadError(f"{what} metadata is too large")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError, OciPayloadError) as error:
        raise OciPayloadError(f"invalid {what} JSON") from error
    if not isinstance(value, dict):
        raise OciPayloadError(f"{what} JSON must be an object")
    return value


def _load_json_file(path: Path, what: str) -> dict[str, Any]:
    """Bound metadata before reading it, avoiding a metadata-size allocation."""
    if _regular(path, what).st_size > MAX_METADATA_BYTES:
        raise OciPayloadError(f"{what} metadata is too large")
    try:
        return _json_bytes(path.read_bytes(), what)
    except OSError as error:
        raise OciPayloadError(f"cannot read {what}") from error


def _descriptor(item: Any) -> tuple[str, int, str]:
    if not isinstance(item, dict) or set(item) - {"mediaType", "digest", "size", "annotations", "platform", "urls", "artifactType", "data"}:
        raise OciPayloadError("descriptor schema is invalid")
    digest, size, media_type = item.get("digest"), item.get("size"), item.get("mediaType")
    if not isinstance(digest, str) or not DIGEST.fullmatch(digest) or not isinstance(size, int) or isinstance(size, bool) or size < 0 or not isinstance(media_type, str):
        raise OciPayloadError("descriptor is invalid")
    return digest, size, media_type


def _safe_label(label: str) -> str:
    if not isinstance(label, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", label):
        raise OciPayloadError("layout name is unsafe")
    return label


def _layout_files(label: str, root: Path, expected: str) -> tuple[list[tuple[str, Path]], dict[str, Any], bytes]:
    _safe_label(label)
    if root.is_symlink() or not root.is_dir():
        raise OciPayloadError("OCI layout root must be a non-symlink directory")
    # Reject surprising content rather than silently transporting it.
    allowed = {"oci-layout", "index.json", "blobs", "ingest"}
    try:
        top = list(root.iterdir())
    except OSError as error:
        raise OciPayloadError("cannot list OCI layout") from error
    names = {item.name for item in top}
    if not {"oci-layout", "index.json", "blobs"}.issubset(names) or names - allowed or any(item.is_symlink() for item in top):
        raise OciPayloadError("OCI layout has unexpected or symlinked paths")
    ingest = root / "ingest"
    if ingest.exists() and (ingest.is_symlink() or not ingest.is_dir() or any(ingest.iterdir())):
        raise OciPayloadError("OCI ingest directory must be an empty non-symlink directory")
    layout_file, index_file, blobs = root / "oci-layout", root / "index.json", root / "blobs" / "sha256"
    _regular(layout_file, "oci-layout"); _regular(index_file, "index.json")
    if (root / "blobs").is_symlink() or not blobs.is_dir() or blobs.is_symlink() or any(item.is_symlink() for item in (root / "blobs").iterdir()):
        raise OciPayloadError("OCI blob directory is unsafe")
    layout = _load_json_file(layout_file, "oci-layout")
    if layout != {"imageLayoutVersion": "1.0.0"}:
        raise OciPayloadError("OCI layout version is invalid")
    index = _load_json_file(index_file, "index")
    if set(index) - {"schemaVersion", "mediaType", "manifests", "annotations"} or index.get("schemaVersion") != 2 or not isinstance(index.get("manifests"), list):
        raise OciPayloadError("OCI index schema is invalid")
    roots = [_descriptor(item) for item in index["manifests"]]
    if [digest for digest, _, _ in roots].count(expected) != 1:
        raise OciPayloadError("expected root is not uniquely present in OCI index")
    chosen = next(item for item in index["manifests"] if item["digest"] == expected)
    _, _, root_type = _descriptor(chosen)
    seen: set[str] = set()
    entries: list[tuple[str, Path]] = [(f"oci/{label}/oci-layout", layout_file)]
    descriptor_seen: dict[str, tuple[int, str]] = {}

    def visit(descriptor: Any) -> None:
        digest, size, media_type = _descriptor(descriptor)
        previous = descriptor_seen.get(digest)
        if previous is not None and previous != (size, media_type):
            raise OciPayloadError("repeated OCI descriptor conflicts with prior descriptor")
        descriptor_seen[digest] = (size, media_type)
        if digest in seen:
            return
        seen.add(digest)
        name = digest[7:]; blob = blobs / name
        info = _regular(blob, "OCI blob")
        if info.st_size != size or _sha(blob) != name:
            raise OciPayloadError("OCI blob size or digest does not match descriptor")
        entries.append((f"oci/{label}/blobs/sha256/{name}", blob))
        # Only index and manifest documents have descriptor edges.  Config JSON
        # is terminal even if it happens to contain a 'config' or 'layers' key.
        if media_type in OCI_INDEX_TYPES:
            document = _load_json_file(blob, "OCI index blob")
            if document.get("schemaVersion") != 2 or not isinstance(document.get("manifests"), list):
                raise OciPayloadError("OCI index blob schema is invalid")
            for child in document["manifests"]:
                visit(child)
        elif media_type in OCI_MANIFEST_TYPES:
            document = _load_json_file(blob, "OCI manifest blob")
            if document.get("schemaVersion") != 2 or not isinstance(document.get("config"), dict) or not isinstance(document.get("layers"), list):
                raise OciPayloadError("OCI manifest blob schema is invalid")
            visit(document["config"])
            for child in document["layers"]:
                visit(child)
        elif digest == expected:
            raise OciPayloadError("root descriptor must be an OCI/Docker index or manifest")

    if root_type not in OCI_INDEX_TYPES | OCI_MANIFEST_TYPES:
        raise OciPayloadError("root descriptor media type is unsupported")
    visit(chosen)
    for item in blobs.iterdir():
        if item.is_symlink() or not item.is_file() or not re.fullmatch(r"[0-9a-f]{64}", item.name):
            raise OciPayloadError("OCI blob path is unsafe")
    # The input index can carry historical or unrelated roots.  Emit an index
    # containing only the caller-approved root.  Its content digest is the
    # manifest/index blob digest, so this does not alter the approved root.
    ref_name = f"root-{expected[7:19]}"
    emitted = dict(chosen)
    emitted["annotations"] = {"org.opencontainers.image.ref.name": ref_name}
    emitted_index = json.dumps({"schemaVersion": 2, "manifests": [emitted]}, sort_keys=True, separators=(",", ":")).encode()
    return entries, {"root_digest": expected, "root_media_type": root_type, "root_annotations": emitted["annotations"]}, emitted_index


def _copy_tar_entry(tar: tarfile.TarFile, arcname: str, source: Path) -> None:
    info = _regular(source, "payload source")
    member = tarfile.TarInfo(arcname); member.size = info.st_size; member.mode = 0o644; member.mtime = 0; member.uid = member.gid = 0; member.uname = member.gname = ""
    with source.open("rb") as handle:
        tar.addfile(member, handle)


def prepare_payload(layouts: Mapping[str, tuple[str | Path, str]], output_dir: str | Path, *, chunk_limit: int = DEFAULT_CHUNK_BYTES) -> dict[str, Any]:
    """Validate approved local layouts and create deterministic chunk assets.

    ``layouts`` maps a stable artifact name to ``(OCI layout root, approved
    root digest)``. The output directory must not exist; no source is modified.
    """
    if not isinstance(chunk_limit, int) or isinstance(chunk_limit, bool) or not 10240 <= chunk_limit <= MAX_CHUNK_BYTES:
        raise OciPayloadError("chunk limit is unsafe")
    if not isinstance(layouts, Mapping) or not layouts:
        raise OciPayloadError("at least one approved OCI layout is required")
    output = Path(output_dir)
    if output.exists() or output.is_symlink() or output.parent.is_symlink() or not output.parent.is_dir():
        raise OciPayloadError("payload output already exists or parent is unsafe")
    files: list[tuple[str, Path]] = []; roots: dict[str, Any] = {}; generated_indexes: dict[str, bytes] = {}
    for label in sorted(layouts):
        value = layouts[label]
        if not isinstance(value, tuple) or len(value) != 2 or not isinstance(value[1], str) or not DIGEST.fullmatch(value[1]):
            raise OciPayloadError("layout input is invalid")
        group, root_info, index_bytes = _layout_files(label, Path(value[0]), value[1]); files.extend(group); roots[label] = root_info; generated_indexes[label] = index_bytes
    if len(files) > MAX_ENTRIES or len({name for name, _ in files}) != len(files):
        raise OciPayloadError("payload entry set is invalid")
    files.sort(key=lambda item: item[0])
    stage = Path(tempfile.mkdtemp(prefix=".oci-payload-", dir=output.parent)); chunks = stage / "chunks"; chunks.mkdir(mode=0o700)
    try:
        for label, data in generated_indexes.items():
            path = stage / f".index-{label}"; path.write_bytes(data); os.chmod(path, 0o600)
            files.append((f"oci/{label}/index.json", path))
        files.sort(key=lambda item: item[0])
        def tar_size(group: list[tuple[str, Path]]) -> int:
            content = sum(512 + ((path.lstat().st_size + 511) // 512) * 512 for _, path in group) + 1024
            return ((content + 10239) // 10240) * 10240
        if any(tar_size([item]) > chunk_limit for item in files):
            raise OciPayloadError("a payload file cannot fit safely in one chunk")
        assignments: list[list[tuple[str, Path]]] = [[]]
        for item in files:
            if assignments[-1] and tar_size(assignments[-1] + [item]) > chunk_limit:
                assignments.append([])
            assignments[-1].append(item)
        chunk_rows = []
        for number, group in enumerate(assignments):
            name = f"oci-payload-{number:05d}.tar"; path = chunks / name
            with tarfile.open(path, "w", format=tarfile.USTAR_FORMAT) as tar:
                for arcname, source in group: _copy_tar_entry(tar, arcname, source)
            size = path.stat().st_size
            if size >= 2 * 1024 * 1024 * 1024 or size > chunk_limit: raise OciPayloadError("chunk exceeds configured size limit")
            chunk_rows.append({"name": f"chunks/{name}", "sha256": _sha(path), "size": size, "entries": [name for name, _ in group]})
        manifest = {"schema_version": 1, "roots": roots, "entries": [{"path": name, "sha256": _sha(path), "size": path.stat().st_size} for name, path in files], "chunks": chunk_rows}
        encoded = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode() + b"\n"
        if len(encoded) > MAX_METADATA_BYTES: raise OciPayloadError("payload manifest is too large")
        (stage / "payload-manifest.json").write_bytes(encoded); os.chmod(stage / "payload-manifest.json", 0o600)
        os.rename(stage, output)
        return manifest
    except Exception:
        shutil.rmtree(stage, ignore_errors=True)
        raise


def _safe_member(name: str) -> str:
    if not isinstance(name, str):
        raise OciPayloadError("unsafe chunk member path")
    path = PurePosixPath(name)
    if not isinstance(name, str) or not name or "\\" in name or path.is_absolute() or any(part in ("", ".", "..") for part in path.parts) or str(path) != name:
        raise OciPayloadError("unsafe chunk member path")
    return name


def verify_payload(payload_dir: str | Path, *, expected_roots: Mapping[str, str], reconstruct_dir: str | Path | None = None) -> dict[str, Any]:
    """Verify chunks and closure; optionally reconstruct safe OCI layouts.

    Reconstructed layouts retain ``index.json`` descriptors and can be used as
    an oras OCI-layout source. This does not authenticate release metadata.
    """
    root = Path(payload_dir)
    if root.is_symlink() or not root.is_dir(): raise OciPayloadError("payload directory is unsafe")
    manifest_path = root / "payload-manifest.json"; _regular(manifest_path, "payload manifest")
    manifest = _load_json_file(manifest_path, "payload manifest")
    if set(manifest) != {"schema_version", "roots", "entries", "chunks"} or manifest["schema_version"] != 1 or not isinstance(manifest["roots"], dict) or not isinstance(manifest["entries"], list) or not isinstance(manifest["chunks"], list): raise OciPayloadError("payload manifest schema is invalid")
    actual_roots: dict[str, str] = {}
    for label, value in manifest["roots"].items():
        _safe_label(label)
        if not isinstance(value, dict) or set(value) != {"root_digest", "root_media_type", "root_annotations"} or not isinstance(value["root_digest"], str) or not DIGEST.fullmatch(value["root_digest"]) or value["root_media_type"] not in OCI_INDEX_TYPES | OCI_MANIFEST_TYPES or not isinstance(value["root_annotations"], dict):
            raise OciPayloadError("payload root schema is invalid")
        actual_roots[label] = value["root_digest"]
    if not isinstance(expected_roots, Mapping) or not expected_roots or any(not isinstance(key, str) or not isinstance(value, str) or not DIGEST.fullmatch(value) for key, value in expected_roots.items()) or actual_roots != dict(expected_roots):
        raise OciPayloadError("payload roots differ from caller approval")
    entry_map = {}; chunk_entries = []
    for entry in manifest["entries"]:
        if not isinstance(entry, dict) or set(entry) != {"path", "sha256", "size"}: raise OciPayloadError("payload entry schema is invalid")
        name = _safe_member(entry["path"])
        if name in entry_map or not isinstance(entry["sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", entry["sha256"]) or not isinstance(entry["size"], int) or isinstance(entry["size"], bool) or entry["size"] < 0: raise OciPayloadError("payload entry is invalid")
        entry_map[name] = entry
    for chunk in manifest["chunks"]:
        if not isinstance(chunk, dict) or set(chunk) != {"name", "sha256", "size", "entries"} or not isinstance(chunk["name"], str) or not re.fullmatch(r"chunks/oci-payload-[0-9]{5}\.tar", chunk["name"]) or not isinstance(chunk["entries"], list): raise OciPayloadError("chunk schema is invalid")
        if (root / "chunks").is_symlink() or not (root / "chunks").is_dir(): raise OciPayloadError("payload chunk directory is unsafe")
        path = root / chunk["name"]; info = _regular(path, "payload chunk")
        if info.st_size != chunk["size"] or info.st_size >= 2 * 1024 * 1024 * 1024 or _sha(path) != chunk["sha256"]: raise OciPayloadError("chunk hash or size is invalid")
        seen = []
        try:
            with tarfile.open(path, "r:") as tar:
                for member in tar:
                    name = _safe_member(member.name)
                    if not member.isfile() or name not in entry_map or name in seen or member.size != entry_map[name]["size"]: raise OciPayloadError("chunk member is invalid")
                    src = tar.extractfile(member); digest = hashlib.sha256()
                    for data in iter(lambda: src.read(COPY_BYTES) if src else b"", b""): digest.update(data)
                    if digest.hexdigest() != entry_map[name]["sha256"]: raise OciPayloadError("chunk member digest is invalid")
                    seen.append(name)
        except (tarfile.TarError, OSError) as error: raise OciPayloadError("chunk cannot be verified") from error
        if seen != chunk["entries"]: raise OciPayloadError("chunk members do not match manifest")
        chunk_entries.extend(seen)
    if sorted(chunk_entries) != sorted(entry_map) or len(chunk_entries) != len(set(chunk_entries)): raise OciPayloadError("chunks do not cover entries exactly")
    destination = Path(reconstruct_dir) if reconstruct_dir is not None else None
    stage_parent = destination.parent if destination is not None else root.parent
    if destination is not None and (destination.exists() or destination.is_symlink() or destination.parent.is_symlink() or not destination.parent.is_dir()): raise OciPayloadError("reconstruction output already exists or parent is unsafe")
    stage = Path(tempfile.mkdtemp(prefix=".oci-reconstruct-", dir=stage_parent))
    try:
        # Re-read each chunk hash immediately before extracting, then validate
        # the reconstructed closure before making any caller-visible output.
        for chunk in manifest["chunks"]:
            path = root / chunk["name"]
            if _sha(path) != chunk["sha256"] or path.lstat().st_size != chunk["size"]: raise OciPayloadError("chunk changed while being verified")
            with tarfile.open(path, "r:") as tar:
                for member in tar:
                    name = _safe_member(member.name)
                    if not member.isfile() or name not in entry_map or member.size != entry_map[name]["size"]: raise OciPayloadError("chunk member changed while extracting")
                    target = stage / name; target.parent.mkdir(parents=True, exist_ok=True)
                    source = tar.extractfile(member)
                    if source is None: raise OciPayloadError("cannot extract payload member")
                    with target.open("xb") as handle: shutil.copyfileobj(source, handle, COPY_BYTES)
                    # A successful tar read is not evidence that the bytes
                    # written to staging still equal the manifest entry.
                    if target.lstat().st_size != entry_map[name]["size"] or _sha(target) != entry_map[name]["sha256"]:
                        raise OciPayloadError("extracted payload member digest is invalid")
        closure = set()
        for label, data in manifest["roots"].items():
            group, _, _ = _layout_files(label, stage / "oci" / label, data["root_digest"])
            closure.update(name for name, _ in group); closure.add(f"oci/{label}/index.json")
        if closure != set(entry_map): raise OciPayloadError("payload entries are not exactly the approved OCI closures")
        if destination is not None: os.rename(stage, destination); stage = None
    finally:
        if stage is not None: shutil.rmtree(stage, ignore_errors=True)
    return manifest
