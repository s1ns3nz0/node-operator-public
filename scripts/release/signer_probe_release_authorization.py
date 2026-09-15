"""Bind a signer-probe candidate publication record to a committed release.

This is local consistency checking only.  Callers must authenticate the bundle
and independently retrieve the exact trusted workflow run/artifact named by
the authorization before treating this record as evidence.  This module does
not perform Cosign verification, retrieve ECR state, or grant activation.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import stat
from typing import Any

from fence_build_inputs import InputError, _hash_regular_file
from signer_probe_build_inputs import INPUT_PATHS
from signer_probe_publication_record import SignerProbePublicationRecordError, validate_record

SHA40 = re.compile(r"^[a-f0-9]{40}$")
SHA256 = re.compile(r"^[a-f0-9]{64}$")
RUN = re.compile(r"^[1-9][0-9]*$")
IMAGE = re.compile(r"^[0-9]{12}\.dkr\.ecr\.ap-northeast-[12]\.amazonaws\.com/[a-z][a-z0-9-]{1,18}[a-z0-9]-baseline-validator-signer-identity-probe@sha256:[a-f0-9]{64}$")
MAX_JSON = 1024 * 1024
AUTH_PATH = "source/release/signer-probe-publication-authorization.json"
RECORD_PATH = "rendered/signer-probe-publication-record.json"


class SignerProbeReleaseAuthorizationError(ValueError):
    """A signer-probe release authorization is malformed or not release-bound."""


def _duplicates(items: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in items:
        if key in result:
            raise SignerProbeReleaseAuthorizationError("duplicate JSON object key")
        result[key] = value
    return result


def _read(path: Path) -> tuple[Any, bytes]:
    try:
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode) or info.st_size > MAX_JSON:
            raise SignerProbeReleaseAuthorizationError("bundle JSON input is unsafe")
        raw = path.read_bytes()
        return json.loads(raw.decode("utf-8"), object_pairs_hook=_duplicates), raw
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise SignerProbeReleaseAuthorizationError("bundle JSON input is invalid") from error


def _decode(raw: bytes) -> Any:
    if not isinstance(raw, bytes) or len(raw) > MAX_JSON:
        raise SignerProbeReleaseAuthorizationError("record bytes are invalid")
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise SignerProbeReleaseAuthorizationError("record JSON is invalid") from error


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise SignerProbeReleaseAuthorizationError("record object is invalid") from error


def _directory(path: Path, label: str) -> None:
    try:
        info = path.lstat()
    except OSError as error:
        raise SignerProbeReleaseAuthorizationError(f"{label} is unavailable") from error
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise SignerProbeReleaseAuthorizationError(f"{label} is unsafe")


def _exact(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise SignerProbeReleaseAuthorizationError(f"{label} schema is invalid")
    return value


def _text(value: Any, label: str, pattern: re.Pattern[str]) -> str:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise SignerProbeReleaseAuthorizationError(f"{label} is invalid")
    return value


def _manifest(value: Any, release: str) -> dict[str, tuple[str, int]]:
    value = _exact(value, {"schema_version", "artifact", "source_revision", "entries"}, "bundle manifest")
    if value["schema_version"] != "v1" or value["source_revision"] != release or not isinstance(value["entries"], list):
        raise SignerProbeReleaseAuthorizationError("bundle manifest release binding is invalid")
    entries: dict[str, tuple[str, int]] = {}
    for item in value["entries"]:
        item = _exact(item, {"path", "sha256", "size"}, "bundle manifest entry")
        if not isinstance(item["path"], str) or item["path"] in entries or type(item["size"]) is not int or item["size"] < 0:
            raise SignerProbeReleaseAuthorizationError("bundle manifest entry is invalid")
        entries[item["path"]] = (_text(item["sha256"], "bundle manifest hash", SHA256), item["size"])
    return entries


def validate_authorization(auth: Any, required_use: str = "stage") -> dict[str, Any]:
    """Validate strict authorization shape before a caller downloads its record."""
    if required_use != "stage":
        raise SignerProbeReleaseAuthorizationError("signer-probe authorization has no activation use")
    auth = _exact(auth, {"schema_version", "candidate_revision", "record_sha256", "publication", "target", "approvals"}, "signer-probe authorization")
    if type(auth["schema_version"]) is not int or auth["schema_version"] != 1:
        raise SignerProbeReleaseAuthorizationError("authorization version is invalid")
    candidate = _text(auth["candidate_revision"], "candidate revision", SHA40)
    _text(auth["record_sha256"], "record hash", SHA256)
    publication = _exact(auth["publication"], {"repository", "workflow", "run_id", "artifact_id"}, "publication")
    if publication["repository"] != "s1ns3nz0/node-operator" or publication["workflow"] != "image-publish.yml" or not isinstance(publication["run_id"], str) or not RUN.fullmatch(publication["run_id"]) or not isinstance(publication["artifact_id"], str) or not RUN.fullmatch(publication["artifact_id"]):
        raise SignerProbeReleaseAuthorizationError("trusted publication identity is invalid")
    target = _exact(auth["target"], {"image_ref", "manifest_digest", "input_sha256"}, "target")
    image_ref = _text(target["image_ref"], "target image reference", IMAGE)
    manifest_digest = _text(target["manifest_digest"], "target manifest digest", re.compile(r"^sha256:[a-f0-9]{64}$"))
    if image_ref.rsplit("@", 1)[1] != manifest_digest:
        raise SignerProbeReleaseAuthorizationError("target image digest differs from manifest digest")
    _text(target["input_sha256"], "target input hash", SHA256)
    approvals = _exact(auth["approvals"], {"stage_approved"}, "approvals")
    if type(approvals["stage_approved"]) is not bool or approvals["stage_approved"] is not True:
        raise SignerProbeReleaseAuthorizationError("stage approval is absent")
    return auth


def validate_candidate_authorization(auth: Any, record: Any, record_bytes: bytes,
                                     source_root: Path, required_use: str = "stage") -> dict[str, Any]:
    """Validate candidate record bytes and explicit stage approval after retrieval."""
    auth = validate_authorization(auth, required_use)
    decoded = _decode(record_bytes)
    if _canonical(decoded) != _canonical(record):
        raise SignerProbeReleaseAuthorizationError("record object does not match raw record bytes")
    if auth["record_sha256"] != hashlib.sha256(record_bytes).hexdigest():
        raise SignerProbeReleaseAuthorizationError("authorization record hash is invalid")
    record = decoded
    candidate = auth["candidate_revision"]
    publication = auth["publication"]
    target = auth["target"]
    try:
        validated = validate_record(record, source_root, expected_release_revision=candidate)
    except SignerProbePublicationRecordError as error:
        raise SignerProbeReleaseAuthorizationError("candidate signer-probe record is invalid") from error
    expected_target = {key: validated[key] for key in ("image_ref", "manifest_digest", "input_sha256")}
    if target != expected_target or publication["run_id"] != str(validated["publication"]["run_id"]):
        raise SignerProbeReleaseAuthorizationError("authorization does not bind candidate publication")
    return {"candidate_revision": candidate, "required_use": required_use,
            "record": validated, "publication": publication}


def _source_manifest_entries(source: Path, entries: dict[str, tuple[str, int]]) -> None:
    """Require the exact five reviewed source bytes in the authenticated manifest."""
    for relative in INPUT_PATHS:
        path = source / relative
        try:
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
                raise SignerProbeReleaseAuthorizationError("reviewed source manifest input is unsafe")
            digest = _hash_regular_file(source, relative)
        except (OSError, InputError) as error:
            raise SignerProbeReleaseAuthorizationError("reviewed source manifest input is unavailable") from error
        entry_path = f"source/{relative}"
        if entries.get(entry_path) != (digest, info.st_size):
            raise SignerProbeReleaseAuthorizationError("bundle manifest does not bind signer-probe source input")


def validate_release_authorization(bundle_root: Path, release_revision: str,
                                   required_use: str = "stage") -> dict[str, Any]:
    """Validate fixed auth/record bytes against a caller-authenticated release R."""
    if not isinstance(release_revision, str) or not SHA40.fullmatch(release_revision):
        raise SignerProbeReleaseAuthorizationError("release revision is invalid")
    if not bundle_root.is_absolute() or bundle_root.is_symlink():
        raise SignerProbeReleaseAuthorizationError("bundle root is unsafe")
    try:
        bundle_root = bundle_root.resolve(strict=True)
    except OSError as error:
        raise SignerProbeReleaseAuthorizationError("bundle root is unavailable") from error
    _directory(bundle_root, "bundle root")
    source = bundle_root / "source"
    _directory(source, "bundle source")
    _directory(source / "release", "bundle release source")
    _directory(bundle_root / "rendered", "bundle rendered output")
    manifest, _ = _read(bundle_root / "bundle-manifest.json")
    entries = _manifest(manifest, release_revision)
    _source_manifest_entries(source, entries)
    auth, auth_raw = _read(bundle_root / AUTH_PATH)
    record, record_raw = _read(bundle_root / RECORD_PATH)
    if (entries.get(AUTH_PATH) != (hashlib.sha256(auth_raw).hexdigest(), len(auth_raw))
            or entries.get(RECORD_PATH) != (hashlib.sha256(record_raw).hexdigest(), len(record_raw))):
        raise SignerProbeReleaseAuthorizationError("bundle manifest does not bind signer-probe authorization bytes")
    value = validate_candidate_authorization(auth, record, record_raw, source, required_use)
    return {"release_revision": release_revision, **value}
