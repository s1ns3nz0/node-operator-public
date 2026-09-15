"""Validate a committed Prysm candidate-to-release authorization.

This is a consistency check only.  Callers must independently authenticate the
bundle and its provenance before using this result; the local manifest is not
an authenticity assertion and this module never activates a validator.
"""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import re
import stat
from typing import Any
from prysm_publication_record import PrysmPublicationRecordError, validate_record

SHA40 = re.compile(r"^[a-f0-9]{40}$")
SHA256 = re.compile(r"^[a-f0-9]{64}$")
RUN = re.compile(r"^[1-9][0-9]*$")
MAX = 1024 * 1024
AUTH_PATH = "source/release/prysm-publication-authorization.json"
RECORD_PATH = "rendered/prysm-mtls-publication-record.json"

class PrysmReleaseAuthorizationError(ValueError):
    """An authorization is not bound to the candidate and authenticated release."""

def _read(path: Path) -> tuple[Any, bytes]:
    try:
        info = path.lstat()
        if path.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_size > MAX:
            raise PrysmReleaseAuthorizationError("authorization input is unsafe")
        data = path.read_bytes()
        def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
            out: dict[str, Any] = {}
            for key, value in items:
                if key in out: raise PrysmReleaseAuthorizationError("duplicate JSON key")
                out[key] = value
            return out
        return json.loads(data.decode("utf-8"), object_pairs_hook=pairs), data
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise PrysmReleaseAuthorizationError("authorization JSON is invalid") from error

def _directory(path: Path, label: str) -> None:
    try:
        info = path.lstat()
    except OSError as error:
        raise PrysmReleaseAuthorizationError(f"{label} is unavailable") from error
    if path.is_symlink() or not stat.S_ISDIR(info.st_mode):
        raise PrysmReleaseAuthorizationError(f"{label} is unsafe")

def _obj(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys: raise PrysmReleaseAuthorizationError(f"{label} schema is invalid")
    return value

def _text(value: Any, label: str, pattern: re.Pattern[str]) -> str:
    if not isinstance(value, str) or not pattern.fullmatch(value): raise PrysmReleaseAuthorizationError(f"{label} is invalid")
    return value

def _manifest(manifest: Any, release: str) -> dict[str, str]:
    manifest = _obj(manifest, {"schema_version", "artifact", "source_revision", "entries"}, "bundle manifest")
    if manifest["schema_version"] != "v1" or manifest["source_revision"] != release or not isinstance(manifest["entries"], list):
        raise PrysmReleaseAuthorizationError("bundle manifest release binding is invalid")
    seen: dict[str, str] = {}
    for item in manifest["entries"]:
        item = _obj(item, {"path", "sha256", "size"}, "bundle manifest entry")
        path = item["path"]
        if not isinstance(path, str) or path in seen or not isinstance(item["size"], int) or isinstance(item["size"], bool) or item["size"] < 0:
            raise PrysmReleaseAuthorizationError("bundle manifest entry is invalid")
        seen[path] = _text(item["sha256"], "bundle manifest hash", SHA256)
    return seen

def validate_release_authorization(bundle_root: Path, release_revision: str, required_use: str) -> dict[str, Any]:
    """Validate fixed authorization/record bytes against caller-authenticated R."""
    if not isinstance(release_revision, str) or not SHA40.fullmatch(release_revision): raise PrysmReleaseAuthorizationError("release revision is invalid")
    if required_use not in {"stage", "activation"}: raise PrysmReleaseAuthorizationError("required use is invalid")
    if not bundle_root.is_absolute() or bundle_root.is_symlink() or not bundle_root.is_dir(): raise PrysmReleaseAuthorizationError("bundle root is unsafe")
    source_root = bundle_root / "source"
    _directory(source_root, "bundle source")
    _directory(source_root / "release", "bundle release source")
    _directory(bundle_root / "rendered", "bundle rendered output")
    manifest, _ = _read(bundle_root / "bundle-manifest.json")
    entries = _manifest(manifest, release_revision)
    auth, auth_bytes = _read(bundle_root / AUTH_PATH)
    record, record_bytes = _read(bundle_root / RECORD_PATH)
    if entries.get(AUTH_PATH) != hashlib.sha256(auth_bytes).hexdigest() or entries.get(RECORD_PATH) != hashlib.sha256(record_bytes).hexdigest():
        raise PrysmReleaseAuthorizationError("bundle manifest does not bind Prysm authorization bytes")
    auth = _obj(auth, {"schema_version", "candidate_revision", "record_sha256", "publication", "target", "approvals"}, "Prysm authorization")
    if type(auth["schema_version"]) is not int or auth["schema_version"] != 1: raise PrysmReleaseAuthorizationError("authorization version is invalid")
    candidate = _text(auth["candidate_revision"], "candidate revision", SHA40)
    if _text(auth["record_sha256"], "record hash", SHA256) != hashlib.sha256(record_bytes).hexdigest(): raise PrysmReleaseAuthorizationError("authorization record hash is invalid")
    publication = _obj(auth["publication"], {"repository", "workflow", "run_id", "artifact_id"}, "publication")
    if publication["repository"] != "s1ns3nz0/node-operator" or publication["workflow"] != "image-publish.yml" or not RUN.fullmatch(str(publication["run_id"])) or isinstance(publication["run_id"], bool) or not isinstance(publication["artifact_id"], str) or not RUN.fullmatch(publication["artifact_id"]): raise PrysmReleaseAuthorizationError("publication identity is invalid")
    target = _obj(auth["target"], {"image_ref", "manifest_digest", "input_sha256"}, "target")
    approvals = _obj(auth["approvals"], {"stage_approved", "activation_approved"}, "approvals")
    if any(type(approvals[key]) is not bool for key in approvals) or not approvals["stage_approved"] or (required_use == "activation" and not approvals["activation_approved"]): raise PrysmReleaseAuthorizationError("required authorization approval is absent")
    try: validated = validate_record(record, source_root, expected_release_revision=candidate)
    except PrysmPublicationRecordError as error: raise PrysmReleaseAuthorizationError("candidate record is invalid") from error
    if str(publication["run_id"]) != str(validated["publication"]["run_id"]) or target != {"image_ref": validated["target"]["image_ref"], "manifest_digest": validated["target"]["manifest_digest"], "input_sha256": validated["input_sha256"]}: raise PrysmReleaseAuthorizationError("authorization does not bind candidate publication")
    return {"release_revision": release_revision, "candidate_revision": candidate, "required_use": required_use, "record": validated, "publication": publication}
