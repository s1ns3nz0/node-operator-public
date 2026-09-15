"""Validate a bundled Fence candidate record against a committed release authorization.

This is local consistency checking only: callers must first authenticate the
bundle and its provenance, and independently retrieve the exact trusted
workflow run/artifact named by the authorization before treating record flags
as evidence.  Checking recorded Cosign fields does not perform Cosign
verification, this module does not retrieve artifacts or attest ECR state, and
it never activates a validator.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import stat
from typing import Any

from fence_build_inputs import InputError, fence_input_sha256

SHA40 = re.compile(r"^[a-f0-9]{40}$")
SHA256 = re.compile(r"^[a-f0-9]{64}$")
DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
RUN = re.compile(r"^[1-9][0-9]*$")
UTC = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
DEPLOYMENT = r"[a-z][a-z0-9-]{1,18}[a-z0-9]"
IMAGE = re.compile(rf"^[0-9]{{12}}\.dkr\.ecr\.ap-northeast-2\.amazonaws\.com/{DEPLOYMENT}-baseline-validator-fence@sha256:[a-f0-9]{{64}}$")
MAX = 4 * 1024 * 1024
AUTH_PATH = "source/release/fence-publication-authorization.json"
RECORD_PATH = "rendered/fence-release-verification.json"
IDENTITY = "https://github.com/s1ns3nz0/node-operator/.github/workflows/image-publish.yml@refs/heads/main"
ISSUER = "https://token.actions.githubusercontent.com"


class FenceReleaseAuthorizationError(ValueError):
    pass


def _duplicates(items: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in items:
        if key in value:
            raise FenceReleaseAuthorizationError("duplicate JSON object key")
        value[key] = item
    return value


def _read(path: Path) -> tuple[Any, bytes]:
    try:
        info = path.lstat()
        if path.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_size > MAX:
            raise FenceReleaseAuthorizationError("bundle input is unsafe")
        raw = path.read_bytes()
        return json.loads(raw.decode("utf-8"), object_pairs_hook=_duplicates), raw
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise FenceReleaseAuthorizationError("bundle JSON is invalid") from error


def _decode(raw: bytes) -> Any:
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise FenceReleaseAuthorizationError("record JSON is invalid") from error


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise FenceReleaseAuthorizationError("record object is invalid") from error


def _obj(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise FenceReleaseAuthorizationError(f"{label} schema is invalid")
    return value


def _text(value: Any, label: str, pattern: re.Pattern[str]) -> str:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise FenceReleaseAuthorizationError(f"{label} is invalid")
    return value


def _manifest(value: Any, release: str) -> dict[str, str]:
    value = _obj(value, {"schema_version", "artifact", "source_revision", "entries"}, "bundle manifest")
    if value["schema_version"] != "v1" or value["source_revision"] != release or not isinstance(value["entries"], list):
        raise FenceReleaseAuthorizationError("bundle manifest release binding is invalid")
    result: dict[str, str] = {}
    for item in value["entries"]:
        item = _obj(item, {"path", "sha256", "size"}, "bundle manifest entry")
        if not isinstance(item["path"], str) or item["path"] in result or type(item["size"]) is not int or item["size"] < 0:
            raise FenceReleaseAuthorizationError("bundle manifest entry is invalid")
        result[item["path"]] = _text(item["sha256"], "bundle manifest hash", SHA256)
    return result


def _record(value: Any, source_root: Path, candidate: str) -> dict[str, Any]:
    value = _obj(value, {"schema_version", "event_type", "collected_at_utc", "image", "artifact_digest", "source_revision", "input_sha256", "result", "cryptographic_verification", "sbom", "vulnerability_scan"}, "Fence release record")
    digest = _text(value["artifact_digest"], "Fence digest", DIGEST)
    image = _text(value["image"], "Fence image", IMAGE)
    _text(value["collected_at_utc"], "Fence collection time", UTC)
    if image.rsplit("@", 1)[1] != digest or type(value["schema_version"]) is not int or value["schema_version"] != 1 or value["event_type"] != "validator-signing-fence-release-verification" or value["result"] != "PASS" or _text(value["source_revision"], "Fence source revision", SHA40) != candidate:
        raise FenceReleaseAuthorizationError("Fence record identity is invalid")
    try:
        expected_input = fence_input_sha256(source_root)
    except InputError as error:
        raise FenceReleaseAuthorizationError("Fence reviewed source inputs are unsafe") from error
    if _text(value["input_sha256"], "Fence input hash", SHA256) != expected_input:
        raise FenceReleaseAuthorizationError("Fence record input hash does not bind reviewed source")
    crypto = _obj(value["cryptographic_verification"], {"tool", "signature_count", "identity", "issuer", "slsa_provenance", "transparency_log_verified"}, "Fence cryptographic verification")
    if crypto["tool"] != "cosign" or type(crypto["signature_count"]) is not int or crypto["signature_count"] <= 0 or crypto["identity"] != IDENTITY or crypto["issuer"] != ISSUER or crypto["slsa_provenance"] is not True or crypto["transparency_log_verified"] is not True:
        raise FenceReleaseAuthorizationError("Fence cryptographic verification is invalid")
    sbom = _obj(value["sbom"], {"tool", "format", "component_count", "sha256"}, "Fence SBOM")
    if sbom["tool"] != "syft" or sbom["format"] != "cyclonedx-json" or type(sbom["component_count"]) is not int or sbom["component_count"] < 0 or not isinstance(sbom["sha256"], str) or not SHA256.fullmatch(sbom["sha256"]):
        raise FenceReleaseAuthorizationError("Fence SBOM is invalid")
    scan = _obj(value["vulnerability_scan"], {"schema_version", "tool", "scanner", "artifact_digest", "sbom_sha256", "scanned_at", "findings", "status"}, "Fence vulnerability scan")
    scanner = _obj(scan["scanner"], {"version", "database_built", "database_schema_version"}, "Fence scanner")
    findings = _obj(scan["findings"], {"critical", "high", "medium", "low", "unknown"}, "Fence vulnerability findings")
    if scan["schema_version"] != "v1" or scan["tool"] != "grype" or scan["artifact_digest"] != digest or scan["sbom_sha256"] != sbom["sha256"] or not isinstance(scan["scanned_at"], str) or not UTC.fullmatch(scan["scanned_at"]) or scan["status"] != "passed" or any(not isinstance(scanner[key], str) or not scanner[key] for key in scanner) or any(type(findings[key]) is not int or findings[key] < 0 for key in findings) or any(findings[key] != 0 for key in ("critical", "high", "unknown")):
        raise FenceReleaseAuthorizationError("Fence vulnerability scan is invalid")
    return value


def validate_candidate_authorization(auth: Any, record: Any, record_bytes: bytes, source_root: Path, required_use: str = "stage") -> dict[str, Any]:
    """Validate raw authorization/record consistency after caller binds bundle bytes."""
    if required_use not in {"stage", "activation"}:
        raise FenceReleaseAuthorizationError("required use is invalid")
    if not isinstance(record_bytes, bytes):
        raise FenceReleaseAuthorizationError("record bytes are invalid")
    decoded = _decode(record_bytes)
    if _canonical(decoded) != _canonical(record):
        raise FenceReleaseAuthorizationError("record object does not match supplied raw bytes")
    record = decoded
    auth = _obj(auth, {"schema_version", "candidate_revision", "record_sha256", "publication", "target", "approvals"}, "Fence authorization")
    if type(auth["schema_version"]) is not int or auth["schema_version"] != 1:
        raise FenceReleaseAuthorizationError("Fence authorization version is invalid")
    candidate = _text(auth["candidate_revision"], "Fence candidate revision", SHA40)
    if _text(auth["record_sha256"], "Fence record hash", SHA256) != hashlib.sha256(record_bytes).hexdigest():
        raise FenceReleaseAuthorizationError("Fence record hash is invalid")
    publication = _obj(auth["publication"], {"repository", "workflow", "run_id", "artifact_id"}, "Fence publication")
    if publication["repository"] != "s1ns3nz0/node-operator" or publication["workflow"] != "image-publish.yml" or not isinstance(publication["run_id"], str) or not RUN.fullmatch(publication["run_id"]) or not isinstance(publication["artifact_id"], str) or not RUN.fullmatch(publication["artifact_id"]):
        raise FenceReleaseAuthorizationError("Fence publication identity is invalid")
    target = _obj(auth["target"], {"image_ref", "manifest_digest", "input_sha256"}, "Fence target")
    approvals = _obj(auth["approvals"], {"stage_approved", "activation_approved"}, "Fence approvals")
    if any(type(item) is not bool for item in approvals.values()) or not approvals["stage_approved"] or (required_use == "activation" and not approvals["activation_approved"]):
        raise FenceReleaseAuthorizationError("Fence approval is absent")
    record = _record(record, source_root, candidate)
    if target != {"image_ref": record["image"], "manifest_digest": record["artifact_digest"], "input_sha256": record["input_sha256"]}:
        raise FenceReleaseAuthorizationError("Fence authorization does not bind candidate record")
    return {"candidate_revision": candidate, "required_use": required_use, "record": record, "publication": publication}


def validate_release_authorization(bundle_root: Path, release_revision: str, required_use: str) -> dict[str, Any]:
    if not isinstance(release_revision, str) or not SHA40.fullmatch(release_revision) or required_use not in {"stage", "activation"}:
        raise FenceReleaseAuthorizationError("release authorization arguments are invalid")
    if not bundle_root.is_absolute() or bundle_root.is_symlink() or not bundle_root.is_dir():
        raise FenceReleaseAuthorizationError("bundle root is unsafe")
    source = bundle_root / "source"
    if source.is_symlink() or not source.is_dir() or (source / "release").is_symlink() or not (source / "release").is_dir() or (bundle_root / "rendered").is_symlink() or not (bundle_root / "rendered").is_dir():
        raise FenceReleaseAuthorizationError("bundle layout is unsafe")
    manifest, _ = _read(bundle_root / "bundle-manifest.json")
    entries = _manifest(manifest, release_revision)
    auth, auth_bytes = _read(bundle_root / AUTH_PATH)
    record, record_bytes = _read(bundle_root / RECORD_PATH)
    if entries.get(AUTH_PATH) != hashlib.sha256(auth_bytes).hexdigest() or entries.get(RECORD_PATH) != hashlib.sha256(record_bytes).hexdigest():
        raise FenceReleaseAuthorizationError("bundle manifest does not bind Fence authorization bytes")
    validated = validate_candidate_authorization(auth, record, record_bytes, source, required_use)
    return {"release_revision": release_revision, **validated}
