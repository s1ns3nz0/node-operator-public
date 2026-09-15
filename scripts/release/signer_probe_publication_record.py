#!/usr/bin/env python3
"""Create and validate local signer-probe publication record consistency.

This record is a trusted-publisher assertion after the producer has completed
its cryptographic checks.  It does not itself verify Cosign, registry state,
or provenance.  A later reviewed authorization must bind its exact raw bytes
and independently authenticated workflow run/artifact metadata.
"""
from __future__ import annotations

import json
from pathlib import Path
import re
import stat
from typing import Any

from signer_probe_build_inputs import SignerProbeInputError, signer_probe_input_sha256

SHA40 = re.compile(r"^[a-f0-9]{40}$")
SHA256 = re.compile(r"^[a-f0-9]{64}$")
DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
ACCOUNT = re.compile(r"^[0-9]{12}$")
REGION = re.compile(r"^ap-northeast-[12]$")
NAME = re.compile(r"^[a-z][a-z0-9-]{1,18}[a-z0-9]$")
RUN = re.compile(r"^[1-9][0-9]*$")
MAX_JSON = 1024 * 1024
RECORD_KEYS = {"schema_version", "component", "kind", "release_revision", "build_revision", "third_party_source_revision", "image_ref", "manifest_digest", "input_sha256", "publication", "verification"}


class SignerProbePublicationRecordError(ValueError):
    """A signer-probe publication record is malformed or not source-bound."""


def _duplicates(items: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in items:
        if key in result:
            raise SignerProbePublicationRecordError("duplicate JSON object key")
        result[key] = value
    return result


def _exact(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise SignerProbePublicationRecordError(f"{label} schema is invalid")
    return value


def _text(value: Any, label: str, pattern: re.Pattern[str]) -> str:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise SignerProbePublicationRecordError(f"{label} is invalid")
    return value


def _context(account: Any, region: Any, deployment: Any, repository: Any,
             image_ref: Any, digest: Any) -> dict[str, str]:
    account = _text(account, "AWS account", ACCOUNT)
    region = _text(region, "AWS region", REGION)
    deployment = _text(deployment, "deployment name", NAME)
    if repository != f"{deployment}-baseline-validator-signer-identity-probe":
        raise SignerProbePublicationRecordError("signer-probe repository does not match deployment")
    digest = _text(digest, "manifest digest", DIGEST)
    expected = f"{account}.dkr.ecr.{region}.amazonaws.com/{repository}@{digest}"
    if image_ref != expected:
        raise SignerProbePublicationRecordError("image reference does not bind selected deployment")
    return {"aws_account_id": account, "aws_region": region, "deployment_name": deployment,
            "repository": repository, "image_ref": expected, "manifest_digest": digest}


def _image_context(image_ref: Any, digest: Any) -> dict[str, str]:
    image_ref = _text(image_ref, "image reference", re.compile(r"^[0-9]{12}\.dkr\.ecr\.ap-northeast-[12]\.amazonaws\.com/[a-z][a-z0-9-]{1,18}[a-z0-9]-baseline-validator-signer-identity-probe@sha256:[a-f0-9]{64}$"))
    digest = _text(digest, "manifest digest", DIGEST)
    registry, rest = image_ref.split("/", 1)
    repository, actual_digest = rest.split("@", 1)
    registry_parts = registry.split(".")
    account, region = registry_parts[0], registry_parts[3]
    deployment = repository.removesuffix("-baseline-validator-signer-identity-probe")
    value = _context(account, region, deployment, repository, image_ref, digest)
    if actual_digest != digest:
        raise SignerProbePublicationRecordError("image digest differs from manifest digest")
    return value


def create_record(source_root: Path, *, release_revision: str, build_revision: str,
                  input_sha256: str, aws_account_id: str, aws_region: str,
                  deployment_name: str, repository: str, image_ref: str,
                  manifest_digest: str, run_id: str | int,
                  invocation: str = "signer-probe-publish") -> dict[str, Any]:
    """Return a source-bound first-party record; never writes or publishes it."""
    context = _context(aws_account_id, aws_region, deployment_name, repository, image_ref, manifest_digest)
    record = {
        "schema_version": 1,
        "component": "validator-signer-identity-probe",
        "kind": "image",
        "release_revision": _text(release_revision, "release revision", SHA40),
        "build_revision": _text(build_revision, "build revision", SHA40),
        "third_party_source_revision": None,
        "image_ref": context["image_ref"],
        "manifest_digest": context["manifest_digest"],
        "input_sha256": _text(input_sha256, "input hash", SHA256),
        "publication": {"workflow": "image-publish.yml", "run_id": run_id,
                        "invocation": invocation},
        "verification": {"method": "cosign-and-slsa", "status": "passed"},
    }
    return validate_record(record, source_root, expected_release_revision=release_revision,
                           expected_context=context)


def validate_record(record: Any, source_root: Path, *, expected_release_revision: str | None = None,
                    expected_context: dict[str, str] | None = None) -> dict[str, Any]:
    """Validate the strict envelope against local reviewed signer-probe inputs."""
    record = _exact(record, RECORD_KEYS, "signer-probe publication record")
    if type(record["schema_version"]) is not int or record["schema_version"] != 1 or record["component"] != "validator-signer-identity-probe" or record["kind"] != "image" or record["third_party_source_revision"] is not None:
        raise SignerProbePublicationRecordError("signer-probe record identity is invalid")
    release = _text(record["release_revision"], "release revision", SHA40)
    if _text(record["build_revision"], "build revision", SHA40) != release:
        raise SignerProbePublicationRecordError("first-party build revision differs from release")
    if expected_release_revision is not None and release != _text(expected_release_revision, "expected release revision", SHA40):
        raise SignerProbePublicationRecordError("record release differs from expected release")
    input_sha = _text(record["input_sha256"], "input hash", SHA256)
    try:
        actual_input = signer_probe_input_sha256(source_root)
    except SignerProbeInputError as error:
        raise SignerProbePublicationRecordError("reviewed signer-probe inputs are unsafe") from error
    if input_sha != actual_input:
        raise SignerProbePublicationRecordError("input hash does not bind reviewed signer-probe inputs")
    context = _image_context(record["image_ref"], record["manifest_digest"])
    if expected_context is not None:
        if not isinstance(expected_context, dict) or context != expected_context:
            raise SignerProbePublicationRecordError("record target differs from selected deployment")
    publication = _exact(record["publication"], {"workflow", "run_id", "invocation"}, "publication")
    if publication["workflow"] != "image-publish.yml" or publication["invocation"] != "signer-probe-publish" or isinstance(publication["run_id"], bool) or not isinstance(publication["run_id"], (str, int)) or not RUN.fullmatch(str(publication["run_id"])):
        raise SignerProbePublicationRecordError("publication identity is invalid")
    verification = _exact(record["verification"], {"method", "status"}, "verification")
    if verification != {"method": "cosign-and-slsa", "status": "passed"}:
        raise SignerProbePublicationRecordError("publisher verification assertion is invalid")
    return record


def load_and_validate(path: Path, source_root: Path, **kwargs: Any) -> dict[str, Any]:
    """Load one bounded, regular JSON record and validate it."""
    try:
        info = path.lstat()
        if path.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_size > MAX_JSON:
            raise SignerProbePublicationRecordError("record file is unsafe")
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_duplicates)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise SignerProbePublicationRecordError("record JSON is invalid") from error
    return validate_record(value, source_root, **kwargs)
