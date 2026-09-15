#!/usr/bin/env python3
"""Fail-closed parsing and bounded evidence writing for CI image attestations."""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import sys

MAX_MANIFEST = 4 * 1024 * 1024
MAX_SBOM = 16 * 1024 * 1024
MAX_RECEIPT = 1024 * 1024
# A maximum-size SBOM is JSON-embedded and base64-encoded in DSSE. Its verified
# envelope is therefore larger than MAX_SBOM but remains bounded.
MAX_VERIFY = 24 * 1024 * 1024
SHA = re.compile(r"[0-9a-f]{64}$")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}$")
REVISION = re.compile(r"[0-9a-f]{40}$")
MAX_EXACT_INTEGER = 2**53 - 1


class EvidenceError(ValueError):
    pass


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise EvidenceError("JSON contains duplicate keys")
        result[key] = value
    return result


def reject_nonfinite(value):
    raise EvidenceError(f"non-finite JSON constant: {value}")


def checked_int(value: str) -> int:
    result = int(value)
    if abs(result) > MAX_EXACT_INTEGER:
        raise EvidenceError("JSON integer exceeds Cosign exact IEEE-754 range")
    return result


def checked_float(value: str) -> float:
    result = float(value)
    if not math.isfinite(result):
        raise EvidenceError("non-finite JSON number")
    if abs(result) > MAX_EXACT_INTEGER:
        raise EvidenceError("JSON number exceeds Cosign exact IEEE-754 range")
    return result


def normalize_json_numbers(value):
    """Match Cosign structpb's finite JSON-number representation, not JCS."""
    if isinstance(value, bool) or value is None or isinstance(value, str):
        return value
    if isinstance(value, int):
        if abs(value) > MAX_EXACT_INTEGER: raise EvidenceError("JSON integer exceeds Cosign exact IEEE-754 range")
        return value
    if isinstance(value, float):
        if not math.isfinite(value) or abs(value) > MAX_EXACT_INTEGER: raise EvidenceError("unsafe JSON number")
        return int(value) if value.is_integer() else value
    if isinstance(value, list): return [normalize_json_numbers(item) for item in value]
    if isinstance(value, dict): return {key: normalize_json_numbers(item) for key, item in value.items()}
    raise EvidenceError("unsupported JSON value")


def canonical_json(value) -> bytes:
    """Type-preserving JSON comparison serialization; this is not JCS."""
    try:
        return json.dumps(normalize_json_numbers(value), sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                          allow_nan=False).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise EvidenceError("unsupported JSON value") from error


def raw(path: Path, maximum: int) -> bytes:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size < 0 or info.st_size > maximum:
            os.close(fd)
            raise EvidenceError(f"unsafe file: {path}")
        with os.fdopen(fd, "rb") as handle:
            result = handle.read(maximum + 1)
    except OSError as error:
        raise EvidenceError(f"cannot read {path}") from error
    if len(result) > maximum:
        raise EvidenceError(f"unsafe file: {path}")
    return result


def document(path: Path, maximum: int):
    try:
        return json.loads(raw(path, maximum), object_pairs_hook=unique, parse_constant=reject_nonfinite, parse_int=checked_int, parse_float=checked_float)
    except (UnicodeDecodeError, json.JSONDecodeError, EvidenceError) as error:
        raise EvidenceError(f"malformed JSON: {path}") from error


def manifest(path: Path, config: str) -> str:
    contents = raw(path, MAX_MANIFEST)
    try:
        value = json.loads(contents, object_pairs_hook=unique, parse_constant=reject_nonfinite, parse_int=checked_int, parse_float=checked_float)
    except (UnicodeDecodeError, json.JSONDecodeError, EvidenceError) as error:
        raise EvidenceError("malformed manifest JSON") from error
    # An OCI index must never be silently accepted in place of the single image
    # whose local config was inspected before push.
    if not isinstance(value, dict) or "manifests" in value or not isinstance(value.get("config"), dict):
        raise EvidenceError("published object is not a single image manifest")
    if value["config"].get("digest") != config:
        raise EvidenceError("published manifest config does not bind the local image")
    return "sha256:" + hashlib.sha256(contents).hexdigest()


def local(sbom_path: Path, receipt_path: Path, revision: str, config: str) -> None:
    if not REVISION.fullmatch(revision) or not DIGEST.fullmatch(config):
        raise EvidenceError("invalid source revision or local config digest")
    sbom = raw(sbom_path, MAX_SBOM)
    # Parse it here as well as hashing it: cosign predicates must be valid JSON,
    # and duplicate fields make equality ambiguous.
    try:
        sbom_document = json.loads(sbom, object_pairs_hook=unique, parse_constant=reject_nonfinite, parse_int=checked_int, parse_float=checked_float)
    except (UnicodeDecodeError, json.JSONDecodeError, EvidenceError) as error:
        raise EvidenceError("SBOM is malformed JSON") from error
    if not isinstance(sbom_document, dict) or sbom_document.get("bomFormat") != "CycloneDX":
        raise EvidenceError("SBOM is not CycloneDX")
    normalize_json_numbers(sbom_document)
    receipt = document(receipt_path, MAX_RECEIPT)
    if not isinstance(receipt, dict):
        raise EvidenceError("receipt is not an object")
    if receipt.get("source_revision") != revision or receipt.get("image_config_digest") != config:
        raise EvidenceError("receipt does not bind this revision and local config")
    if receipt.get("sbom_sha256") != hashlib.sha256(sbom).hexdigest():
        raise EvidenceError("receipt does not bind the supplied SBOM")


def records(path: Path):
    contents = raw(path, MAX_VERIFY)
    try:
        value = json.loads(contents, object_pairs_hook=unique, parse_constant=reject_nonfinite, parse_int=checked_int, parse_float=checked_float)
        return value if isinstance(value, list) else [value]
    except (UnicodeDecodeError, json.JSONDecodeError, EvidenceError):
        # Cosign may emit newline-delimited JSON records. Do not accept empty
        # lines or any non-JSON text as a successful verification result.
        try:
            return [json.loads(line, object_pairs_hook=unique, parse_constant=reject_nonfinite, parse_int=checked_int, parse_float=checked_float) for line in contents.decode("utf-8").splitlines() if line]
        except (UnicodeDecodeError, json.JSONDecodeError, EvidenceError) as error:
            raise EvidenceError(f"malformed cosign output: {path}") from error


def wanted_subject(value, image: str, digest: str) -> bool:
    return value == [{"name": image, "digest": {"sha256": digest.removeprefix("sha256:")}}]


def attestation(path: Path, image: str, digest: str, predicate, predicate_type: str) -> None:
    expected_type = "application/vnd.in-toto+json"
    matched = False
    for envelope in records(path):
        if not isinstance(envelope, dict) or envelope.get("payloadType") != expected_type or not isinstance(envelope.get("payload"), str):
            continue
        try:
            payload = base64.b64decode(envelope["payload"], validate=True)
            statement = json.loads(payload, object_pairs_hook=unique, parse_constant=reject_nonfinite, parse_int=checked_int, parse_float=checked_float)
        except (ValueError, UnicodeDecodeError, json.JSONDecodeError, EvidenceError) as error:
            raise EvidenceError("invalid verified DSSE payload") from error
        if not isinstance(statement, dict):
            raise EvidenceError("verified DSSE statement is not an object")
        # Cosign v3.1.2's generateCustomStatement and generateCycloneDXStatement
        # set in_toto.StatementInTotoV01 (pkg/cosign/attestation/attestation.go,
        # lines 224-247 and 426-448), so accept that pinned producer format only.
        if (wanted_subject(statement.get("subject"), image, digest)
                and statement.get("_type") == "https://in-toto.io/Statement/v0.1"
                and statement.get("predicateType") == predicate_type
                and canonical_json(statement.get("predicate")) == canonical_json(predicate)):
            matched = True
    if not matched:
        raise EvidenceError("verified DSSE predicate or subject does not exactly match local evidence")


def signature(path: Path, image: str, digest: str) -> None:
    # The signature output has a different schema from DSSE attestations.
    expected = digest
    for record in records(path):
        try:
            critical = record["critical"]
            if (critical.get("type") == "https://sigstore.dev/cosign/sign/v1"
                    and critical["identity"]["docker-reference"] == f"{image}@{digest}"
                    and critical["image"]["docker-manifest-digest"] == expected):
                return
        except (KeyError, TypeError):
            pass
    raise EvidenceError("verified signature does not bind the expected image digest")


def consumer(signature_path: Path, sbom_attestation: Path, receipt_attestation: Path, sbom_path: Path, receipt_path: Path, image: str, digest: str, revision: str) -> None:
    """Verify producer evidence without treating receipt booleans as proof."""
    if not DIGEST.fullmatch(digest) or not REVISION.fullmatch(revision):
        raise EvidenceError("invalid image digest or approved source revision")
    sbom = document(sbom_path, MAX_SBOM)
    receipt = document(receipt_path, MAX_RECEIPT)
    if not isinstance(sbom, dict) or sbom.get("bomFormat") != "CycloneDX" or not isinstance(receipt, dict):
        raise EvidenceError("local producer evidence has an invalid schema")
    raw_sbom = raw(sbom_path, MAX_SBOM)
    expected_claims = {"signature": False, "registry_manifest_digest": False, "sca": False}
    expected_subject = image.rsplit("/", 1)[-1]
    if (set(receipt) != {"schema_version", "stage", "subject", "source_revision", "docker_archive_sha256", "image_config_digest", "sbom_sha256", "claims"} or
            type(receipt.get("schema_version")) is not int or receipt.get("schema_version") != 1 or receipt.get("stage") != "build" or receipt.get("subject") != expected_subject or receipt.get("source_revision") != revision or
            not isinstance(receipt.get("docker_archive_sha256"), str) or not SHA.fullmatch(receipt["docker_archive_sha256"]) or
            not isinstance(receipt.get("image_config_digest"), str) or not DIGEST.fullmatch(receipt["image_config_digest"]) or
            receipt.get("sbom_sha256") != hashlib.sha256(raw_sbom).hexdigest() or not isinstance(receipt.get("claims"), dict) or
            set(receipt["claims"]) != set(expected_claims) or any(value is not False for value in receipt["claims"].values())):
        raise EvidenceError("receipt does not bind the source and local SBOM under the producer schema")
    signature(signature_path, image, digest)
    attestation(sbom_attestation, image, digest, sbom, "https://cyclonedx.org/bom")
    attestation(receipt_attestation, image, digest, receipt, "https://github.com/s1ns3nz0/node-operator/attestations/image-build-receipt/v1")


def copy_new(directory: Path, pairs: list[tuple[str, Path]], image: str) -> None:
    if directory.exists() or directory.is_symlink() or directory.parent.is_symlink():
        raise EvidenceError("evidence output directory must be new and non-symlinked")
    try:
        directory.mkdir(mode=0o700)
        for name, source in pairs:
            content = raw(source, MAX_SBOM if name == "sbom.cyclonedx.json" else MAX_VERIFY)
            fd = os.open(directory / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "wb") as destination:
                destination.write(content)
        fd = os.open(directory / "image-ref.txt", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as destination:
            destination.write(image + "\n")
    except OSError as error:
        raise EvidenceError("cannot create bounded evidence output") from error


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    item = commands.add_parser("manifest"); item.add_argument("path", type=Path); item.add_argument("config")
    item = commands.add_parser("local"); item.add_argument("sbom", type=Path); item.add_argument("receipt", type=Path); item.add_argument("revision"); item.add_argument("config")
    item = commands.add_parser("verify"); item.add_argument("signature_file", type=Path); item.add_argument("sbom_file", type=Path); item.add_argument("receipt_file", type=Path); item.add_argument("sbom", type=Path); item.add_argument("receipt", type=Path); item.add_argument("image"); item.add_argument("digest")
    item = commands.add_parser("consumer"); item.add_argument("signature_file", type=Path); item.add_argument("sbom_file", type=Path); item.add_argument("receipt_file", type=Path); item.add_argument("sbom", type=Path); item.add_argument("receipt", type=Path); item.add_argument("image"); item.add_argument("digest"); item.add_argument("revision")
    item = commands.add_parser("copy"); item.add_argument("directory", type=Path); item.add_argument("image"); item.add_argument("manifest", type=Path); item.add_argument("sbom", type=Path); item.add_argument("receipt", type=Path); item.add_argument("signature", type=Path); item.add_argument("sbom_verified", type=Path); item.add_argument("receipt_verified", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == "manifest": print(manifest(args.path, args.config))
        elif args.command == "local": local(args.sbom, args.receipt, args.revision, args.config)
        elif args.command == "verify":
            signature(args.signature_file, args.image, args.digest)
            attestation(args.sbom_file, args.image, args.digest, document(args.sbom, MAX_SBOM), "https://cyclonedx.org/bom")
            attestation(args.receipt_file, args.image, args.digest, document(args.receipt, MAX_RECEIPT), "https://github.com/s1ns3nz0/node-operator/attestations/image-build-receipt/v1")
        elif args.command == "consumer":
            consumer(args.signature_file, args.sbom_file, args.receipt_file, args.sbom, args.receipt, args.image, args.digest, args.revision)
        else:
            copy_new(args.directory, [("manifest.json", args.manifest), ("sbom.cyclonedx.json", args.sbom), ("receipt.json", args.receipt), ("signature-verified.json", args.signature), ("sbom-attestation-verified.json", args.sbom_verified), ("receipt-attestation-verified.json", args.receipt_verified)], args.image)
    except EvidenceError as error:
        print(f"CI image attestation rejected: {error}", file=sys.stderr)
        return 65
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
