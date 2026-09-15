"""Create and validate the third-party Prysm mTLS publication record offline.

Validation binds recorded claims to local source and selected deployment context;
it does not perform a registry, scan, Cosign, or provenance verification.  The
producer must complete those checks before it records the passed claims.
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import stat
import tempfile
from typing import Any
import argparse

SHA40 = re.compile(r"^[a-f0-9]{40}$")
SHA256 = re.compile(r"^[a-f0-9]{64}$")
DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
ACCOUNT = re.compile(r"^[0-9]{12}$")
REGION = re.compile(r"^ap-northeast-[12]$")
NAME = re.compile(r"^[a-z][a-z0-9-]{1,18}[a-z0-9]$")
REPOSITORY = re.compile(r"^[a-z0-9]+(?:[._/-][a-z0-9]+)*$")
IMAGE = re.compile(r"^[0-9]{12}\.dkr\.ecr\.ap-northeast-[12]\.amazonaws\.com/[a-z0-9]+(?:[._/-][a-z0-9]+)*@sha256:[a-f0-9]{64}$")
MAX_JSON = 1024 * 1024
MAX_BUILD_INPUT = 4 * 1024 * 1024
PATCHES = {
    "patch_sha256": ".ci/prysm-mtls/patches/0001-web3signer-http-mtls.patch",
    "security_patch_sha256": ".ci/prysm-mtls/patches/0002-security-dependencies.patch",
}
BUILD_INPUTS = (
    ".ci/prysm-mtls/source.lock.json",
    ".ci/prysm-mtls/Dockerfile",
    ".ci/prysm-mtls/Dockerfile.dockerignore",
    PATCHES["patch_sha256"],
    PATCHES["security_patch_sha256"],
    ".ci/prysm-mtls-applicability.json",
    ".ci/prysm-mtls-applicability/GO-2026-5932.json",
)
LOCK_KEYS = {"schema_version", "repository", "tag", "commit", "go_version", "target", "release_platform", "patch_directory", "patch_sha256", "security_patch_sha256", "builder_image", "runtime_image", "status"}
RECORD_KEYS = {"schema_version", "component", "release_revision", "build_revision", "input_sha256", "source", "target", "publication", "verification"}
V2_RECORD_KEYS = RECORD_KEYS | {"applicability"}


class PrysmPublicationRecordError(ValueError):
    """A local Prysm publication record or source identity is unsafe."""


def _duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise PrysmPublicationRecordError("duplicate JSON object key")
        result[key] = value
    return result


def _json(path: Path) -> Any:
    try:
        info = path.lstat()
        if path.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_size > MAX_JSON:
            raise PrysmPublicationRecordError("JSON input is unsafe")
        return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_duplicates)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, PrysmPublicationRecordError) as error:
        if isinstance(error, PrysmPublicationRecordError):
            raise
        raise PrysmPublicationRecordError("JSON input is invalid") from error


def _exact(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise PrysmPublicationRecordError(f"{label} has an unexpected schema")
    return value


def _text(value: Any, label: str, pattern: re.Pattern[str] | None = None) -> str:
    if not isinstance(value, str) or not value or (pattern and not pattern.fullmatch(value)):
        raise PrysmPublicationRecordError(f"{label} is invalid")
    return value


def _sha256(path: Path) -> str:
    try:
        info = path.lstat()
        if path.is_symlink() or not stat.S_ISREG(info.st_mode):
            raise PrysmPublicationRecordError("Prysm patch is unsafe")
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as error:
        raise PrysmPublicationRecordError("Prysm patch cannot be read") from error
    return digest

def _source_path(source_root: Path, relative: str) -> Path:
    """Resolve a reviewed relative input without crossing symlinked ancestry."""
    current = source_root
    for part in Path(relative).parts:
        current /= part
        try:
            info = current.lstat()
        except OSError as error:
            raise PrysmPublicationRecordError("Prysm source input cannot be inspected") from error
        if current.is_symlink() or (part != Path(relative).parts[-1] and not stat.S_ISDIR(info.st_mode)):
            raise PrysmPublicationRecordError("Prysm source input ancestry is unsafe")
    return current


def build_input_sha256(source_root: Path) -> str:
    """Hash the exact reviewed Prysm build inputs with unambiguous path binding."""
    if not source_root.is_absolute() or source_root.is_symlink() or not source_root.is_dir():
        raise PrysmPublicationRecordError("source root is unsafe")
    digest = hashlib.sha256()
    for relative in BUILD_INPUTS:
        path = _source_path(source_root, relative)
        try:
            info = path.lstat()
            if path.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_size > MAX_BUILD_INPUT:
                raise PrysmPublicationRecordError("Prysm build input is unsafe")
            contents = path.read_bytes()
        except OSError as error:
            raise PrysmPublicationRecordError("Prysm build input cannot be read") from error
        # Frame arbitrary file contents with their fixed-size digest.  Raw bytes
        # plus delimiters are ambiguous when a build input itself contains the
        # delimiter sequence.
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(hashlib.sha256(contents).digest())
    return digest.hexdigest()


def source_identity(source_root: Path) -> dict[str, str]:
    """Read the locked third-party source and bind it to actual reviewed patches."""
    if not source_root.is_absolute() or source_root.is_symlink() or not source_root.is_dir():
        raise PrysmPublicationRecordError("source root is unsafe")
    lock = _exact(_json(_source_path(source_root, ".ci/prysm-mtls/source.lock.json")), LOCK_KEYS, "Prysm source lock")
    if type(lock["schema_version"]) is not int or lock["schema_version"] != 1 or lock["repository"] != "https://github.com/OffchainLabs/prysm.git" or lock["release_platform"] != "linux/amd64" or lock["patch_directory"] != ".ci/prysm-mtls/patches":
        raise PrysmPublicationRecordError("Prysm source lock identity is invalid")
    result = {"repository": _text(lock["repository"], "source repository"), "tag": _text(lock["tag"], "source tag"), "commit": _text(lock["commit"], "source commit", SHA40), "platform": "linux/amd64"}
    for key, relative in PATCHES.items():
        expected = _text(lock[key], key, SHA256)
        actual = _sha256(_source_path(source_root, relative))
        if actual != expected:
            raise PrysmPublicationRecordError(f"{key} does not match the reviewed patch")
        result[key] = actual
    return result


def _context(account: Any, region: Any, deployment: Any, repository: Any, image_ref: Any, digest: Any) -> dict[str, str]:
    account = _text(account, "AWS account ID", ACCOUNT)
    region = _text(region, "AWS region", REGION)
    deployment = _text(deployment, "deployment name", NAME)
    repository = _text(repository, "target repository", REPOSITORY)
    if repository != f"{deployment}-baseline-validator-prysm":
        raise PrysmPublicationRecordError("target repository does not match selected deployment")
    digest = _text(digest, "manifest digest", DIGEST)
    image_ref = _text(image_ref, "target image reference", IMAGE)
    expected = f"{account}.dkr.ecr.{region}.amazonaws.com/{repository}@{digest}"
    if image_ref != expected:
        raise PrysmPublicationRecordError("target image reference does not bind selected context and digest")
    return {"aws_account_id": account, "aws_region": region, "deployment_name": deployment,
            "repository": repository, "image_ref": image_ref, "manifest_digest": digest,
            "platform": "linux/amd64"}


def create_record(source_root: Path, *, release_revision: str, build_revision: str,
                  input_sha256: str, aws_account_id: str, aws_region: str,
                  deployment_name: str, repository: str, image_ref: str,
                  manifest_digest: str, run_id: str | int,
                  invocation: str = "prysm-mtls-publish", applicability_assessment: Path | None = None) -> dict[str, Any]:
    """Create a validated in-memory record; this does not publish or write it."""
    record = {
        "schema_version": 1, "component": "prysm-mtls",
        "release_revision": _text(release_revision, "release revision", SHA40),
        "build_revision": _text(build_revision, "build revision", SHA40),
        "input_sha256": _text(input_sha256, "input hash", SHA256),
        "source": source_identity(source_root),
        "target": _context(aws_account_id, aws_region, deployment_name, repository, image_ref, manifest_digest),
        "publication": {"workflow": "image-publish.yml", "run_id": run_id, "invocation": invocation},
        "verification": {"method": "scan-cosign-and-provenance", "status": "passed",
                         "scan_passed": True, "cosign_verified": True, "provenance_verified": True},
    }
    if applicability_assessment is not None:
        assessment = _json(applicability_assessment)
        keys = {"schema_version", "component", "status", "raw_scan_status", "applicability", "advisory_id", "subject", "sbom_sha256", "raw_grype_sha256", "raw_scan_summary", "advisory_sha256", "reviewed_at", "expires_at", "validator_sha256", "dependency_closure_sha256", "dependency_closure_count", "deployment_authorized"}
        if not isinstance(assessment, dict) or set(assessment) != keys or assessment.get("schema_version") != "v2" or assessment.get("component") != "prysm-mtls" or assessment.get("status") != "passed-with-non-applicability" or assessment.get("raw_scan_status") != "blocked" or assessment.get("applicability") != "not_affected" or assessment.get("deployment_authorized") is not False:
            raise PrysmPublicationRecordError("Prysm applicability assessment is invalid")
        if assessment.get("subject") != image_ref or any(not isinstance(assessment.get(k), str) or not SHA256.fullmatch(assessment[k]) for k in ("sbom_sha256", "raw_grype_sha256", "advisory_sha256", "validator_sha256", "dependency_closure_sha256")):
            raise PrysmPublicationRecordError("Prysm applicability assessment does not bind image evidence")
        record["schema_version"] = 2
        record["applicability"] = {"assessment_sha256": _sha256(applicability_assessment), "raw_grype_sha256": assessment["raw_grype_sha256"], "sbom_sha256": assessment["sbom_sha256"], "raw_scan_status": "blocked", "decision": "not_affected", "advisory_id": assessment["advisory_id"], "advisory_sha256": assessment["advisory_sha256"], "subject": assessment["subject"], "expires_at": assessment["expires_at"]}
        record["verification"] = {"method": "scan-applicability-cosign-and-provenance", "status": "passed-with-non-applicability", "scan_passed": False, "cosign_verified": True, "provenance_verified": True}
    return validate_record(record, source_root)


def validate_record(record: Any, source_root: Path, *, expected_release_revision: str | None = None,
                    expected_context: dict[str, str] | None = None) -> dict[str, Any]:
    """Validate all record fields against local source identity and caller context."""
    if not isinstance(record, dict) or type(record.get("schema_version")) is not int or record["schema_version"] not in (1,2) or set(record) != (V2_RECORD_KEYS if record["schema_version"] == 2 else RECORD_KEYS) or record["component"] != "prysm-mtls":
        raise PrysmPublicationRecordError("Prysm publication record identity is invalid")
    release = _text(record["release_revision"], "release revision", SHA40)
    build = _text(record["build_revision"], "build revision", SHA40)
    if build != release:
        raise PrysmPublicationRecordError("Prysm build revision differs from the selected release")
    input_sha = _text(record["input_sha256"], "input hash", SHA256)
    if input_sha != build_input_sha256(source_root):
        raise PrysmPublicationRecordError("Prysm input hash does not bind the reviewed build inputs")
    if expected_release_revision is not None and release != _text(expected_release_revision, "expected release revision", SHA40):
        raise PrysmPublicationRecordError("Prysm release revision differs from selected release")
    source = _exact(record["source"], {"repository", "tag", "commit", "patch_sha256", "security_patch_sha256", "platform"}, "Prysm source")
    if source != source_identity(source_root):
        raise PrysmPublicationRecordError("Prysm source does not bind the locked reviewed patches")
    target = _exact(record["target"], {"aws_account_id", "aws_region", "deployment_name", "repository", "image_ref", "manifest_digest", "platform"}, "Prysm target")
    if target["platform"] != "linux/amd64":
        raise PrysmPublicationRecordError("Prysm target platform is invalid")
    target = _context(target["aws_account_id"], target["aws_region"], target["deployment_name"],
                      target["repository"], target["image_ref"], target["manifest_digest"])
    if expected_context is not None:
        if not isinstance(expected_context, dict) or any(target.get(key) != expected_context.get(key) for key in ("aws_account_id", "aws_region", "deployment_name", "repository", "image_ref", "manifest_digest", "platform")):
            raise PrysmPublicationRecordError("Prysm target differs from selected deployment context")
    publication = _exact(record["publication"], {"workflow", "run_id", "invocation"}, "Prysm publication")
    run_id = publication["run_id"]
    if (publication["workflow"] != "image-publish.yml" or publication["invocation"] != "prysm-mtls-publish"
            or not isinstance(run_id, (str, int)) or isinstance(run_id, bool)
            or not re.fullmatch(r"[1-9][0-9]*", str(run_id))):
        raise PrysmPublicationRecordError("Prysm publication is invalid")
    verification = _exact(record["verification"], {"method", "status", "scan_passed", "cosign_verified", "provenance_verified"}, "Prysm verification")
    v2 = record["schema_version"] == 2
    if ((not v2 and (verification.get("method") != "scan-cosign-and-provenance" or verification.get("status") != "passed" or verification.get("scan_passed") is not True))
            or (v2 and (verification.get("method") != "scan-applicability-cosign-and-provenance" or verification.get("status") != "passed-with-non-applicability" or verification.get("scan_passed") is not False))
            or any(type(verification[key]) is not bool or verification[key] is not True for key in ("cosign_verified", "provenance_verified"))):
        raise PrysmPublicationRecordError("Prysm verification is not a passed scan, cosign, and provenance result")
    if v2:
        app = _exact(record["applicability"], {"assessment_sha256", "raw_grype_sha256", "sbom_sha256", "raw_scan_status", "decision", "advisory_id", "advisory_sha256", "subject", "expires_at"}, "Prysm applicability")
        manifest = _json(_source_path(source_root, ".ci/prysm-mtls-applicability.json"))
        advisory = _source_path(source_root, ".ci/prysm-mtls-applicability/GO-2026-5932.json")
        try: expiry = datetime.fromisoformat(app["expires_at"].replace("Z", "+00:00"))
        except (TypeError, ValueError): raise PrysmPublicationRecordError("Prysm applicability expiry is invalid")
        if any(not isinstance(app[k], str) or not SHA256.fullmatch(app[k]) for k in ("assessment_sha256", "raw_grype_sha256", "sbom_sha256", "advisory_sha256")) or app["raw_scan_status"] != "blocked" or app["decision"] != "not_affected" or app["advisory_id"] != "GO-2026-5932" or app["advisory_sha256"] != _sha256(advisory) or app["subject"] != target["image_ref"] or manifest.get("expires_at") != app["expires_at"] or expiry <= datetime.now(timezone.utc):
            raise PrysmPublicationRecordError("Prysm applicability binding is invalid")
    return record


def load_and_validate(path: Path, source_root: Path, **kwargs: Any) -> dict[str, Any]:
    """Safely load a bounded non-symlink record and validate it."""
    return validate_record(_json(path), source_root, **kwargs)


def write_record(path: Path, record: dict[str, Any], source_root: Path) -> None:
    """Atomically write one validated non-sensitive record without overwriting."""
    validate_record(record, source_root)
    if not path.is_absolute() or path.name != "prysm-mtls-publication-record.json":
        raise PrysmPublicationRecordError("record output path is invalid")
    try:
        parent = path.parent.lstat()
    except OSError as error:
        raise PrysmPublicationRecordError("record output parent is unavailable") from error
    if path.parent.is_symlink() or not stat.S_ISDIR(parent.st_mode) or stat.S_IMODE(parent.st_mode) != 0o700 or path.exists() or path.is_symlink():
        raise PrysmPublicationRecordError("record output path is unsafe or already exists")
    encoded = (json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    fd, temporary = tempfile.mkstemp(prefix=".prysm-mtls-publication-record-", dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(encoded); handle.flush(); os.fsync(handle.fileno())
        os.link(temporary, path)
    except OSError as error:
        raise PrysmPublicationRecordError("could not atomically publish Prysm record") from error
    finally:
        try: os.unlink(temporary)
        except FileNotFoundError: pass


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", required=True, type=Path)
    parser.add_argument("--release-revision", required=True)
    parser.add_argument("--build-revision", required=True)
    parser.add_argument("--input-sha256", required=True)
    parser.add_argument("--aws-account-id", required=True)
    parser.add_argument("--aws-region", required=True)
    parser.add_argument("--deployment-name", required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--image-ref", required=True)
    parser.add_argument("--manifest-digest", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--invocation", default="prysm-mtls-publish")
    parser.add_argument("--applicability-assessment", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        value = create_record(args.source_root, release_revision=args.release_revision,
                              build_revision=args.build_revision, input_sha256=args.input_sha256,
                              aws_account_id=args.aws_account_id, aws_region=args.aws_region,
                              deployment_name=args.deployment_name, repository=args.repository,
                              image_ref=args.image_ref, manifest_digest=args.manifest_digest,
                              run_id=args.run_id, invocation=args.invocation, applicability_assessment=args.applicability_assessment)
        write_record(args.output, value, args.source_root)
    except PrysmPublicationRecordError as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
