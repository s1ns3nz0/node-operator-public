#!/usr/bin/env python3
"""Read one authorization-bound signer-probe record from GitHub Actions.

This command only performs authenticated read-only GitHub API requests.  Its
result is a newly-created private directory containing the exact record bytes.
The caller must still authenticate the authorization/bundle and independently
trust GitHub artifact retrieval; this does not verify Cosign, ECR, or activate
a validator.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import sys
import tempfile
from typing import Any
import zipfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts" / "release"))
import signer_probe_release_authorization as authorization

RECORD_NAME = "signer-identity-probe-publication-record.json"
MAX_MEMBER = 4 * 1024 * 1024


class FetchSignerProbeError(ValueError):
    """GitHub publication retrieval is malformed, unsafe, or untrusted."""


def fail(message: str) -> None:
    raise FetchSignerProbeError(message)


def generic() -> Any:
    path = ROOT / "scripts" / "ci" / "fetch-release-publication-records.py"
    spec = importlib.util.spec_from_file_location("release_publication_retrieval", path)
    if spec is None or spec.loader is None:
        fail("cannot load GitHub retrieval safety helpers")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _output_is_safe(output: Path) -> None:
    if (not output.is_absolute() or os.path.normpath(str(output)) != str(output)
            or output.exists() or output.is_symlink()):
        fail("output directory must be an absolute new path")
    ancestor = Path(output.anchor)
    for part in output.parts[1:-1]:
        ancestor /= part
        try:
            info = ancestor.lstat()
        except OSError as error:
            raise FetchSignerProbeError("output parent must be an existing regular directory") from error
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            fail("output parent ancestry must contain only regular directories")


def _authorization(path: Path) -> dict[str, Any]:
    if not path.is_absolute():
        fail("authorization path must be absolute")
    try:
        value, _ = authorization._read(path)
        return authorization.validate_authorization(value, "stage")
    except authorization.SignerProbeReleaseAuthorizationError as error:
        raise FetchSignerProbeError("authorization is unsafe or invalid") from error


def _artifact(value: Any, auth: dict[str, Any]) -> None:
    publication = auth["publication"]
    candidate = auth["candidate_revision"]
    expected_name = f"signer-probe-publication-record-{candidate}"
    if not isinstance(value, dict) or not isinstance(value.get("artifacts"), list):
        fail("artifact listing is invalid")
    found = [item for item in value["artifacts"]
             if isinstance(item, dict) and item.get("name") == expected_name]
    if len(found) != 1:
        fail("signer-probe artifact is missing or ambiguous")
    item = found[0]
    workflow_run = item.get("workflow_run")
    if (type(item.get("id")) is not int or str(item["id"]) != publication["artifact_id"]
            or item.get("expired") is not False or not isinstance(workflow_run, dict)
            or type(workflow_run.get("id")) is not int
            or str(workflow_run["id"]) != publication["run_id"]
            or workflow_run.get("head_sha") != candidate):
        fail("signer-probe artifact is not bound to authorization")


def _extract_record(archive_path: Path, stage: Path, archive_limit: int) -> tuple[dict[str, Any], bytes]:
    try:
        with zipfile.ZipFile(archive_path) as archive:
            infos = archive.infolist()
            if len(infos) != 1 or len({info.filename for info in infos}) != 1:
                fail("signer-probe artifact ZIP must contain exactly one file")
            info = infos[0]
            member = PurePosixPath(info.filename)
            file_type = (info.external_attr >> 16) & 0o170000
            if (info.filename != RECORD_NAME or info.is_dir() or member.is_absolute()
                    or ".." in member.parts or len(member.parts) != 1
                    or file_type not in {0, stat.S_IFREG} or info.file_size > MAX_MEMBER
                    or info.compress_size > archive_limit):
                fail("signer-probe artifact ZIP contains an unsafe record")
            raw = archive.read(info)
    except (OSError, RuntimeError, zipfile.BadZipFile) as error:
        raise FetchSignerProbeError("signer-probe artifact ZIP is invalid") from error
    if len(raw) > MAX_MEMBER:
        fail("signer-probe publication record exceeds limit")
    destination = stage / RECORD_NAME
    try:
        with destination.open("xb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(destination, 0o600)
        value, loaded = authorization._read(destination)
    except (OSError, authorization.SignerProbeReleaseAuthorizationError) as error:
        raise FetchSignerProbeError("signer-probe publication record is invalid") from error
    if not isinstance(value, dict) or loaded != raw:
        fail("signer-probe publication record is invalid")
    return value, raw


def retrieve(authorization_path: Path, source_root: Path, output: Path) -> None:
    """Fetch, locally bind, and atomically publish one signer-probe record."""
    auth = _authorization(authorization_path)  # Reject unauthorised endpoints before gh.
    _output_is_safe(output)
    if not source_root.is_absolute():
        fail("source root must be absolute")
    publication = auth["publication"]
    candidate = auth["candidate_revision"]
    stage = Path(tempfile.mkdtemp(prefix=".signer-probe-publication-record-", dir=output.parent))
    os.chmod(stage, 0o700)
    helper = generic()
    try:
        try:
            run = helper.gh_json(
                f"repos/{publication['repository']}/actions/runs/{publication['run_id']}", stage)
            helper.run_is_trusted(run, publication["repository"], candidate, publication["run_id"])
            artifacts = helper.list_artifacts(publication["repository"], publication["run_id"], stage)
            _artifact(artifacts, auth)
        except (helper.FetchError, OSError) as error:
            raise FetchSignerProbeError("publication run is not trusted") from error
        archive = stage / "record.zip"
        try:
            helper.gh_zip(
                f"repos/{publication['repository']}/actions/artifacts/{publication['artifact_id']}/zip", archive)
            record, raw = _extract_record(archive, stage, helper.MAX_ARCHIVE)
        except (helper.FetchError, OSError) as error:
            raise FetchSignerProbeError("signer-probe artifact download is unsafe or invalid") from error
        if hashlib.sha256(raw).hexdigest() != auth["record_sha256"]:
            fail("signer-probe record hash differs from authorization")
        try:
            authorization.validate_candidate_authorization(auth, record, raw, source_root, "stage")
        except authorization.SignerProbeReleaseAuthorizationError as error:
            raise FetchSignerProbeError("signer-probe record is not authorization-bound") from error
        archive.unlink(missing_ok=True)
        try:
            helper.publish(stage, output)
        except (helper.FetchError, OSError) as error:
            raise FetchSignerProbeError("cannot atomically publish signer-probe record") from error
    finally:
        shutil.rmtree(stage, ignore_errors=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--authorization-path", required=True, type=Path)
    parser.add_argument("--source-root", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    arguments = parser.parse_args()
    try:
        retrieve(arguments.authorization_path, arguments.source_root, arguments.output_dir)
    except FetchSignerProbeError as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
