#!/usr/bin/env python3
"""Retrieve one authorization-bound Fence record from a trusted GitHub run.

This command reads GitHub Actions metadata and an artifact only.  It does not
verify Cosign, query ECR, activate a validator, or grant an approval.  The
authorization selects the only accepted candidate run and artifact; callers
still need to authenticate the authorization/bundle that supplied it.
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
import fence_release_authorization as fence

ARTIFACT_NAME = "validator-signing-fence-release-verification"
RECORD_NAME = "fence-release-verification.json"
MAX_ARCHIVE = 16 * 1024 * 1024
MAX_MEMBER = 4 * 1024 * 1024


class FetchFenceError(ValueError):
    pass


def fail(message: str) -> None:
    raise FetchFenceError(message)


def generic() -> Any:
    path = ROOT / "scripts" / "ci" / "fetch-release-publication-records.py"
    spec = importlib.util.spec_from_file_location("release_publication_retrieval", path)
    if spec is None or spec.loader is None:
        fail("cannot load GitHub retrieval safety helpers")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _output_is_safe(output: Path) -> None:
    if not output.is_absolute() or os.path.normpath(str(output)) != str(output) or output.exists() or output.is_symlink():
        fail("output directory must be an absolute new path")
    ancestor = Path(output.anchor)
    for part in output.parts[1:-1]:
        ancestor /= part
        try:
            info = ancestor.lstat()
        except OSError as error:
            raise FetchFenceError("output parent must be an existing regular directory") from error
        if ancestor.is_symlink() or not stat.S_ISDIR(info.st_mode):
            fail("output parent ancestry must contain only regular directories")


def _authorization(path: Path) -> dict[str, Any]:
    if not path.is_absolute():
        fail("authorization path must be absolute")
    try:
        value, _ = fence._read(path)
    except fence.FenceReleaseAuthorizationError as error:
        raise FetchFenceError("authorization is unsafe or invalid") from error
    expected = {"schema_version", "candidate_revision", "record_sha256", "publication", "target", "approvals"}
    if not isinstance(value, dict) or set(value) != expected or type(value.get("schema_version")) is not int or value["schema_version"] != 1:
        fail("authorization is invalid")
    publication = value.get("publication")
    target = value.get("target")
    approvals = value.get("approvals")
    if (not isinstance(publication, dict) or set(publication) != {"repository", "workflow", "run_id", "artifact_id"} or
            publication.get("repository") != "s1ns3nz0/node-operator" or publication.get("workflow") != "image-publish.yml" or
            not isinstance(value.get("candidate_revision"), str) or not isinstance(value.get("record_sha256"), str) or
            not isinstance(publication.get("run_id"), str) or not isinstance(publication.get("artifact_id"), str) or
            not isinstance(target, dict) or set(target) != {"image_ref", "manifest_digest", "input_sha256"} or
            not isinstance(approvals, dict) or set(approvals) != {"stage_approved", "activation_approved"} or
            any(type(item) is not bool for item in approvals.values()) or approvals["stage_approved"] is not True):
        fail("authorization is invalid")
    candidate = value["candidate_revision"]
    run_id = publication["run_id"]
    artifact_id = publication["artifact_id"]
    repository = publication["repository"]
    helper = generic()
    if (not helper.SHA40.fullmatch(candidate) or not helper.RUN_ID.fullmatch(run_id) or
            not helper.RUN_ID.fullmatch(artifact_id) or not fence.SHA256.fullmatch(value["record_sha256"])):
        fail("authorization endpoint identity is invalid")
    return value


def _artifact(value: Any, run_id: str, candidate: str, artifact_id: str) -> None:
    if not isinstance(value, dict) or not isinstance(value.get("artifacts"), list):
        fail("artifact listing is invalid")
    found = [item for item in value["artifacts"] if isinstance(item, dict) and item.get("name") == ARTIFACT_NAME]
    if len(found) != 1:
        fail("Fence artifact is missing or ambiguous")
    item = found[0]
    workflow_run = item.get("workflow_run")
    if (type(item.get("id")) is not int or str(item["id"]) != artifact_id or
            item.get("expired") is not False or not isinstance(workflow_run, dict) or
            type(workflow_run.get("id")) is not int or str(workflow_run["id"]) != run_id or
            workflow_run.get("head_sha") != candidate):
        fail("Fence artifact is not bound to authorization")


def _safe_record(archive_path: Path, stage: Path) -> tuple[dict[str, Any], bytes]:
    try:
        with zipfile.ZipFile(archive_path) as archive:
            infos = archive.infolist()
            if len(infos) != 1 or len({info.filename for info in infos}) != 1:
                fail("Fence artifact ZIP must contain exactly one file")
            info = infos[0]
            path = PurePosixPath(info.filename)
            file_type = (info.external_attr >> 16) & 0o170000
            if (info.filename != RECORD_NAME or info.is_dir() or path.is_absolute() or ".." in path.parts or
                    len(path.parts) != 1 or file_type not in {0, stat.S_IFREG} or info.file_size > MAX_MEMBER or
                    info.compress_size > MAX_ARCHIVE):
                fail("Fence artifact ZIP contains an unsafe record")
            raw = archive.read(info)
    except (OSError, RuntimeError, zipfile.BadZipFile) as error:
        raise FetchFenceError("Fence artifact ZIP is invalid") from error
    if len(raw) > MAX_MEMBER:
        fail("Fence publication record exceeds limit")
    destination = stage / RECORD_NAME
    try:
        with destination.open("xb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(destination, 0o600)
        value, loaded = fence._read(destination)
    except (OSError, fence.FenceReleaseAuthorizationError) as error:
        raise FetchFenceError("Fence publication record is invalid") from error
    if not isinstance(value, dict) or loaded != raw:
        fail("Fence publication record is invalid")
    return value, raw


def retrieve(authorization_path: Path, source_root: Path, output: Path) -> None:
    auth = _authorization(authorization_path)
    publication = auth["publication"]
    candidate = auth["candidate_revision"]
    repository = publication["repository"]
    run_id = publication["run_id"]
    artifact_id = publication["artifact_id"]
    _output_is_safe(output)
    if not source_root.is_absolute():
        fail("source root must be absolute")
    stage = Path(tempfile.mkdtemp(prefix=".fence-publication-record-", dir=output.parent))
    os.chmod(stage, 0o700)
    helper = generic()
    try:
        try:
            run = helper.gh_json(f"repos/{repository}/actions/runs/{run_id}", stage)
            helper.run_is_trusted(run, repository, candidate, run_id)
            artifacts = helper.list_artifacts(repository, run_id, stage)
            _artifact(artifacts, run_id, candidate, artifact_id)
        except (helper.FetchError, OSError) as error:
            raise FetchFenceError("publication run is not trusted") from error
        archive = stage / "record.zip"
        try:
            helper.gh_zip(f"repos/{repository}/actions/artifacts/{artifact_id}/zip", archive)
            record, raw = _safe_record(archive, stage)
        except (helper.FetchError, OSError) as error:
            raise FetchFenceError("Fence artifact download is unsafe or invalid") from error
        if hashlib.sha256(raw).hexdigest() != auth.get("record_sha256"):
            fail("Fence record hash differs from authorization")
        try:
            fence.validate_candidate_authorization(auth, record, raw, source_root, "stage")
        except fence.FenceReleaseAuthorizationError as error:
            raise FetchFenceError("Fence record is not authorization-bound") from error
        archive.unlink(missing_ok=True)
        try:
            helper.publish(stage, output)
        except (helper.FetchError, OSError) as error:
            raise FetchFenceError("cannot atomically publish Fence record") from error
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
    except FetchFenceError as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
