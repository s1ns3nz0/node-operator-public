#!/usr/bin/env python3
"""Fetch exactly the three verified image-publication records for one run.

This tool is deliberately read-only with respect to GitHub.  Its only durable
output is a new private directory of the three validated record bytes.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import selectors
import tempfile
import time
from typing import Any
import zipfile

SHA40 = re.compile(r"^[0-9a-f]{40}$")
RUN_ID = re.compile(r"^[1-9][0-9]*$")
REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
MAX_ARCHIVE = 16 * 1024 * 1024
MAX_MEMBER = 4 * 1024 * 1024
MAX_JSON = 4 * 1024 * 1024
COMMAND_TIMEOUT = 20

SPECS = (
    ("vault-bootstrap", "toolchain-publish", "input-hash-and-registry-digest"),
    ("gitops-oci-mirror", "toolchain-publish", "input-hash-and-registry-digest"),
    ("vault-audit-relay", "relay-publish", "cosign-and-slsa"),
)


class FetchError(ValueError):
    pass


def fail(message: str) -> None:
    raise FetchError(message)


def gh_stream(endpoint: str, destination: Path, limit: int) -> None:
    with destination.open("xb") as handle:
        process = subprocess.Popen(["gh", "api", "--hostname", "github.com", endpoint], stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        assert process.stdout is not None
        selector = selectors.DefaultSelector(); selector.register(process.stdout, selectors.EVENT_READ)
        total, deadline = 0, time.monotonic() + COMMAND_TIMEOUT
        try:
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    fail("GitHub API read timed out")
                events = selector.select(remaining)
                if not events:
                    fail("GitHub API read timed out")
                chunk = os.read(process.stdout.fileno(), 65536)
                if not chunk:
                    break
                total += len(chunk)
                if total > limit:
                    fail("GitHub API response exceeded limit")
                handle.write(chunk)
            if process.wait(timeout=max(0.1, deadline - time.monotonic())) != 0:
                fail("GitHub API read failed")
        except (OSError, subprocess.TimeoutExpired):
            fail("GitHub API read failed or timed out")
        finally:
            selector.close()
            if process.poll() is None:
                process.kill(); process.wait()


def gh_json(endpoint: str, stage: Path) -> Any:
    response = stage / f"response-{len(list(stage.glob('response-*')))}.json"
    gh_stream(endpoint, response, MAX_JSON)
    try:
        return json.loads(response.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise FetchError("GitHub API returned invalid JSON") from error
    finally:
        response.unlink(missing_ok=True)


def gh_zip(endpoint: str, destination: Path) -> None:
    gh_stream(endpoint, destination, MAX_ARCHIVE)


def exact_object(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        fail(f"{label} has an unexpected schema")
    return value


def run_is_trusted(value: Any, repository: str, source_sha: str, run_id: str) -> None:
    if not isinstance(value, dict):
        fail("workflow run is invalid")
    if not isinstance(value.get("id"), int) or isinstance(value["id"], bool) or str(value["id"]) != run_id:
        fail("workflow run identity differs")
    source_repository, head_repository = value.get("repository"), value.get("head_repository")
    if not isinstance(source_repository, dict) or not isinstance(head_repository, dict) or source_repository.get("full_name") != repository or head_repository.get("full_name") != repository:
        fail("workflow run repository is not the requested source repository")
    if value.get("head_sha") != source_sha or value.get("head_branch") != "main":
        fail("workflow run is not the requested main source revision")
    if value.get("event") not in {"push", "workflow_dispatch"} or value.get("status") != "completed" or value.get("conclusion") != "success":
        fail("workflow run is not a successful trusted publication event")
    path = value.get("path")
    if path not in {".github/workflows/image-publish.yml", ".github/workflows/image-publish.yml@refs/heads/main", f".github/workflows/image-publish.yml@{source_sha}"}:
        fail("workflow run does not use image-publish.yml")


def select_artifacts(value: Any, run_id: str, source_sha: str) -> dict[str, int]:
    if not isinstance(value, dict) or not isinstance(value.get("artifacts"), list):
        fail("artifact listing is invalid")
    names = {
        "vault-bootstrap": f"toolchain-publication-record-vault-bootstrap-{source_sha}",
        "gitops-oci-mirror": f"toolchain-publication-record-gitops-oci-mirror-{source_sha}",
        "vault-audit-relay": "vault-audit-relay-release-evidence",
    }
    chosen: dict[str, int] = {}
    for component, name in names.items():
        found = [item for item in value["artifacts"] if isinstance(item, dict) and item.get("name") == name]
        if len(found) != 1:
            fail(f"required artifact is missing or ambiguous: {component}")
        item = found[0]
        artifact_id = item.get("id")
        workflow_run = item.get("workflow_run")
        if (item.get("expired") is not False or not isinstance(workflow_run, dict) or
                not isinstance(workflow_run.get("id"), int) or isinstance(workflow_run["id"], bool) or
                str(workflow_run["id"]) != run_id or workflow_run.get("head_sha") != source_sha or
                not isinstance(artifact_id, int) or isinstance(artifact_id, bool) or artifact_id < 1):
            fail(f"artifact metadata is not bound to selected run: {component}")
        chosen[component] = artifact_id
    return chosen


def list_artifacts(repository: str, run_id: str, stage: Path) -> dict[str, Any]:
    all_artifacts: list[Any] = []
    total: int | None = None
    for page in range(1, 101):
        value = gh_json(f"repos/{repository}/actions/runs/{run_id}/artifacts?per_page=100&page={page}", stage)
        if not isinstance(value, dict) or not isinstance(value.get("artifacts"), list) or not isinstance(value.get("total_count"), int) or value["total_count"] < 0:
            fail("artifact listing is invalid")
        if total is None:
            total = value["total_count"]
        elif total != value["total_count"]:
            fail("artifact listing changed while being read")
        all_artifacts.extend(value["artifacts"])
        if len(all_artifacts) >= total:
            if len(all_artifacts) != total:
                fail("artifact listing pagination is inconsistent")
            return {"artifacts": all_artifacts}
        if not value["artifacts"]:
            fail("artifact listing ended before declared total")
    fail("artifact listing exceeds pagination limit")


def safe_member(info: zipfile.ZipInfo) -> bool:
    path = PurePosixPath(info.filename)
    return (not info.is_dir() and not path.is_absolute() and ".." not in path.parts and
            len(path.parts) == 1 and not info.filename.endswith("/") and
            ((info.external_attr >> 16) & 0o170000) in {0, stat.S_IFREG})


def extract_record(archive_path: Path, component: str, stage: Path) -> Path:
    expected = f"{component}-publication-record.json"
    try:
        with zipfile.ZipFile(archive_path) as archive:
            infos = archive.infolist()
            if (len(infos) > 128 or len({info.filename for info in infos}) != len(infos) or sum(info.file_size for info in infos) > MAX_ARCHIVE or
                    any(not safe_member(info) or info.file_size > MAX_MEMBER for info in infos)):
                fail("artifact ZIP contains unsafe or oversized member")
            matches = [info for info in infos if info.filename == expected]
            if len(matches) != 1:
                fail(f"artifact does not contain exactly one expected record: {component}")
            if component != "vault-audit-relay" and len(infos) != 1:
                fail(f"toolchain artifact has unexpected additional files: {component}")
            data = archive.read(matches[0])
    except (OSError, zipfile.BadZipFile, RuntimeError) as error:
        raise FetchError("artifact ZIP is invalid") from error
    if len(data) > MAX_MEMBER:
        fail("publication record exceeds limit")
    destination = stage / expected
    with destination.open("xb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
    os.chmod(destination, 0o600)
    return destination


def index_module() -> Any:
    path = Path(__file__).resolve().parents[1] / "release" / "create-installer-artifact-index.py"
    spec = importlib.util.spec_from_file_location("installer_artifact_index", path)
    if spec is None or spec.loader is None:
        fail("cannot load record validator")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def installer_files_module() -> Any:
    path = Path(__file__).resolve().parents[1] / "release" / "installer_files.py"
    spec = importlib.util.spec_from_file_location("installer_files", path)
    if spec is None or spec.loader is None:
        fail("cannot load atomic directory publisher")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def validate_records(stage: Path, source_sha: str, run_id: str) -> None:
    validator = index_module()
    for component, invocation, method in SPECS:
        path = stage / f"{component}-publication-record.json"
        try:
            value = validator._record(path, component, source_sha, method)
        except (validator.ArtifactIndexError, OSError) as error:
            raise FetchError(f"publication record is invalid: {component}") from error
        publication = value["publication"]
        if (value["build_revision"] != source_sha or publication["workflow"] != "image-publish.yml" or
                str(publication["run_id"]) != run_id or publication["invocation"] != invocation):
            fail(f"publication record is not bound to selected run: {component}")


def publish(stage: Path, output: Path) -> None:
    try:
        installer_files_module().publish_directory(stage, output)
    except OSError as error:
        raise FetchError("cannot atomically publish validated records") from error


def retrieve(repository: str, source_sha: str, run_id: str, output: Path) -> None:
    if output.exists() or output.is_symlink() or not output.is_absolute() or os.path.normpath(str(output)) != str(output):
        fail("output directory must be an absolute new path")
    ancestor = Path(output.anchor)
    for part in output.parts[1:-1]:
        ancestor /= part
        try:
            info = ancestor.lstat()
        except OSError as error:
            raise FetchError("output parent must be an existing regular directory") from error
        if ancestor.is_symlink() or not stat.S_ISDIR(info.st_mode):
            fail("output parent ancestry must contain only regular directories")
    stage = Path(tempfile.mkdtemp(prefix=".release-publication-records-", dir=output.parent))
    os.chmod(stage, 0o700)
    try:
        run_is_trusted(gh_json(f"repos/{repository}/actions/runs/{run_id}", stage), repository, source_sha, run_id)
        artifacts = select_artifacts(list_artifacts(repository, run_id, stage), run_id, source_sha)
        for component, artifact_id in artifacts.items():
            archive = stage / f"{artifact_id}.zip"
            gh_zip(f"repos/{repository}/actions/artifacts/{artifact_id}/zip", archive)
            extract_record(archive, component, stage)
            archive.unlink()
        validate_records(stage, source_sha, run_id)
        publish(stage, output)
    finally:
        shutil.rmtree(stage, ignore_errors=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()
    try:
        if not REPOSITORY.fullmatch(args.repository) or not SHA40.fullmatch(args.source_sha) or not RUN_ID.fullmatch(args.run_id):
            fail("repository, source SHA, or run ID is invalid")
        retrieve(args.repository, args.source_sha, args.run_id, args.output_dir)
    except FetchError as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
