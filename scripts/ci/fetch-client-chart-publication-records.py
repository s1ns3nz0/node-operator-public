#!/usr/bin/env python3
"""Retrieve one authorization-bound GitOps client-chart evidence artifact.

This is read-only GitHub retrieval.  It does not independently verify Cosign
or ECR state, activate anything, or authenticate the approval source.
"""
from __future__ import annotations

import argparse
import importlib.util
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import sys
import tempfile
from typing import Any
import zipfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts" / "release"))
import client_chart_release_authorization as authorization

NAMES = authorization.NAMES
REVIEW_FILES = frozenset(("gitops-chart-signature-verified.json", "gitops-chart-sbom-verified.json", "gitops-chart-release-predicate.json", "gitops-chart-release-verified.json"))
MAX_MEMBER = 4 * 1024 * 1024
ARTIFACT_NAME = re.compile(r"^gitops-chart-evidence-[a-z0-9-]+$")


class FetchClientChartError(ValueError):
    pass


def fail(message: str) -> None:
    raise FetchClientChartError(message)


def generic() -> Any:
    path = ROOT / "scripts" / "ci" / "fetch-release-publication-records.py"
    spec = importlib.util.spec_from_file_location("release_publication_retrieval", path)
    if spec is None or spec.loader is None:
        fail("cannot load GitHub retrieval safety helpers")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def output_is_safe(output: Path) -> None:
    if not output.is_absolute() or os.path.normpath(str(output)) != str(output) or output.exists() or output.is_symlink():
        fail("output directory must be an absolute new path")
    ancestor = Path(output.anchor)
    for part in output.parts[1:-1]:
        ancestor /= part
        try:
            info = ancestor.lstat()
        except OSError as error:
            raise FetchClientChartError("output parent must be an existing regular directory") from error
        if ancestor.is_symlink() or not stat.S_ISDIR(info.st_mode):
            fail("output parent ancestry must contain only regular directories")


def load_authorization(path: Path) -> dict[str, Any]:
    if not path.is_absolute():
        fail("authorization path must be absolute")
    try:
        value, _ = authorization._read(path)
    except authorization.ClientChartAuthorizationError as error:
        raise FetchClientChartError("authorization is unsafe or invalid") from error
    try:
        publication, source = value["publication"], value["source_revision"]
        repository, workflow = publication["repository"], publication["workflow"]
        run_id, artifact_id, artifact_name, run_number = (publication[key] for key in ("run_id", "artifact_id", "artifact_name", "run_number"))
        target, hashes, approvals = value["target"], value["evidence_sha256"], value["approvals"]
    except (KeyError, TypeError) as error:
        raise FetchClientChartError("authorization is invalid") from error
    try:
        authorization.validate_authorization(value, "stage")
    except authorization.ClientChartAuthorizationError as error:
        raise FetchClientChartError("authorization is invalid") from error
    helper = generic()
    if (repository != "s1ns3nz0/node-operator-gitops" or workflow != "publish-oci.yml" or not isinstance(source, str) or
            not all(isinstance(item, str) for item in (run_id, artifact_id, artifact_name, run_number)) or
            not helper.SHA40.fullmatch(source) or not all(helper.RUN_ID.fullmatch(item) for item in (run_id, artifact_id, run_number)) or
            not ARTIFACT_NAME.fullmatch(artifact_name)):
        fail("authorization endpoint identity is invalid")
    return value


def trusted_run(value: Any, repository: str, source: str, run_id: str, run_number: str) -> None:
    if not isinstance(value, dict) or type(value.get("id")) is not int or str(value["id"]) != run_id or type(value.get("run_number")) is not int or str(value["run_number"]) != run_number:
        fail("workflow run identity differs")
    for key in ("repository", "head_repository"):
        if not isinstance(value.get(key), dict) or value[key].get("full_name") != repository:
            fail("workflow run repository is not the requested source repository")
    if value.get("head_sha") != source or value.get("head_branch") != "main" or value.get("event") not in {"push", "workflow_dispatch"} or value.get("status") != "completed" or value.get("conclusion") != "success":
        fail("workflow run is not a successful trusted main publication")
    path = value.get("path")
    if path not in {".github/workflows/publish-oci.yml", ".github/workflows/publish-oci.yml@refs/heads/main", f".github/workflows/publish-oci.yml@{source}"}:
        fail("workflow run does not use publish-oci.yml")


def select_artifact(value: Any, auth: dict[str, Any]) -> None:
    publication = auth["publication"]
    if not isinstance(value, dict) or not isinstance(value.get("artifacts"), list):
        fail("artifact listing is invalid")
    found = [item for item in value["artifacts"] if isinstance(item, dict) and item.get("name") == publication["artifact_name"]]
    if len(found) != 1:
        fail("client-chart artifact is missing or ambiguous")
    item = found[0]
    workflow_run = item.get("workflow_run")
    if (type(item.get("id")) is not int or str(item["id"]) != publication["artifact_id"] or item.get("expired") is not False or
            not isinstance(workflow_run, dict) or type(workflow_run.get("id")) is not int or str(workflow_run["id"]) != publication["run_id"] or
            workflow_run.get("head_sha") != auth["source_revision"]):
        fail("client-chart artifact is not bound to authorization")


def extract_evidence(archive_path: Path, stage: Path) -> dict[str, bytes]:
    try:
        with zipfile.ZipFile(archive_path) as archive:
            infos = archive.infolist()
            names = {info.filename for info in infos}
            if names not in (set(NAMES), set(NAMES) | REVIEW_FILES) or len(names) != len(infos) or sum(info.file_size for info in infos) > generic().MAX_ARCHIVE:
                fail("client-chart artifact ZIP does not match a reviewed five- or nine-file layout")
            evidence: dict[str, bytes] = {}
            for info in infos:
                path = PurePosixPath(info.filename)
                kind = (info.external_attr >> 16) & 0o170000
                if (info.is_dir() or path.is_absolute() or ".." in path.parts or len(path.parts) != 1 or
                        kind not in {0, stat.S_IFREG} or info.file_size > MAX_MEMBER or info.compress_size > generic().MAX_ARCHIVE):
                    fail("client-chart artifact ZIP contains an unsafe member")
                raw = archive.read(info)
                if len(raw) > MAX_MEMBER:
                    fail("client-chart evidence exceeds limit")
                # Auxiliary review artifacts are bounded and ignored, not treated
                # as verified authority. Only the five authorized hashes are used.
                if info.filename in NAMES:
                    evidence[info.filename] = raw
    except (OSError, RuntimeError, zipfile.BadZipFile) as error:
        raise FetchClientChartError("client-chart artifact ZIP is invalid") from error
    if set(evidence) != set(NAMES):
        fail("client-chart artifact ZIP does not contain the required evidence")
    for name in NAMES:
        destination = stage / name
        with destination.open("xb") as handle:
            handle.write(evidence[name]); handle.flush(); os.fsync(handle.fileno())
        os.chmod(destination, 0o600)
    return evidence


def retrieve(authorization_path: Path, output: Path) -> None:
    auth = load_authorization(authorization_path)
    output_is_safe(output)
    publication = auth["publication"]
    stage = Path(tempfile.mkdtemp(prefix=".client-chart-publication-records-", dir=output.parent))
    os.chmod(stage, 0o700)
    helper = generic()
    try:
        try:
            run = helper.gh_json(f"repos/{publication['repository']}/actions/runs/{publication['run_id']}", stage)
            trusted_run(run, publication["repository"], auth["source_revision"], publication["run_id"], publication["run_number"])
            artifacts = helper.list_artifacts(publication["repository"], publication["run_id"], stage)
            select_artifact(artifacts, auth)
            archive = stage / "evidence.zip"
            helper.gh_zip(f"repos/{publication['repository']}/actions/artifacts/{publication['artifact_id']}/zip", archive)
            evidence = extract_evidence(archive, stage)
        except (helper.FetchError, OSError) as error:
            raise FetchClientChartError("client-chart publication retrieval is unsafe") from error
        try:
            authorization.validate_candidate_authorization(auth, evidence, "stage")
        except authorization.ClientChartAuthorizationError as error:
            raise FetchClientChartError("client-chart evidence is not authorization-bound") from error
        archive.unlink(missing_ok=True)
        try:
            helper.publish(stage, output)
        except (helper.FetchError, OSError) as error:
            raise FetchClientChartError("cannot atomically publish client-chart evidence") from error
    finally:
        shutil.rmtree(stage, ignore_errors=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--authorization-path", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()
    try:
        retrieve(args.authorization_path, args.output_dir)
    except FetchClientChartError as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
