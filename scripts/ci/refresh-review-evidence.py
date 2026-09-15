#!/usr/bin/env python3
# Check objective: Safely recover exact-head policy evidence from a trusted, recent gate artifact.
# Purpose: Recover recent exact-head review evidence only after validating its full GitHub provenance chain.
# Inputs: Review event, GitHub context/token, trusted SHA, EVIDENCE_ROOT, and read-only GitHub artifact APIs.
# Outputs: Validated cache evidence/context JSON plus subject/pr/cache readiness outputs.
# Side effects: Read-only GitHub API/artifact download and bounded local cache writes; no scanner rerun or publication.
"""Fail-closed cache loader for review-refresh policy evaluations.

Only GitHub API responses and an artifact produced by the pinned policy gate are
accepted.  Archive members are read in memory by exact name; no archive path is
ever extracted into the runner workspace.
"""
import datetime as dt
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import zipfile
from io import BytesIO

SHA = re.compile(r"[0-9a-f]{40}")
MAX_ZIP_BYTES = 5 * 1024 * 1024
MAX_JSON_BYTES = 512 * 1024
MAX_ARTIFACT_AGE = dt.timedelta(hours=24)
MAX_FUTURE_SKEW = dt.timedelta(minutes=5)


class Rejected(Exception):
    pass


def reject(message):
    raise Rejected(message)


def env(name):
    value = os.environ.get(name, "")
    if not value:
        reject("required execution context is missing")
    return value


def sha(value, field):
    if not isinstance(value, str) or not SHA.fullmatch(value):
        reject(f"{field} is invalid")
    return value


def positive_id(value, field):
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        reject(f"{field} is invalid")
    return value


def api_json(endpoint, paginate=False):
    command = ["gh", "api", "--method", "GET"]
    if paginate:
        command.append("--paginate")
    command.append(endpoint)
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False)
    if result.returncode:
        reject("GitHub API read failed")
    try:
        text = result.stdout.decode("utf-8")
    except UnicodeDecodeError:
        reject("GitHub API returned invalid JSON")
    decoder = json.JSONDecoder()
    documents = []
    offset = 0
    while offset < len(text):
        while offset < len(text) and text[offset].isspace():
            offset += 1
        if offset == len(text):
            break
        try:
            document, offset = decoder.raw_decode(text, offset)
        except json.JSONDecodeError:
            reject("GitHub API returned invalid JSON")
        documents.append(document)
    if not documents:
        reject("GitHub API returned no JSON")
    return documents if paginate else documents[0]


def api_zip(endpoint):
    process = subprocess.Popen(["gh", "api", "--method", "GET", endpoint], stdout=subprocess.PIPE,
                               stderr=subprocess.DEVNULL)
    assert process.stdout is not None
    payload = process.stdout.read(MAX_ZIP_BYTES + 1)
    if len(payload) > MAX_ZIP_BYTES:
        process.kill()
        process.wait()
        reject("artifact archive exceeds the size limit")
    if process.wait() != 0:
        reject("artifact download failed")
    return payload


def object_field(value, field):
    if not isinstance(value, dict):
        reject(f"{field} is invalid")
    return value


def exact_event(event, repository):
    workflow_run = object_field(event.get("workflow_run"), "review signal")
    if (workflow_run.get("name") != "CI Evidence Review Signal" or
            workflow_run.get("path") != ".github/workflows/review-signal.yml" or
            workflow_run.get("event") != "pull_request_review" or
            workflow_run.get("conclusion") != "success" or
            object_field(workflow_run.get("repository"), "review signal repository").get("full_name") != repository):
        reject("review signal is not trusted")
    pull_requests = workflow_run.get("pull_requests")
    if not isinstance(pull_requests, list) or len(pull_requests) != 1:
        reject("review signal pull request is invalid")
    return positive_id(object_field(pull_requests[0], "review signal pull request").get("number"), "pull request number")


def current_pull_request(repository, number):
    pull = object_field(api_json(f"repos/{repository}/pulls/{number}"), "pull request")
    if pull.get("state") != "open":
        reject("pull request is not open")
    head = sha(object_field(pull.get("head"), "pull request head").get("sha"), "pull request head")
    base = sha(object_field(pull.get("base"), "pull request base").get("sha"), "pull request base")
    return head, base


def parse_created_at(value):
    if not isinstance(value, str):
        reject("artifact creation time is invalid")
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        reject("artifact creation time is invalid")
    if parsed.tzinfo is None:
        reject("artifact creation time is invalid")
    return parsed.astimezone(dt.timezone.utc)


def newest_artifact(repository, subject_sha):
    documents = api_json(f"repos/{repository}/actions/artifacts?per_page=100", paginate=True)
    artifacts = []
    for document in documents:
        page = object_field(document, "artifact page").get("artifacts")
        if not isinstance(page, list):
            reject("artifact page is invalid")
        artifacts.extend(page)
    expected_name = f"ci-evidence-gate-{subject_sha}"
    matching = [artifact for artifact in artifacts if isinstance(artifact, dict) and artifact.get("name") == expected_name]
    if not matching:
        reject("no exact-head evidence artifact exists")
    def ordering(artifact):
        return (parse_created_at(artifact.get("created_at")), positive_id(artifact.get("id"), "artifact ID"))
    artifact = max(matching, key=ordering)
    created_at = parse_created_at(artifact.get("created_at"))
    now = dt.datetime.now(dt.timezone.utc)
    if created_at > now + MAX_FUTURE_SKEW or now - created_at > MAX_ARTIFACT_AGE:
        reject("newest artifact is outside the accepted age window")
    if artifact.get("expired") is not False:
        reject("newest artifact is expired")
    return artifact, positive_id(object_field(artifact.get("workflow_run"), "artifact workflow run").get("id"), "artifact workflow run ID")


def validate_gate_run(repository, gate_run_id, trusted_sha):
    run = object_field(api_json(f"repos/{repository}/actions/runs/{gate_run_id}"), "gate run")
    if (object_field(run.get("repository"), "gate run repository").get("full_name") != repository or
            run.get("path") != ".github/workflows/evidence-gate.yml" or run.get("event") != "workflow_run" or
            run.get("status") != "completed" or run.get("conclusion") not in {"success", "failure"} or
            run.get("head_sha") != trusted_sha):
        reject("artifact was not produced by the trusted policy gate")


def read_archive(repository, artifact_id):
    payload = api_zip(f"repos/{repository}/actions/artifacts/{artifact_id}/zip")
    try:
        archive = zipfile.ZipFile(BytesIO(payload))
        names = archive.namelist()
        expected = {"published/evidence.json", "published/cache-context.json"}
        if not expected <= set(names) or any(names.count(name) != 1 for name in expected):
            reject("artifact is missing required cache members")
        contents = {}
        for name in expected:
            info = archive.getinfo(name)
            if info.is_dir() or info.file_size > MAX_JSON_BYTES or info.compress_size > MAX_JSON_BYTES:
                reject("artifact cache member exceeds the size limit")
            contents[name] = archive.read(info)
    except (OSError, zipfile.BadZipFile, KeyError):
        reject("artifact archive is invalid")
    decoded = []
    for content in (contents["published/evidence.json"], contents["published/cache-context.json"]):
        try:
            decoded.append(json.loads(content.decode("utf-8")))
        except (UnicodeDecodeError, json.JSONDecodeError):
            reject("artifact cache member is invalid JSON")
    return decoded[0], decoded[1]


def validate_context(context, subject_sha, base_sha, trusted_sha, gate_run_id):
    context = object_field(context, "cache context")
    if (type(context.get("schema_version")) is not int or context.get("schema_version") != 1 or
            context.get("subject_sha") != subject_sha or
            context.get("base_sha") != base_sha or context.get("trusted_sha") != trusted_sha or
            positive_id(context.get("gate_run_id"), "cache gate run ID") != gate_run_id):
        reject("cache context does not bind to the current review")
    return positive_id(context.get("source_run_id"), "cache source run ID")


def validate_source_run(repository, source_run_id, subject_sha, pr_number):
    run = object_field(api_json(f"repos/{repository}/actions/runs/{source_run_id}"), "source run")
    pull_requests = run.get("pull_requests")
    if (object_field(run.get("repository"), "source run repository").get("full_name") != repository or
            run.get("name") != "CI" or run.get("path") != ".github/workflows/continuous-integration.yml" or
            run.get("event") != "pull_request" or run.get("status") != "completed" or
            run.get("conclusion") != "success" or run.get("head_sha") != subject_sha or
            not isinstance(pull_requests, list) or len(pull_requests) != 1 or
            object_field(pull_requests[0], "source run pull request").get("number") != pr_number):
        reject("cache source run is not the current successful CI run")


def validate_evidence(evidence, subject_sha):
    evidence = object_field(evidence, "cached evidence")
    subject = object_field(evidence.get("subject"), "cached evidence subject")
    if subject.get("commit_sha") != subject_sha:
        reject("cached evidence does not match the current head")
    for field in ("evidence", "scm", "policy"):
        object_field(evidence.get(field), f"cached evidence {field}")


def write_json_exclusive(path, value):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as output:
        json.dump(value, output, sort_keys=True, separators=(",", ":"))
        output.write("\n")


def append_output(path, **values):
    with open(path, "a", encoding="utf-8") as output:
        for key, value in values.items():
            output.write(f"{key}={value}\n")


def main():
    repository = env("GITHUB_REPOSITORY")
    env("GH_TOKEN")
    trusted_sha = sha(env("GITHUB_SHA"), "trusted workflow SHA")
    event_path = Path(env("GITHUB_EVENT_PATH"))
    output_path = env("GITHUB_OUTPUT")
    evidence_root = Path(env("EVIDENCE_ROOT"))
    try:
        event = json.loads(event_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        reject("review event is invalid")
    pr_number = exact_event(object_field(event, "review event"), repository)
    subject_sha, base_sha = current_pull_request(repository, pr_number)
    # Publish the current binding before artifact lookup so later failure cannot
    # accidentally approve evidence for a moved pull-request head.
    append_output(output_path, subject_sha=subject_sha, pr_number=pr_number)
    artifact, gate_run_id = newest_artifact(repository, subject_sha)
    validate_gate_run(repository, gate_run_id, trusted_sha)
    evidence, context = read_archive(repository, positive_id(artifact.get("id"), "artifact ID"))
    source_run_id = validate_context(context, subject_sha, base_sha, trusted_sha, gate_run_id)
    validate_source_run(repository, source_run_id, subject_sha, pr_number)
    validate_evidence(evidence, subject_sha)
    evidence_root.mkdir(parents=True, exist_ok=True)
    cache = evidence_root / "cache"
    try:
        cache.mkdir(mode=0o700)
        write_json_exclusive(cache / "evidence.json", evidence)
        write_json_exclusive(cache / "cache-context.json", context)
    except OSError:
        reject("validated cache output cannot be written safely")
    append_output(output_path, cache_ready="true")


if __name__ == "__main__":
    try:
        main()
    except Rejected as error:
        print(f"refresh evidence cache rejected: {error}", file=sys.stderr)
        raise SystemExit(1)
