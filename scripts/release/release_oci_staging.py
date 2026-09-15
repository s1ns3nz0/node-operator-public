#!/usr/bin/env python3
# Check objective: stage only bounded, exact-version OCI payload bytes before later approval binding.
"""Fetch a version-pinned OCI payload into a private local staging directory.

This is a transport integrity check, not release approval or authentication.
The caller must later bind the staged bytes to its canonical approval.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from typing import Any, Callable

from installer_oci_payload import MAX_METADATA_BYTES, verify_payload

MAX_CHUNKS = 994
MAX_CHUNK_BYTES = 2 * 1024 * 1024 * 1024
MAX_TOTAL_BYTES = 32 * 1024 * 1024 * 1024
SHA256 = re.compile(r"^[0-9a-f]{64}$")


class StagingError(ValueError):
    pass


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise StagingError("duplicate JSON object key")
        result[key] = value
    return result


def _json(raw: bytes, what: str) -> dict[str, Any]:
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError, StagingError) as error:
        raise StagingError(f"invalid {what} JSON") from error
    if not isinstance(value, dict):
        raise StagingError(f"{what} must be a JSON object")
    return value


def _regular(path: Path, what: str) -> os.stat_result:
    try:
        info = path.lstat()
    except OSError as error:
        raise StagingError(f"missing {what}") from error
    if not stat.S_ISREG(info.st_mode) or path.is_symlink():
        raise StagingError(f"{what} must be a regular file")
    return info


def _version(value: Any) -> str:
    if not isinstance(value, str) or not value or value == "null" or len(value) > 1024 or any(character in value for character in "\x00\r\n"):
        raise StagingError("explicit S3 VersionId is required")
    return value


def _object(value: Any, what: str, *, name: str | None = None) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {"key", "version_id", "sha256"} | ({"name", "size"} if name is not None else set()):
        raise StagingError(f"{what} schema is invalid")
    key, version, digest = value.get("key"), _version(value.get("version_id")), value.get("sha256")
    if not isinstance(key, str) or not key or len(key) > 1024 or any(character in key for character in "\x00\r\n") or not isinstance(digest, str) or not SHA256.fullmatch(digest):
        raise StagingError(f"{what} is invalid")
    if name is not None:
        size = value.get("size")
        if value.get("name") != name or type(size) is not int or not 0 < size < MAX_CHUNK_BYTES:
            raise StagingError(f"{what} is invalid")
    return value


def load_config(path: str | Path) -> dict[str, Any]:
    source = Path(path)
    info = _regular(source, "source config")
    if info.st_size > MAX_METADATA_BYTES:
        raise StagingError("source config is too large")
    config = _json(source.read_bytes(), "source config")
    if set(config) != {"schema_version", "region", "bucket", "manifest", "chunks"} or config.get("schema_version") != 1:
        raise StagingError("source config schema is invalid")
    if not isinstance(config["region"], str) or not re.fullmatch(r"[a-z0-9-]{3,64}", config["region"]):
        raise StagingError("source region is invalid")
    if not isinstance(config["bucket"], str) or not re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]", config["bucket"]):
        raise StagingError("source bucket is invalid")
    _object(config["manifest"], "manifest")
    chunks = config["chunks"]
    if not isinstance(chunks, list) or not 0 < len(chunks) <= MAX_CHUNKS:
        raise StagingError("source chunk count is invalid")
    total = 0
    for number, chunk in enumerate(chunks):
        _object(chunk, "chunk", name=f"chunks/oci-payload-{number:05d}.tar")
        total += chunk["size"]
    if total > MAX_TOTAL_BYTES:
        raise StagingError("source payload is too large")
    return config


def _private_new_output(output: Path) -> None:
    if not output.is_absolute() or output.exists() or output.is_symlink() or output.parent.is_symlink() or not output.parent.is_dir():
        raise StagingError("output must be a fresh absolute path beneath an existing private directory")
    if stat.S_IMODE(output.parent.stat().st_mode) & 0o077:
        raise StagingError("output parent must be private")


def _environment(region: str) -> dict[str, str]:
    environment = dict(os.environ)
    for key in list(environment):
        if key == "AWS_ENDPOINT_URL" or key.startswith("AWS_ENDPOINT_URL_"):
            environment.pop(key, None)
    environment["AWS_REGION"] = region
    environment["AWS_DEFAULT_REGION"] = region
    environment["AWS_IGNORE_CONFIGURED_ENDPOINT_URLS"] = "true"
    return environment


def _aws_json(command: list[str], environment: dict[str, str], runner: Callable[..., Any], *, timeout: int = 60) -> dict[str, Any]:
    try:
        result = runner(command, check=False, capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=timeout, env=environment)
        if getattr(result, "returncode", 1) != 0:
            raise StagingError("S3 read failed")
        raw = getattr(result, "stdout", "")
        return _json(raw.encode() if isinstance(raw, str) else raw, "S3 response")
    except (OSError, subprocess.TimeoutExpired, TypeError) as error:
        raise StagingError("S3 read failed") from error


def _get(bucket: str, region: str, item: dict[str, Any], target: Path, environment: dict[str, str], runner: Callable[..., Any]) -> None:
    # Payload chunks may approach 2 GiB; retain a finite but practical transfer bound.
    result = _aws_json(["aws", "s3api", "get-object", "--bucket", bucket, "--key", item["key"], "--version-id", item["version_id"], "--region", region, "--no-cli-pager", "--output", "json", str(target)], environment, runner, timeout=900)
    if result.get("VersionId") != item["version_id"]:
        raise StagingError("S3 object version differs from source config")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def fetch(source_config: str | Path, output_dir: str | Path, *, runner: Callable[..., Any] = subprocess.run) -> dict[str, Any]:
    """Download exact S3 object versions and verify the complete OCI graph."""
    config = load_config(source_config)
    output = Path(output_dir)
    _private_new_output(output)
    environment = _environment(config["region"])
    stage = Path(tempfile.mkdtemp(prefix=".oci-staging-", dir=output.parent))
    os.chmod(stage, 0o700)
    try:
        manifest_path = stage / "payload-manifest.json"
        manifest_head = _aws_json(["aws", "s3api", "head-object", "--bucket", config["bucket"], "--key", config["manifest"]["key"], "--version-id", config["manifest"]["version_id"], "--region", config["region"], "--no-cli-pager", "--output", "json"], environment, runner)
        if manifest_head.get("VersionId") != config["manifest"]["version_id"] or type(manifest_head.get("ContentLength")) is not int or not 0 <= manifest_head["ContentLength"] <= MAX_METADATA_BYTES:
            raise StagingError("S3 manifest metadata differs from source config")
        _get(config["bucket"], config["region"], config["manifest"], manifest_path, environment, runner)
        manifest_info = _regular(manifest_path, "downloaded manifest")
        if manifest_info.st_size > MAX_METADATA_BYTES or _sha256(manifest_path) != config["manifest"]["sha256"]:
            raise StagingError("downloaded manifest differs from source config")
        manifest = _json(manifest_path.read_bytes(), "downloaded manifest")
        rows = manifest.get("chunks")
        if not isinstance(rows, list) or len(rows) != len(config["chunks"]):
            raise StagingError("downloaded manifest chunks differ from source config")
        for supplied, recorded in zip(config["chunks"], rows):
            if not isinstance(recorded, dict) or {key: recorded.get(key) for key in ("name", "sha256", "size")} != {key: supplied[key] for key in ("name", "sha256", "size")}:
                raise StagingError("downloaded manifest chunks differ from source config")
        chunks = stage / "chunks"
        chunks.mkdir(mode=0o700)
        for item in config["chunks"]:
            head = _aws_json(["aws", "s3api", "head-object", "--bucket", config["bucket"], "--key", item["key"], "--version-id", item["version_id"], "--region", config["region"], "--no-cli-pager", "--output", "json"], environment, runner)
            if head.get("VersionId") != item["version_id"] or type(head.get("ContentLength")) is not int or head["ContentLength"] != item["size"]:
                raise StagingError("S3 chunk metadata differs from source config")
            target = stage / item["name"]
            _get(config["bucket"], config["region"], item, target, environment, runner)
            info = _regular(target, "downloaded chunk")
            if info.st_size != item["size"] or _sha256(target) != item["sha256"]:
                raise StagingError("downloaded chunk differs from source config")
            os.chmod(target, 0o600)
        roots = manifest.get("roots")
        if not isinstance(roots, dict):
            raise StagingError("downloaded manifest roots are invalid")
        expected_roots = {label: value.get("root_digest") for label, value in roots.items() if isinstance(value, dict)}
        if len(expected_roots) != len(roots):
            raise StagingError("downloaded manifest roots are invalid")
        verify_payload(stage, expected_roots=expected_roots)
        os.rename(stage, output)
        stage = None  # type: ignore[assignment]
        return manifest
    except (OSError, ValueError) as error:
        raise StagingError("OCI staging fetch failed") from error
    finally:
        if stage is not None:
            shutil.rmtree(stage, ignore_errors=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-config", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()
    try:
        fetch(args.source_config, args.output_dir)
    except StagingError:
        print("OCI staging fetch failed; no payload was staged.", file=sys.stderr)
        return 65
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
