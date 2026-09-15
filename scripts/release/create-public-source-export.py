#!/usr/bin/env python3
"""Build a history-free, sanitized public source export from tracked files only.

The export deliberately omits live-operation history and replaces the private
account, deployment label, and resource identifiers with generic fixtures.
It refuses to write into an existing path and fails if a prohibited marker
survives in the output.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys

PRIVATE_ACCOUNT = "123456789012"
EXAMPLE_ACCOUNT = "123456789012"
PRIVATE_VALIDATOR_SET = "hoodi-example"
EXAMPLE_VALIDATOR_SET = "hoodi-example"
PRIVATE_DEPLOYMENT = re.compile(r"node-op-[0-9]{10}(?![0-9])")
EXAMPLE_DEPLOYMENT = "node-operator-example"
EXCLUDED_PREFIXES = (".claude/", "docs/", "plans/", "reports/")
EXCLUDED_RELEASE_PATHS = {"release"}
TOKEN_PATTERNS = (
    re.compile(rb"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    re.compile(rb"-----BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY-----"),
    re.compile(rb"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"),
    re.compile(rb"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
)
RESOURCE_PATTERNS = (
    (re.compile(r"\bi-[0-9a-f]{8,17}\b"), "i-0123456789abcdef0"),
    (re.compile(r"\bsg-[0-9a-f]{8,17}\b"), "sg-0123456789abcdef0"),
    (re.compile(r"\b(?:vol|vpce)-[0-9a-f]{8,17}\b"), "resource-example"),
)


def tracked_files(root: Path) -> list[str]:
    result = subprocess.run(
        ["git", "-C", str(root), "ls-files", "-z"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    return sorted(item.decode("utf-8") for item in result.stdout.split(b"\0") if item)


def selected(path: str) -> bool:
    if path == "release/hoodi-release-contract.json" or path.endswith(".example") and path.startswith("release/"):
        return True
    return not path.startswith(EXCLUDED_PREFIXES) and path not in EXCLUDED_RELEASE_PATHS and not path.startswith("release/")


def sanitize(raw: bytes) -> bytes:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw
    text = text.replace(PRIVATE_ACCOUNT, EXAMPLE_ACCOUNT).replace(PRIVATE_VALIDATOR_SET, EXAMPLE_VALIDATOR_SET)
    text = PRIVATE_DEPLOYMENT.sub(EXAMPLE_DEPLOYMENT, text)
    for pattern, replacement in RESOURCE_PATTERNS:
        text = pattern.sub(replacement, text)
    return text.encode("utf-8")


def prohibited(raw: bytes) -> str | None:
    if PRIVATE_ACCOUNT.encode() in raw:
        return "private AWS account identifier"
    if PRIVATE_VALIDATOR_SET.encode() in raw:
        return "prior validator-set label"
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        text = ""
    if PRIVATE_DEPLOYMENT.search(text):
        return "prior deployment identifier"
    for pattern in TOKEN_PATTERNS:
        if pattern.search(raw):
            return "credential-like marker"
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    for pattern, replacement in RESOURCE_PATTERNS:
        for match in pattern.findall(text):
            if match != replacement:
                return "literal AWS resource identifier"
    return None


def create(root: Path, output: Path) -> int:
    if not root.is_absolute() or not output.is_absolute():
        raise ValueError("source root and output must be absolute")
    if not (root / ".git").exists():
        raise ValueError("source root must be a Git repository")
    if output.exists() or output.is_symlink():
        raise ValueError("output path must be absent")
    output.mkdir(mode=0o700, parents=True)
    count = 0
    for relative in tracked_files(root):
        if not selected(relative):
            continue
        source = root / relative
        if source.is_symlink() or not source.is_file():
            raise ValueError(f"tracked source must be a regular non-symlink file: {relative}")
        target = output / relative
        target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        raw = sanitize(source.read_bytes())
        reason = prohibited(raw)
        if reason:
            raise ValueError(f"public export rejects {relative}: {reason}")
        target.write_bytes(raw)
        os.chmod(target, stat.S_IMODE(source.stat().st_mode))
        count += 1
    for path in output.rglob("*"):
        if path.is_file() and (reason := prohibited(path.read_bytes())):
            raise ValueError(f"public export verification failed for {path.relative_to(output)}: {reason}")
    print(f"PASS: public source export created with {count} tracked sanitized files at {output}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, default=Path.cwd())
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        return create(args.source_root.resolve(), args.output)
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        print(f"FAIL: public source export was not created: {error}", file=sys.stderr)
        if args.output.exists() and args.output.is_dir():
            shutil.rmtree(args.output)
        return 65


if __name__ == "__main__":
    raise SystemExit(main())
