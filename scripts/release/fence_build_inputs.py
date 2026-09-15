#!/usr/bin/env python3
"""Compute the canonical reviewed-input digest for the signing-fence image."""

from __future__ import annotations

import argparse
import hashlib
import os
import stat
import sys
from pathlib import Path


INPUT_PATHS = (
    "go.mod",
    ".ci/validator-signing-fence/Dockerfile",
    "cmd/validator-signing-fence/main.go",
    "cmd/validator-signing-fence/main_test.go",
    "scripts/ci/collect-validator-signing-fence-release-evidence.sh",
    ".github/workflows/fence-security.yml",
    ".ci/fence-security/Dockerfile",
    ".ci/fence-security/blackbox.go",
    ".ci/fence-security/tools.env",
    ".ci/fence-security/zap-report.jq",
    "scripts/ci/install-fence-security-tools.sh",
    "scripts/ci/run-fence-security-sast.sh",
    "scripts/ci/run-fence-security-dast.sh",
)


class InputError(ValueError):
    """The requested source tree cannot safely provide reviewed inputs."""


def _lstat(path: Path, description: str) -> os.stat_result:
    try:
        return path.lstat()
    except OSError as error:
        raise InputError(f"{description}: {error.strerror}") from error


def _require_directory_without_symlink(path: Path, root: Path) -> None:
    current = path
    while True:
        mode = _lstat(current, "required input parent is unavailable").st_mode
        if stat.S_ISLNK(mode):
            raise InputError(f"required input parent is a symlink: {current}")
        if not stat.S_ISDIR(mode):
            raise InputError(f"required input parent is not a directory: {current}")
        if current == root:
            return
        current = current.parent


def _hash_regular_file(root: Path, relative: str) -> str:
    path = root / relative
    _require_directory_without_symlink(path.parent, root)
    before = _lstat(path, "required input is unavailable")
    if stat.S_ISLNK(before.st_mode):
        raise InputError(f"required input is a symlink: {relative}")
    if not stat.S_ISREG(before.st_mode):
        raise InputError(f"required input is not a regular file: {relative}")

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise InputError(f"required input cannot be opened safely: {relative}: {error.strerror}") from error
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise InputError(f"required input changed while opening: {relative}")
        digest = hashlib.sha256()
        while chunk := os.read(descriptor, 1024 * 1024):
            digest.update(chunk)
        return digest.hexdigest()
    finally:
        os.close(descriptor)


def fence_input_sha256(root: Path) -> str:
    if not root.is_absolute():
        raise InputError("source root must be absolute")
    root_status = _lstat(root, "source root is unavailable")
    if stat.S_ISLNK(root_status.st_mode):
        raise InputError("source root must not be a symlink")
    if not stat.S_ISDIR(root_status.st_mode):
        raise InputError("source root is not a directory")

    raw_hashes = (_hash_regular_file(root, relative) for relative in INPUT_PATHS)
    serialized = "".join(f"{raw_hash}\n" for raw_hash in raw_hashes).encode("ascii")
    return hashlib.sha256(serialized).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, type=Path, help="absolute repository root")
    arguments = parser.parse_args()
    try:
        print(fence_input_sha256(arguments.root))
    except InputError as error:
        print(f"fence build inputs: {error}", file=sys.stderr)
        return 65
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
