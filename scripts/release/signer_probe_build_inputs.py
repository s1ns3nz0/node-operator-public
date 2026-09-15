#!/usr/bin/env python3
"""Compute the reviewed build-context digest for the signer identity probe."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import stat
import sys

from fence_build_inputs import InputError, _hash_regular_file, _lstat


INPUT_PATHS = (
    "go.mod",
    ".ci/validator-signer-identity-probe/Dockerfile",
    ".ci/validator-signer-identity-probe/Dockerfile.dockerignore",
    "cmd/validator-signer-identity-probe/main.go",
    "cmd/validator-signer-identity-probe/main_test.go",
)


class SignerProbeInputError(ValueError):
    """The reviewed signer-probe build context is unavailable or unsafe."""


def signer_probe_input_sha256(root: Path) -> str:
    """Return SHA-256 of the ordered raw SHA-256 hashes of exact build inputs."""
    if not root.is_absolute():
        raise SignerProbeInputError("source root must be absolute")
    try:
        info = _lstat(root, "source root is unavailable")
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise SignerProbeInputError("source root must be a non-symlink directory")
        raw_hashes = (_hash_regular_file(root, relative) for relative in INPUT_PATHS)
        joined = "".join(f"{raw_hash}\n" for raw_hash in raw_hashes).encode("ascii")
        return hashlib.sha256(joined).hexdigest()
    except InputError as error:
        raise SignerProbeInputError("reviewed signer-probe input is unsafe") from error


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, type=Path, help="absolute repository root")
    arguments = parser.parse_args()
    try:
        print(signer_probe_input_sha256(arguments.root))
    except SignerProbeInputError as error:
        print(f"signer probe build inputs: {error}", file=sys.stderr)
        return 65
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
