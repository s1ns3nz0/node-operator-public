#!/usr/bin/env python3
"""Offline EIP-2335 custody-key verifier.

This tool intentionally accepts passwords only via a private file or inherited
file descriptor.  It is not packaged or wired into a release yet.
"""
import argparse
import hashlib
import hmac
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
from typing import Any

MAX_KEYSTORE_BYTES = 1024 * 1024
MAX_PASSWORD_BYTES = 16 * 1024
MAX_SCRYPT_MEMORY_BYTES = 512 * 1024 * 1024
MAX_SCRYPT_N = 1 << 18
MAX_SCRYPT_R = 8
MAX_SCRYPT_P = 2
MAX_PBKDF2_ROUNDS = 2_000_000


class VerificationError(Exception):
    pass


class PrivateArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise VerificationError()


def reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise VerificationError()
        result[key] = value
    return result


def read_private_fd(fd: int, maximum: int) -> bytes:
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600:
        raise VerificationError()
    if info.st_size < 0 or info.st_size > maximum:
        raise VerificationError()
    os.lseek(fd, 0, os.SEEK_SET)
    data = bytearray()
    while len(data) <= maximum:
        chunk = os.read(fd, min(65536, maximum + 1 - len(data)))
        if not chunk:
            break
        data.extend(chunk)
    if len(data) > maximum:
        raise VerificationError()
    return bytes(data)


def open_private_file(value: str) -> int:
    path = Path(value)
    if not path.is_absolute():
        raise VerificationError()
    try:
        return os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except (AttributeError, OSError) as exc:
        raise VerificationError() from exc


def read_private_file(value: str, maximum: int) -> bytes:
    fd = open_private_file(value)
    try:
        return read_private_fd(fd, maximum)
    finally:
        os.close(fd)


def input_bytes(file_value: str | None, fd_value: int | None, maximum: int) -> bytes:
    if (file_value is None) == (fd_value is None):
        raise VerificationError()
    if fd_value is not None:
        return read_private_fd(fd_value, maximum)
    assert file_value is not None
    return read_private_file(file_value, maximum)


def validate_expected(value: str) -> str:
    if not isinstance(value, str) or len(value) != 98 or not value.startswith("0x"):
        raise VerificationError()
    try:
        int(value[2:], 16)
    except ValueError as exc:
        raise VerificationError() from exc
    return value.lower()


def validate_kdf(document: dict[str, Any]) -> None:
    try:
        kdf = document["crypto"]["kdf"]
        function = kdf["function"]
        params = kdf["params"]
    except (KeyError, TypeError) as exc:
        raise VerificationError() from exc
    if not isinstance(params, dict):
        raise VerificationError()
    if function == "scrypt":
        keys = {"dklen", "n", "r", "p", "salt"}
        if set(params) != keys:
            raise VerificationError()
        n, r, p, dklen = (params[name] for name in ("n", "r", "p", "dklen"))
        if (any(type(item) is not int for item in (n, r, p, dklen)) or dklen != 32 or
                n < 2 or n & (n - 1) or n > MAX_SCRYPT_N or r < 1 or r > MAX_SCRYPT_R or
                p < 1 or p > MAX_SCRYPT_P or 128 * n * r > MAX_SCRYPT_MEMORY_BYTES):
            raise VerificationError()
    elif function == "pbkdf2":
        keys = {"dklen", "c", "prf", "salt"}
        if set(params) != keys:
            raise VerificationError()
        rounds, dklen, prf = params["c"], params["dklen"], params["prf"]
        if (type(rounds) is not int or not 1 <= rounds <= MAX_PBKDF2_ROUNDS or dklen != 32 or
                prf != "hmac-sha256"):
            raise VerificationError()
    else:
        raise VerificationError()


def git_blob_sha1(data: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(data)).encode("ascii") + b"\0" + data).hexdigest()


def verify_package_tree(upstream: Path, commit: str) -> None:
    package = upstream / "ethstaker_deposit"
    if package.is_symlink() or not package.is_dir():
        raise VerificationError()
    if any(upstream.glob("ethstaker_deposit.*")):
        raise VerificationError()
    listing = subprocess.run(
        ["git", "-C", str(upstream), "ls-tree", "-r", "-z", "--full-tree", commit, "--", "ethstaker_deposit"],
        capture_output=True, check=False, timeout=10,
    )
    if listing.returncode != 0 or listing.stderr:
        raise VerificationError()
    expected: dict[Path, str] = {}
    for entry in listing.stdout.split(b"\0"):
        if not entry:
            continue
        try:
            details, encoded_path = entry.split(b"\t", 1)
            mode, kind, object_id = details.decode("ascii").split(" ")
            relative = Path(encoded_path.decode("utf-8"))
        except (UnicodeError, ValueError) as exc:
            raise VerificationError() from exc
        if mode != "100644" or kind != "blob" or len(object_id) != 40 or relative.is_absolute() or ".." in relative.parts:
            raise VerificationError()
        expected[relative] = object_id
    if not expected:
        raise VerificationError()
    actual: set[Path] = set()
    for directory, directories, files in os.walk(package, followlinks=False):
        directory_path = Path(directory)
        if directory_path.is_symlink():
            raise VerificationError()
        relative_directory = directory_path.relative_to(upstream)
        if not any(path.parts[:len(relative_directory.parts)] == relative_directory.parts for path in expected):
            raise VerificationError()
        for child in directories:
            if child == "__pycache__" or (directory_path / child).is_symlink():
                raise VerificationError()
        for child in files:
            path = directory_path / child
            relative = path.relative_to(upstream)
            if child.endswith(".pyc") or path.is_symlink() or not path.is_file() or relative not in expected:
                raise VerificationError()
            if git_blob_sha1(path.read_bytes()) != expected[relative]:
                raise VerificationError()
            actual.add(relative)
    if actual != set(expected):
        raise VerificationError()


def verify_source(upstream: Path) -> None:
    try:
        source_lock = Path(__file__).resolve().parents[2] / ".ci/custody-verifier/source-lock.json"
        lock = json.loads(source_lock.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicate_pairs)
        expected_hashes = lock["sha256"]
        if lock != {
            "schema_version": 1,
            "upstream": "ethstaker-deposit",
            "tag": "v1.3.0",
            "tag_object": "e62e0f6d42b96fc046fea46432aad00b7c55f270",
            "commit": "d8016bc8ca25d7f85e143828b6d99160f55a640f",
            "tree": "cb4515b6c62efa869294cc417a1b6cfe960e9ce4",
            "sha256": {
                "requirements.txt": "152f183d0ee04e47f8f77fee67dc67fe9a4a5dd77597a7c2939fa3024e867277",
                "uv.lock": "d7a6b3b5943c15dc8845f3a797789ced175cc6d0293b224ae5af60595d8468e8",
                "pyproject.toml": "fc02a0e15a839c17d71098be88dfc2002d1b36dcc9d10b2443b092cc45a3ef76",
            },
        }:
            raise VerificationError()
        for name in ("requirements.txt", "uv.lock", "pyproject.toml"):
            expected = expected_hashes[name]
            actual = hashlib.sha256((upstream / name).read_bytes()).hexdigest()
            if not hmac.compare_digest(actual, expected):
                raise VerificationError()
        git = subprocess.run(
            ["git", "-C", str(upstream), "rev-parse", "HEAD", "HEAD^{tree}", "v1.3.0^{commit}"],
            capture_output=True, text=True, check=False, timeout=10,
        )
        if git.returncode != 0 or git.stderr:
            raise VerificationError()
        if git.stdout.splitlines() != [lock["commit"], lock["tree"], lock["commit"]]:
            raise VerificationError()
        tag_type = subprocess.run(
            ["git", "-C", str(upstream), "cat-file", "-t", lock["tag_object"]],
            capture_output=True, text=True, check=False, timeout=10,
        )
        if tag_type.returncode != 0 or tag_type.stdout != "tag\n" or tag_type.stderr:
            raise VerificationError()
        verify_package_tree(upstream, lock["commit"])
    except (OSError, KeyError, TypeError, ValueError, subprocess.SubprocessError) as exc:
        raise VerificationError() from exc


def parse_args() -> argparse.Namespace:
    parser = PrivateArgumentParser(add_help=False)
    parser.add_argument("--keystore-file")
    parser.add_argument("--keystore-fd", type=int)
    parser.add_argument("--password-file")
    parser.add_argument("--password-fd", type=int)
    parser.add_argument("--expected-public-key", required=True)
    parser.add_argument("--upstream-root", required=True)
    return parser.parse_args()


def main() -> int:
    try:
        args = parse_args()
        expected = validate_expected(args.expected_public_key)
        upstream = Path(args.upstream_root)
        if not upstream.is_absolute() or not upstream.is_dir():
            raise VerificationError()
        verify_source(upstream)
        raw_keystore = input_bytes(args.keystore_file, args.keystore_fd, MAX_KEYSTORE_BYTES)
        raw_password = input_bytes(args.password_file, args.password_fd, MAX_PASSWORD_BYTES)
        document = json.loads(raw_keystore.decode("utf-8"), object_pairs_hook=reject_duplicate_pairs)
        if not isinstance(document, dict):
            raise VerificationError()
        validate_kdf(document)
        password = raw_password.decode("utf-8")
        sys.dont_write_bytecode = True
        sys.path.insert(0, str(upstream))
        from ethstaker_deposit.key_handling.keystore import Keystore
        from py_ecc.bls import G2ProofOfPossession as bls
        keystore = Keystore.from_json(document)
        metadata_key = "0x" + keystore.pubkey.lower()
        secret = keystore.decrypt(password)
        if not isinstance(secret, bytes) or len(secret) != 32:
            raise VerificationError()
        derived = bls.SkToPk(int.from_bytes(secret, "big"))
        if not bls.KeyValidate(derived):
            raise VerificationError()
        actual = "0x" + bytes(derived).hex()
        if not (hmac.compare_digest(actual, metadata_key) and hmac.compare_digest(actual, expected)):
            raise VerificationError()
        print(actual)
        return 0
    except (VerificationError, OSError, UnicodeError, ValueError, TypeError, KeyError):
        print("custody keystore verification failed", file=sys.stderr)
        return 65
    except Exception:
        print("custody keystore verification failed", file=sys.stderr)
        return 65


if __name__ == "__main__":
    raise SystemExit(main())
