#!/usr/bin/env python3
"""Validate non-secret EIP-2335 keystore identity metadata before custody writes."""
import argparse
import json
import os
from pathlib import Path
import re
import stat
import uuid
import sys

PUBKEY = re.compile(r"0x[0-9a-fA-F]{96}\Z")
HEX = re.compile(r"[0-9a-fA-F]+\Z")
MAX_BYTES = 1024 * 1024


def fail(message: str, code: int = 65) -> "None":
    print(message, file=sys.stderr)
    raise SystemExit(code)


def regular(path: Path) -> bool:
    try:
        return path.is_file() and not path.is_symlink()
    except OSError:
        return False


def no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def hex_value(value, length):
    return isinstance(value, str) and len(value) == length and bool(HEX.fullmatch(value))


def eip2335(value):
    if not isinstance(value, dict) or not {"crypto", "pubkey", "path", "uuid", "version"} <= set(value) or value.get("version") != 4 or not isinstance(value.get("path"), str):
        return False
    try: uuid.UUID(value["uuid"])
    except (ValueError, TypeError): return False
    crypto = value.get("crypto")
    if not isinstance(crypto, dict) or set(crypto) != {"kdf", "checksum", "cipher"}:
        return False
    kdf, checksum, cipher = crypto["kdf"], crypto["checksum"], crypto["cipher"]
    if not all(isinstance(part, dict) and set(part) == {"function", "params", "message"} for part in (kdf, checksum, cipher)):
        return False
    params = kdf["params"]
    kdf_ok = ((kdf["function"] == "scrypt" and set(params) == {"dklen","n","r","p","salt"} and all(isinstance(params[x], int) and params[x] > 0 for x in ("dklen","n","r","p")) and hex_value(params["salt"], 64)) or
              (kdf["function"] == "pbkdf2" and set(params) == {"dklen","c","prf","salt"} and isinstance(params["dklen"], int) and params["dklen"] > 0 and isinstance(params["c"], int) and params["c"] > 0 and params["prf"] == "hmac-sha256" and hex_value(params["salt"], 64)))
    return (kdf_ok and isinstance(kdf["message"], str) and
            checksum["function"] == "sha256" and checksum["params"] == {} and hex_value(checksum["message"], 64) and
            cipher["function"] == "aes-128-ctr" and isinstance(cipher["params"], dict) and hex_value(cipher["message"], 64) and hex_value(cipher["params"].get("iv"), 32))


def main() -> None:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--keystore-dir", required=True)
    parser.add_argument("--expected-public-key", required=True)
    args = parser.parse_args()
    expected = args.expected_public_key.lower()
    if not PUBKEY.fullmatch(expected):
        fail("expected public key is invalid", 64)
    directory = Path(args.keystore_dir)
    if not directory.is_absolute() or directory.is_symlink() or not directory.is_dir():
        fail("keystore directory is unsafe", 64)
    try:
        candidates = list(directory.glob("keystore-*.json"))
    except OSError:
        fail("keystore directory cannot be inspected")
    if len(candidates) != 1 or not regular(candidates[0]):
        fail("expected exactly one regular keystore JSON")
    path = candidates[0]
    try:
        if not hasattr(os, "O_NOFOLLOW"): raise OSError("nofollow unavailable")
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_BYTES:
            raise OSError("unsafe keystore")
        raw = os.read(fd, MAX_BYTES + 1)
        os.close(fd)
        if len(raw) > MAX_BYTES: raise OSError("oversized keystore")
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=no_duplicates)
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError):
        fail("keystore metadata is invalid")
    if not eip2335(value):
        fail("keystore is not EIP-2335 version 4")
    pubkey = value.get("pubkey")
    if not isinstance(pubkey, str) or not PUBKEY.fullmatch("0x" + pubkey.removeprefix("0x")):
        fail("keystore public key metadata is invalid")
    actual = ("0x" + pubkey.removeprefix("0x")).lower()
    if actual != expected:
        fail("keystore public key does not match the expected validator")
    print(json.dumps({"schema_version": 1, "public_key": actual, "keystore_file": path.name}, separators=(",", ":")))


if __name__ == "__main__":
    main()
