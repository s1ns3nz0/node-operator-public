#!/usr/bin/env python3
"""Verify public Hoodi registration before reusing an existing validator key.

This is registration evidence only. It never authorizes signing or replaces the
separate deposit-receipt and slashing-protection gates required for activation.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import ssl
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable

HOODI_GENESIS_ROOT = "0x212f13fc4df078b6cb7db228f1c8307566dcecf900867401a92023d7ba99cb5f"
HOODI_GENESIS_TIME = 1742213400
KEY = re.compile(r"^0x[0-9a-f]{96}$")
CREDENTIALS = re.compile(r"^0x[0-9a-f]{64}$")
MAX_BODY = 1024 * 1024
ALLOWED_STATUS = {"pending_initialized", "pending_queued", "active_ongoing"}


class VerificationError(ValueError):
    pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> None:
        raise VerificationError("public Beacon redirect refused")


class HttpsTransport:
    def __init__(self, origin: str):
        self.origin = origin
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(), urllib.request.HTTPSHandler(context=ssl.create_default_context()))

    def get(self, path: str) -> bytes:
        request = urllib.request.Request(self.origin + path, headers={"Accept": "application/json", "User-Agent": "node-operator-installer/1.0"})
        try:
            with self.opener.open(request, timeout=10) as response:
                if response.status != 200 or response.geturl() != request.full_url:
                    raise VerificationError("public Beacon response is invalid")
                length = response.headers.get("Content-Length")
                if length is not None and (not length.isdigit() or int(length) > MAX_BODY):
                    raise VerificationError("public Beacon response exceeds limit")
                body = response.read(MAX_BODY + 1)
                if len(body) > MAX_BODY:
                    raise VerificationError("public Beacon response exceeds limit")
                return body
        except VerificationError:
            raise
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError) as error:
            raise VerificationError("public Beacon request failed") from error


def origin(url: str) -> str:
    if not isinstance(url, str):
        raise VerificationError("public Beacon URL is invalid")
    value = urllib.parse.urlsplit(url)
    if (value.scheme != "https" or not value.hostname or value.username or value.password or
            value.query or value.fragment or value.path not in {"", "/"}):
        raise VerificationError("public Beacon URL must be an HTTPS origin without credentials, query, fragment, or path")
    try:
        port = value.port
    except ValueError as error:
        raise VerificationError("public Beacon URL port is invalid") from error
    host = value.hostname
    if port is not None:
        host = f"{host}:{port}"
    return f"https://{host}"


def object_data(raw: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise VerificationError(f"{label} response is invalid JSON") from error
    if not isinstance(value, dict):
        raise VerificationError(f"{label} response is invalid")
    return value


def exact_text(value: Any, pattern: re.Pattern[str], label: str) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise VerificationError(f"{label} is invalid")
    return value


def verify(validator_public_key: str, withdrawal_credentials: str, beacon_url: str, output: Path, *, transport: Any | None = None, now: Callable[[], str] | None = None) -> dict[str, Any]:
    if not isinstance(validator_public_key, str) or not isinstance(withdrawal_credentials, str):
        raise VerificationError("validator public key or withdrawal credentials are invalid")
    key, credentials = exact_text(validator_public_key.lower(), KEY, "validator public key"), exact_text(withdrawal_credentials.lower(), CREDENTIALS, "withdrawal credentials")
    source = origin(beacon_url)
    if not output.is_absolute() or output.exists() or output.is_symlink() or not output.parent.is_dir() or output.parent.is_symlink():
        raise VerificationError("output must be an absolute new file under an existing regular directory")
    reader = transport or HttpsTransport(source)
    try:
        genesis_raw = reader.get("/eth/v1/beacon/genesis")
        validator_raw = reader.get(f"/eth/v1/beacon/states/finalized/validators/{key}")
    except VerificationError:
        raise
    except Exception as error:
        raise VerificationError("public Beacon request failed") from error
    if not isinstance(genesis_raw, bytes) or not isinstance(validator_raw, bytes) or len(genesis_raw) > MAX_BODY or len(validator_raw) > MAX_BODY:
        raise VerificationError("public Beacon response exceeds limit")
    genesis, validator_response = object_data(genesis_raw, "genesis"), object_data(validator_raw, "validator")
    genesis_data = genesis.get("data")
    if not isinstance(genesis_data, dict) or genesis_data.get("genesis_validators_root") != HOODI_GENESIS_ROOT or genesis_data.get("genesis_time") != str(HOODI_GENESIS_TIME):
        raise VerificationError("public Beacon Hoodi genesis mismatch")
    data = validator_response.get("data")
    if validator_response.get("finalized") is not True or validator_response.get("execution_optimistic") is not False or not isinstance(data, dict):
        raise VerificationError("public Beacon validator response is not finalized and execution-confirmed")
    index, status, validator = data.get("index"), data.get("status"), data.get("validator")
    if isinstance(index, bool) or not str(index).isdigit() or not isinstance(status, str) or status not in ALLOWED_STATUS or not isinstance(validator, dict):
        raise VerificationError("public Beacon validator status is invalid")
    if validator.get("pubkey") != key or validator.get("withdrawal_credentials") != credentials or validator.get("slashed") is not False:
        raise VerificationError("public Beacon validator identity or slashing state is invalid")
    checked_at = now() if now else __import__("datetime").datetime.now(__import__("datetime").timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    if not isinstance(checked_at, str) or not checked_at:
        raise VerificationError("verification timestamp is invalid")
    result = {"schema_version": 1, "result": "REGISTRATION_VERIFIED", "signing_allowed": False, "checked_at_utc": checked_at, "beacon_origin": source, "response_sha256": {"genesis": hashlib.sha256(genesis_raw).hexdigest(), "validator": hashlib.sha256(validator_raw).hexdigest()}, "genesis_validators_root": HOODI_GENESIS_ROOT, "genesis_time": HOODI_GENESIS_TIME, "validator_public_key": key, "withdrawal_credentials": credentials, "validator_index": str(index), "status": status}
    encoded = (json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n").encode()
    descriptor, temporary_name = tempfile.mkstemp(prefix=".existing-hoodi-validator-", dir=output.parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(temporary, output)
        except FileExistsError as error:
            raise VerificationError("refusing to overwrite existing registration evidence") from error
    finally:
        temporary.unlink(missing_ok=True)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--validator-public-key", required=True)
    parser.add_argument("--withdrawal-credentials", required=True)
    parser.add_argument("--beacon-url", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        verify(args.validator_public_key, args.withdrawal_credentials, args.beacon_url, args.output)
    except VerificationError as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
