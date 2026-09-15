#!/usr/bin/env python3
"""Prepare and read-only verify the non-secret custody verifier runtime."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from typing import Any

COMMIT = "d8016bc8ca25d7f85e143828b6d99160f55a640f"
UPSTREAM = "https://github.com/ethstaker/ethstaker-deposit-cli.git"
PUBLIC_KEY = re.compile(r"0x[0-9a-f]{96}\Z")
RUNTIME = "custody-verifier-runtime"


class RuntimeError(Exception):
    pass


def _hash(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        raise RuntimeError()
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _clean_python_env() -> dict[str, str]:
    """Keep only path discovery; never inherit Python or pip configuration."""
    blocked = {"PYTHONHOME", "PYTHONPATH", "PYTHONSTARTUP", "PYTHONUSERBASE", "PIP_CONFIG_FILE"}
    return {key: value for key, value in os.environ.items()
            if key not in blocked and not key.startswith("PIP_")}


def _clean_git_env() -> dict[str, str]:
    return {"PATH": os.environ.get("PATH", ""), "GIT_TERMINAL_PROMPT": "0",
            "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull}


def _object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise RuntimeError()
        result[key] = value
    return result


def _read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_object_pairs)
    except (OSError, UnicodeError, ValueError) as exc:
        raise RuntimeError() from exc
    if not isinstance(value, dict):
        raise RuntimeError()
    return value


def _regular_directory(path: Path) -> None:
    if not path.is_absolute() or path.is_symlink() or not path.is_dir():
        raise RuntimeError()


def _bundle(bundle: Path) -> dict[str, str]:
    _regular_directory(bundle)
    manifest_path = bundle / "bundle-manifest.json"
    manifest = _read_json(manifest_path)
    revision = manifest.get("source_revision")
    entries = manifest.get("entries")
    if not isinstance(revision, str) or not re.fullmatch(r"[0-9a-f]{40}", revision) or not isinstance(entries, list):
        raise RuntimeError()
    expected = {
        "source/scripts/ops/verify-custody-keystore-secret.py": bundle / "source/scripts/ops/verify-custody-keystore-secret.py",
        "source/.ci/custody-verifier/source-lock.json": bundle / "source/.ci/custody-verifier/source-lock.json",
    }
    listed: dict[str, str] = {}
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {"path", "sha256", "size"}:
            raise RuntimeError()
        path, digest = entry.get("path"), entry.get("sha256")
        if not isinstance(path, str) or not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise RuntimeError()
        if path in listed:
            raise RuntimeError()
        listed[path] = digest
    values = {"bundle_manifest_sha256": _hash(manifest_path), "release_revision": revision}
    for relative, path in expected.items():
        digest = _hash(path)
        if listed.get(relative) != digest:
            raise RuntimeError()
        values[relative] = digest
    return values


def _verify_source(verifier: Path, upstream: Path) -> None:
    spec = importlib.util.spec_from_file_location("custody_source_verifier", verifier)
    if spec is None or spec.loader is None:
        raise RuntimeError()
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
        module.verify_source(upstream)
    except Exception as exc:
        raise RuntimeError() from exc


def _runtime_paths(work: Path) -> tuple[Path, Path, Path, Path]:
    _regular_directory(work)
    runtime = work / RUNTIME
    if runtime.exists() and (runtime.is_symlink() or not runtime.is_dir()):
        raise RuntimeError()
    return runtime, runtime / "upstream", runtime / "venv", runtime / "receipt.json"


def _site_packages_hash(venv: Path) -> str:
    candidates = list((venv / "lib").glob("python*/site-packages"))
    if len(candidates) != 1 or candidates[0].is_symlink() or not candidates[0].is_dir():
        raise RuntimeError()
    digest = hashlib.sha256()
    for path in sorted(candidates[0].rglob("*")):
        relative = path.relative_to(candidates[0]).as_posix()
        if path.is_symlink():
            raise RuntimeError()
        if path.is_dir():
            continue
        if not path.is_file():
            raise RuntimeError()
        digest.update(relative.encode("utf-8") + b"\0" + hashlib.sha256(path.read_bytes()).digest())
    return digest.hexdigest()


def _receipt(values: dict[str, str], public_key: str, upstream: Path, python: Path, venv: Path) -> dict[str, Any]:
    git = subprocess.run(["git", "-C", str(upstream), "rev-parse", "HEAD", "HEAD^{tree}"], capture_output=True, text=True, check=False, timeout=20, env=_clean_git_env())
    if git.returncode or git.stderr or len(git.stdout.splitlines()) != 2:
        raise RuntimeError()
    return values | {"schema_version": 1, "expected_public_key": public_key, "upstream_commit": git.stdout.splitlines()[0],
                     "upstream_tree": git.stdout.splitlines()[1], "python_sha256": _hash(python),
                     "site_packages_sha256": _site_packages_hash(venv)}


def _verify(work: Path, bundle: Path, public_key: str) -> dict[str, str]:
    values = _bundle(bundle)
    runtime, upstream, venv, receipt_path = _runtime_paths(work)
    receipt = _read_json(receipt_path)
    python = venv / "bin/python"
    expected = _receipt(values, public_key, upstream, python, venv)
    if receipt != expected:
        raise RuntimeError()
    verifier = bundle / "source/scripts/ops/verify-custody-keystore-secret.py"
    _verify_source(verifier, upstream)
    check = subprocess.run([str(python), "-I", "-B", "-c", "import sys; sys.path.insert(0, sys.argv[1]); from ethstaker_deposit.key_handling.keystore import Keystore; from py_ecc.bls import G2ProofOfPossession", str(upstream)], capture_output=True, text=True, check=False, timeout=30, env=_clean_python_env())
    if check.returncode or check.stdout or check.stderr:
        raise RuntimeError()
    return {"python": str(python), "upstream_root": str(upstream), "receipt": str(receipt_path)}


def prepare(work: Path, bundle: Path, public_key: str) -> dict[str, str]:
    values = _bundle(bundle)
    runtime, upstream, venv, receipt = _runtime_paths(work)
    if receipt.exists():
        return _verify(work, bundle, public_key)
    runtime.mkdir(mode=0o700, exist_ok=True)
    if not upstream.exists():
        subprocess.run(["git", "clone", "--no-checkout", UPSTREAM, str(upstream)], check=True, capture_output=True, text=True, timeout=300, env=_clean_git_env())
    _regular_directory(upstream)
    subprocess.run(["git", "-C", str(upstream), "checkout", "--detach", COMMIT], check=True, capture_output=True, text=True, timeout=60, env=_clean_git_env())
    verifier = bundle / "source/scripts/ops/verify-custody-keystore-secret.py"
    _verify_source(verifier, upstream)
    subprocess.run([sys.executable, "-I", "-m", "venv", "--copies", str(venv)], check=True, timeout=120, env=_clean_python_env())
    python = venv / "bin/python"
    subprocess.run([str(python), "-I", "-m", "pip", "install", "--disable-pip-version-check", "--no-input", "--require-hashes", "-r", str(upstream / "requirements.txt")], check=True, timeout=900, env=_clean_python_env())
    result = _receipt(values, public_key, upstream, python, venv)
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=runtime, prefix=".receipt.", delete=False) as handle:
        json.dump(result, handle, sort_keys=True, separators=(",", ":")); handle.write("\n")
        temporary = Path(handle.name)
    temporary.chmod(0o600)
    os.replace(temporary, receipt)
    return _verify(work, bundle, public_key)


def main() -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("operation", choices=("prepare", "verify"))
    parser.add_argument("--work-dir", required=True)
    parser.add_argument("--bundle-root", required=True)
    parser.add_argument("--expected-public-key", required=True)
    args = parser.parse_args()
    try:
        public_key = args.expected_public_key.lower()
        if not PUBLIC_KEY.fullmatch(public_key):
            raise RuntimeError()
        work, bundle = Path(args.work_dir), Path(args.bundle_root)
        result = prepare(work, bundle, public_key) if args.operation == "prepare" else _verify(work, bundle, public_key)
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return 0
    except (RuntimeError, OSError, subprocess.SubprocessError, ValueError):
        print("custody verifier runtime preflight failed", file=sys.stderr)
        return 65


if __name__ == "__main__":
    raise SystemExit(main())
