#!/usr/bin/env python3
"""Private, local replay state for the platform bootstrap ceremony.

This only protects local orchestration state.  It does not attest Terraform,
AWS, CodeBuild, or Vault outcomes.
"""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

MAX = 64 * 1024
PHASES = ("argocd_apply", "argocd_build", "tls_ready", "vault_apply", "vault_build", "revoke_complete")


class ReplayError(RuntimeError):
    pass


def _pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    out: dict[str, object] = {}
    for key, value in pairs:
        if key in out:
            raise ValueError("duplicate JSON key")
        out[key] = value
    return out


def _private(path: Path, directory: bool) -> None:
    try:
        info = path.lstat()
    except OSError as error:
        raise ReplayError("platform replay path is unavailable or unsafe") from error
    if path.is_symlink() or stat.S_IMODE(info.st_mode) != (0o700 if directory else 0o600):
        raise ReplayError("platform replay path is unavailable or unsafe")
    if not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)):
        raise ReplayError("platform replay path is unavailable or unsafe")


def _root(work: Path) -> Path:
    if not work.is_absolute() or Path(os.path.normpath(str(work))) != work:
        raise ReplayError("platform work directory must be normalized and absolute")
    _private(work, True)
    macos_aliases = {Path("/private"): Path("/private"), Path("/var"): Path("/private/var"), Path("/tmp"): Path("/private/tmp")}
    for parent in work.parents:
        # /tmp and /var are macOS system aliases.  Linux treats /tmp as an
        # ordinary directory, so it must use the normal ancestry checks.
        if sys.platform == "darwin" and parent in macos_aliases:
            try:
                info = parent.lstat()
                if parent.resolve() != macos_aliases[parent]:
                    raise ReplayError("platform work directory ancestry is unsafe")
                if parent == Path("/private"):
                    if parent.is_symlink() or not stat.S_ISDIR(info.st_mode):
                        raise ReplayError("platform work directory ancestry is unsafe")
                elif not parent.is_symlink():
                    raise ReplayError("platform work directory ancestry is unsafe")
            except OSError as error:
                raise ReplayError("platform work directory ancestry is unsafe") from error
            continue
        try:
            info = parent.lstat()
        except OSError as error:
            raise ReplayError("platform work directory ancestry is unsafe") from error
        if parent.is_symlink() or not stat.S_ISDIR(info.st_mode):
            raise ReplayError("platform work directory ancestry is unsafe")
    root = work / "platform-bootstrap-replay"
    if root.exists() or root.is_symlink():
        _private(root, True)
    else:
        root.mkdir(mode=0o700)
    return root


def _read(path: Path) -> bytes:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError as error:
        raise ReplayError("platform replay input is unavailable or unsafe") from error
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX:
            raise ReplayError("platform replay input is unavailable or unsafe")
        data = os.read(fd, MAX + 1)
        if len(data) > MAX:
            raise ReplayError("platform replay input is unavailable or unsafe")
        return data
    finally:
        os.close(fd)


def _json(path: Path) -> dict[str, object]:
    _private(path, False)
    try:
        value = json.loads(_read(path), object_pairs_hook=_pairs)
    except (UnicodeDecodeError, ValueError, ReplayError) as error:
        raise ReplayError("platform replay checkpoint is malformed") from error
    if not isinstance(value, dict):
        raise ReplayError("platform replay checkpoint is malformed")
    return value


def _publish(path: Path, value: object, replace: bool = False) -> None:
    if path.exists() or path.is_symlink():
        if not replace:
            raise ReplayError("platform replay output already exists")
        _private(path, False)
    fd, temporary = tempfile.mkstemp(prefix=".platform-replay-", dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w") as handle:
            json.dump(value, handle, sort_keys=True, separators=(",", ":"))
            handle.flush()
            os.fsync(handle.fileno())
        if replace:
            os.replace(temporary, path)
        else:
            os.link(temporary, path)
    except OSError as error:
        raise ReplayError("platform replay output could not be persisted") from error
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def _bound(path: Path) -> dict[str, str]:
    data = _read(path)
    return {"path": str(path), "sha256": hashlib.sha256(data).hexdigest()}


def _context(args: argparse.Namespace) -> dict[str, object]:
    if not (args.account.isdigit() and len(args.account) == 12 and args.region and args.deployment):
        raise ReplayError("platform replay identity is invalid")
    files = {name: _bound(Path(path)) for name, path in (
        ("baseline", args.baseline_config), ("session", args.session),
        ("argocd_input", args.argocd_input), ("vault_input", args.vault_input),
        ("vault_overlay", args.vault_overlay),
    )}
    return {"schema_version": 1, "work_dir": str(Path(args.work_dir)), "account": args.account, "region": args.region,
            "deployment": args.deployment, "files": files, "phases": {}}


def _validate_context(root: Path, candidate: dict[str, object] | None = None, state: dict[str, object] | None = None) -> dict[str, object]:
    state = _json(root / "checkpoint.json") if state is None else state
    required = {"schema_version", "work_dir", "account", "region", "deployment", "files", "phases"}
    if set(state) != required or state.get("schema_version") != 1 or not isinstance(state.get("files"), dict) or not isinstance(state.get("phases"), dict):
        raise ReplayError("platform replay checkpoint is malformed")
    if candidate is not None and {k: state[k] for k in required if k != "phases"} != {k: candidate[k] for k in required if k != "phases"}:
        raise ReplayError("platform replay checkpoint does not bind current selected inputs")
    expected_files = {"baseline", "session", "argocd_input", "vault_input", "vault_overlay"}
    if set(state["files"]) != expected_files or state["work_dir"] != str(root.parent):
        raise ReplayError("platform replay checkpoint is malformed")
    for name, entry in state["files"].items():
        if not isinstance(entry, dict) or set(entry) != {"path", "sha256"} or not isinstance(entry["path"], str) or not isinstance(entry["sha256"], str):
            raise ReplayError("platform replay checkpoint is malformed")
        source = Path(entry["path"])
        if not source.is_absolute() or Path(os.path.normpath(str(source))) != source:
            raise ReplayError("platform replay checkpoint is malformed")
        if name in {"argocd_input", "vault_input", "vault_overlay"} and source != root.parent / "platform-bootstrap-inputs" / {"argocd_input":"argocd.tfvars.json", "vault_input":"vault.tfvars.json", "vault_overlay":"vault-image-overrides.json"}[name]:
            raise ReplayError("platform replay checkpoint is malformed")
        if name in {"argocd_input", "vault_input", "vault_overlay"}:
            _private(source, False)
        if name in {"baseline", "session"}:
            try: source.relative_to(root.parent.parent)
            except ValueError as error: raise ReplayError("platform replay checkpoint is malformed") from error
        if _bound(Path(entry["path"])) != entry:
            raise ReplayError("platform replay input changed since the checkpoint")
    if any(not isinstance(phase, str) or phase not in PHASES for phase in state["phases"]):
        raise ReplayError("platform replay checkpoint is malformed")
    for index, phase in enumerate(PHASES):
        status = state["phases"].get(phase)
        if status not in ("intent", "complete"):
            if status is not None:
                raise ReplayError("platform replay checkpoint is malformed")
        if status is not None and any(state["phases"].get(previous) != "complete" for previous in PHASES[:index]):
            raise ReplayError("platform replay checkpoint has an invalid phase order")
    return state


def initialize(args: argparse.Namespace) -> None:
    root = _root(Path(args.work_dir)); candidate = _context(args); path = root / "checkpoint.json"
    if path.exists() or path.is_symlink():
        _validate_context(root, candidate)
    else:
        _validate_context(root, candidate, candidate)
        _publish(path, candidate)


def phase(args: argparse.Namespace) -> None:
    root = _root(Path(args.work_dir)); state = _validate_context(root); phases = state["phases"]
    if args.phase not in PHASES:
        raise ReplayError("platform replay phase is invalid")
    current = phases.get(args.phase)
    if args.action == "get":
        print(current or "new")
        return
    if args.action == "intent":
        if current == "complete":
            print("complete")
            return
        index = PHASES.index(args.phase)
        if any(phases.get(previous) != "complete" for previous in PHASES[:index]):
            raise ReplayError("platform replay phase predecessor is incomplete")
        phases[args.phase] = "intent"
    elif args.action == "complete":
        if current != "intent":
            raise ReplayError("platform replay phase was not started")
        phases[args.phase] = "complete"
    else:
        raise ReplayError("platform replay action is invalid")
    _publish(root / "checkpoint.json", state, replace=True)


def materialize(args: argparse.Namespace) -> None:
    output = Path(args.output)
    if not output.is_absolute() or Path(os.path.normpath(str(output))) != output:
        raise ReplayError("platform input output must be normalized and absolute")
    data = sys.stdin.buffer.read(MAX + 1)
    if len(data) > MAX:
        raise ReplayError("platform input is too large")
    try:
        info = output.parent.lstat()
    except OSError as error:
        raise ReplayError("platform input directory is unavailable") from error
    if output.parent.is_symlink() or not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700:
        raise ReplayError("platform input directory is unavailable")
    if output.exists() or output.is_symlink():
        _private(output, False)
        if _read(output) != data:
            raise ReplayError("platform input differs from the bound checkpoint candidate")
        return
    fd, temporary = tempfile.mkstemp(prefix=".platform-input-", dir=output.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(data); handle.flush(); os.fsync(handle.fileno())
        os.link(temporary, output)
    except OSError as error:
        raise ReplayError("platform input could not be persisted") from error
    finally:
        try: os.unlink(temporary)
        except FileNotFoundError: pass


def directory(args: argparse.Namespace) -> None:
    path = Path(args.path)
    if not path.is_absolute() or Path(os.path.normpath(str(path))) != path:
        raise ReplayError("platform private directory path is invalid")
    if path.exists() or path.is_symlink():
        _private(path, True)
    else:
        try: path.mkdir(mode=0o700)
        except OSError as error: raise ReplayError("platform private directory is unavailable") from error


def discard(args: argparse.Namespace) -> None:
    path = Path(args.path)
    _private(path.parent, True)
    if path.exists() or path.is_symlink():
        _private(path, False)
        try: path.unlink()
        except OSError as error: raise ReplayError("platform stale plan cannot be removed safely") from error


def lock(args: argparse.Namespace) -> None:
    root = _root(Path(args.work_dir)); path = root / ".platform.lock"
    fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600:
            raise ReplayError("platform replay lock is unsafe")
        try: fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error: raise ReplayError("another platform replay holds the whole-platform lock") from error
        env = os.environ.copy(); env["PLATFORM_REPLAY_LOCK_FD"] = str(fd)
        command = args.command[1:] if args.command[:1] == ["--"] else args.command
        try:
            child = subprocess.Popen(command, pass_fds=(fd,), env=env)
        except OSError as error:
            raise ReplayError("platform replay child could not be started") from error
        result = child.wait()
        raise SystemExit(result)
    finally:
        # Closing our descriptor preserves an inherited kernel flock while a
        # child survives an interrupted supervisor; the final child close
        # releases it without a stale-lock deletion protocol.
        os.close(fd)


def assert_lock(args: argparse.Namespace) -> None:
    root = _root(Path(args.work_dir)); path = root / ".platform.lock"
    try:
        fd = int(args.fd)
        opened = os.fstat(fd); expected = path.lstat()
    except (OSError, ValueError) as error:
        raise ReplayError("platform replay lock inheritance is invalid") from error
    if not stat.S_ISREG(opened.st_mode) or stat.S_IMODE(opened.st_mode) != 0o600 or (opened.st_dev, opened.st_ino) != (expected.st_dev, expected.st_ino):
        raise ReplayError("platform replay lock inheritance is invalid")
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as error:
        raise ReplayError("platform replay lock inheritance is invalid") from error


def main() -> int:
    parser = argparse.ArgumentParser(); sub = parser.add_subparsers(dest="operation", required=True)
    init = sub.add_parser("initialize")
    for option in ("work_dir", "account", "region", "deployment", "baseline_config", "session", "argocd_input", "vault_input", "vault_overlay"):
        init.add_argument("--" + option.replace("_", "-"), required=True)
    step = sub.add_parser("phase"); step.add_argument("--work-dir", required=True); step.add_argument("--phase", required=True); step.add_argument("--action", choices=("get", "intent", "complete"), required=True)
    write = sub.add_parser("materialize"); write.add_argument("--output", required=True)
    private_dir = sub.add_parser("directory"); private_dir.add_argument("--path", required=True)
    remove = sub.add_parser("discard"); remove.add_argument("--path", required=True)
    hold = sub.add_parser("lock"); hold.add_argument("--work-dir", required=True); hold.add_argument("child", nargs=argparse.REMAINDER)
    inherited = sub.add_parser("assert-lock"); inherited.add_argument("--work-dir", required=True); inherited.add_argument("--fd", required=True)
    args = parser.parse_args()
    try:
        if args.operation == "initialize": initialize(args)
        elif args.operation == "phase": phase(args)
        elif args.operation == "materialize": materialize(args)
        elif args.operation == "directory": directory(args)
        elif args.operation == "discard": discard(args)
        elif args.operation == "assert-lock": assert_lock(args)
        else:
            if not args.child: raise ReplayError("missing platform command")
            args.command = args.child
            lock(args)
    except ReplayError as error:
        print(str(error), file=sys.stderr); return 65
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
