#!/usr/bin/env python3
"""Small, local-only checkpoint store for a future interactive installer.

The on-disk format deliberately has no general-purpose metadata or output
fields.  It records only the release context and the status of named stages.
Callers must hold ``lock()`` while reading or changing state.
"""
from __future__ import annotations

import contextlib
import errno
import fcntl
import json
import os
from pathlib import Path
import re
import stat
from typing import Iterator, Mapping


SCHEMA_VERSION = 1
CONTEXT_FIELDS = frozenset({
    "release_sha", "bundle_digest", "aws_profile", "aws_account_id",
    "aws_region", "deployment_name",
})
STAGE_STATUSES = frozenset({"pending", "running", "complete", "failed", "awaiting_input"})
STAGE_NAMES = frozenset({
    "preflight", "infrastructure", "ops_access", "vault", "secrets", "gitops",
    "workloads", "custody", "deposit", "activation", "duty", "evidence",
})
_RELEASE_SHA = re.compile(r"[0-9a-f]{40}\Z")
_BUNDLE_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_PROFILE = re.compile(r"[A-Za-z0-9_.-]{1,128}\Z")
_ACCOUNT_ID = re.compile(r"[0-9]{12}\Z")
_DEPLOYMENT_NAME = re.compile(r"[a-z](?:[a-z0-9-]{1,18}[a-z0-9])?\Z")


class StateError(RuntimeError):
    """The checkpoint cannot safely be used."""


class StateLockedError(StateError):
    """Another live process owns this checkpoint's advisory lock."""


class ContextMismatchError(StateError):
    """A checkpoint belongs to a different installer invocation."""


class CheckpointStore:
    """Strict JSON state in *directory*/checkpoint.json.

    ``lock()`` uses an advisory ``flock``.  It does not examine process IDs or
    attempt stale-lock recovery: the operating system releases the lock when
    its owning process exits.  A stage marked ``running`` is always returned as
    such; reconciliation is an explicit responsibility of the future caller.
    """

    def __init__(self, directory: str | os.PathLike[str], context: Mapping[str, str]):
        self.directory = Path(directory)
        self.path = self.directory / "checkpoint.json"
        self.lock_path = self.directory / ".checkpoint.lock"
        self.context = self._validate_context(context)
        self._lock_fd: int | None = None

    @staticmethod
    def _validate_context(context: Mapping[str, str]) -> dict[str, str]:
        if set(context) != CONTEXT_FIELDS:
            raise StateError("installer context has unsupported or missing fields")
        if any(not isinstance(value, str) or not value for value in context.values()):
            raise StateError("installer context values must be non-empty strings")
        if not _RELEASE_SHA.fullmatch(context["release_sha"]):
            raise StateError("release SHA is invalid")
        if not _BUNDLE_DIGEST.fullmatch(context["bundle_digest"]):
            raise StateError("bundle digest is invalid")
        if not _PROFILE.fullmatch(context["aws_profile"]):
            raise StateError("AWS profile is invalid")
        if not _ACCOUNT_ID.fullmatch(context["aws_account_id"]):
            raise StateError("AWS account ID is invalid")
        if context["aws_region"] not in {"ap-northeast-1", "ap-northeast-2"}:
            raise StateError("AWS region is invalid")
        if not _DEPLOYMENT_NAME.fullmatch(context["deployment_name"]):
            raise StateError("deployment name is invalid")
        return {key: context[key] for key in sorted(CONTEXT_FIELDS)}

    @staticmethod
    def _regular_mode(path: Path, expected: int) -> None:
        try:
            value = os.lstat(path)
        except FileNotFoundError:
            return
        if stat.S_ISLNK(value.st_mode) or not stat.S_ISREG(value.st_mode):
            raise StateError("checkpoint path is not a regular file")
        if stat.S_IMODE(value.st_mode) != expected:
            raise StateError("checkpoint file permissions are unsafe")

    def _ensure_directory(self) -> None:
        try:
            value = os.lstat(self.directory)
        except FileNotFoundError:
            # Do not create parents implicitly; that makes the intended state
            # location explicit and lets us validate its immediate parent.
            parent = self.directory.parent
            parent_value = os.lstat(parent)
            if stat.S_ISLNK(parent_value.st_mode) or not stat.S_ISDIR(parent_value.st_mode):
                raise StateError("checkpoint parent is not a directory")
            os.mkdir(self.directory, 0o700)
            return
        if stat.S_ISLNK(value.st_mode) or not stat.S_ISDIR(value.st_mode):
            raise StateError("checkpoint directory is not a directory")
        if stat.S_IMODE(value.st_mode) != 0o700:
            raise StateError("checkpoint directory permissions are unsafe")

    def _require_lock(self) -> None:
        if self._lock_fd is None:
            raise StateError("checkpoint operation requires lock()")

    def _read_checkpoint(self) -> str:
        """Read through a no-follow descriptor, closing the check/use gap."""
        try:
            fd = os.open(self.path, os.O_RDONLY | os.O_NOFOLLOW)
        except OSError as exc:
            raise StateError("could not safely open checkpoint") from exc
        try:
            value = os.fstat(fd)
            if not stat.S_ISREG(value.st_mode) or stat.S_IMODE(value.st_mode) != 0o600:
                raise StateError("checkpoint file permissions are unsafe")
            with os.fdopen(fd, "r", encoding="utf-8") as handle:
                fd = -1
                return handle.read()
        finally:
            if fd != -1:
                os.close(fd)

    @contextlib.contextmanager
    def lock(self) -> Iterator["CheckpointStore"]:
        """Acquire the non-blocking process lock for this checkpoint."""
        if self._lock_fd is not None:
            raise StateError("checkpoint lock is already held by this store")
        self._ensure_directory()
        self._regular_mode(self.lock_path, 0o600)
        try:
            fd = os.open(self.lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        except OSError as exc:
            raise StateError("could not safely open checkpoint lock") from exc
        try:
            opened = os.fstat(fd)
            if not stat.S_ISREG(opened.st_mode):
                raise StateError("checkpoint lock is not a regular file")
            os.fchmod(fd, 0o600)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as exc:
                if exc.errno in (errno.EACCES, errno.EAGAIN):
                    raise StateLockedError("checkpoint is in use") from None
                raise StateError("could not lock checkpoint") from exc
            self._lock_fd = fd
            yield self
        finally:
            self._lock_fd = None
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            finally:
                os.close(fd)

    def _validate_state(self, data: object) -> dict[str, object]:
        if not isinstance(data, dict) or set(data) != {"schema_version", "context", "stages"}:
            raise StateError("checkpoint schema is invalid")
        if type(data["schema_version"]) is not int or data["schema_version"] != SCHEMA_VERSION:
            raise StateError("checkpoint schema version is unsupported")
        stored_context = self._validate_context(data["context"]) if isinstance(data["context"], dict) else None
        if stored_context != self.context:
            raise ContextMismatchError("checkpoint context does not match this invocation")
        stages = data["stages"]
        if not isinstance(stages, dict):
            raise StateError("checkpoint stages are invalid")
        for name, value in stages.items():
            if not isinstance(name, str) or name not in STAGE_NAMES:
                raise StateError("checkpoint stage name is invalid")
            if (not isinstance(value, dict) or set(value) != {"status"}
                    or not isinstance(value["status"], str) or value["status"] not in STAGE_STATUSES):
                raise StateError("checkpoint stage schema is invalid")
        return data

    def resume(self) -> dict[str, object]:
        """Return existing state, or atomically create an empty checkpoint."""
        self._require_lock()
        self._regular_mode(self.path, 0o600)
        if not self.path.exists():
            state: dict[str, object] = {"schema_version": SCHEMA_VERSION, "context": self.context, "stages": {}}
            self._write(state)
            return state
        try:
            raw = self._read_checkpoint()
            return self._validate_state(json.loads(raw, object_pairs_hook=self._no_duplicate_object))
        except (OSError, UnicodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
            raise StateError("checkpoint is unreadable or corrupt") from exc

    def set_stage(self, name: str, status: str) -> dict[str, object]:
        """Persist one explicit stage transition; no status is inferred."""
        self._require_lock()
        if not isinstance(name, str) or name not in STAGE_NAMES:
            raise StateError("stage name is invalid")
        if not isinstance(status, str) or status not in STAGE_STATUSES:
            raise StateError("stage status is invalid")
        state = self.resume()
        stages = state["stages"]
        assert isinstance(stages, dict)
        stages[name] = {"status": status}
        self._write(state)
        return state

    @staticmethod
    def _no_duplicate_object(pairs: list[tuple[object, object]]) -> dict[object, object]:
        result: dict[object, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON object key")
            result[key] = value
        return result

    def _write(self, state: dict[str, object]) -> None:
        self._require_lock()
        # Revalidate before persistence, including the strict no-output schema.
        self._validate_state(state)
        encoded = (json.dumps(state, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
        temporary = self.directory / ".checkpoint.json.tmp"
        self._regular_mode(temporary, 0o600)
        try:
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        except FileExistsError as exc:
            raise StateError("checkpoint temporary file already exists") from exc
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(encoded)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self.path)
            directory_fd = os.open(self.directory, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        except Exception:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass
            raise
