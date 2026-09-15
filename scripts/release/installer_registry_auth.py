"""Portable, short-lived registry credentials for installer mirror containers."""
from __future__ import annotations

import base64
import json
import os
import re
import stat
import tempfile
from pathlib import Path


_ECR_REGISTRY = re.compile(r"^[0-9]{12}\.dkr\.ecr\.[a-z0-9-]+\.amazonaws\.com$")


class RegistryAuthError(RuntimeError):
    pass


def _private_directory(path: Path) -> None:
    try:
        info = path.lstat()
    except OSError as error:
        raise RegistryAuthError("registry auth directory is unavailable") from error
    if path.is_symlink() or not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700:
        raise RegistryAuthError("registry auth directory is unsafe")


def _load_owned(path: Path, known_registries: set[str]) -> dict[str, str]:
    if not path.exists():
        if path.is_symlink():
            raise RegistryAuthError("registry auth file is unsafe")
        if known_registries:
            raise RegistryAuthError("registry auth file disappeared")
        return {}
    if not known_registries:
        raise RegistryAuthError("registry auth file already exists")
    try:
        info = path.lstat()
        if path.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 1024 * 1024:
            raise RegistryAuthError("registry auth file is unsafe")
        value = json.loads(path.read_text())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RegistryAuthError("registry auth file is invalid") from error
    auths = value.get("auths") if isinstance(value, dict) and set(value) == {"auths"} else None
    if not isinstance(auths, dict) or set(auths) != known_registries:
        raise RegistryAuthError("registry auth file is not owned by this mirror")
    if any(not _ECR_REGISTRY.fullmatch(registry) or not isinstance(entry, dict) or set(entry) != {"auth"} or not isinstance(entry["auth"], str) for registry, entry in auths.items()):
        raise RegistryAuthError("registry auth file is invalid")
    return {registry: entry["auth"] for registry, entry in auths.items()}


def write_ecr_auth(auth_dir: Path, registry: str, password: str, known_registries: set[str]) -> None:
    """Atomically add an ECR token without invoking host credential helpers.

    ``known_registries`` is mirror-local state.  It prevents an existing config
    from being adopted or overwritten and permits bounded multi-registry merges.
    """
    _private_directory(auth_dir)
    if not _ECR_REGISTRY.fullmatch(registry) or not isinstance(password, str):
        raise RegistryAuthError("ECR registry credentials are invalid")
    if password.endswith("\r\n"):
        password = password[:-2]
    elif password.endswith("\n"):
        password = password[:-1]
    if not password:
        raise RegistryAuthError("ECR registry password is empty")
    path = auth_dir / "config.json"
    auths = _load_owned(path, known_registries)
    encoded = base64.b64encode(("AWS:" + password).encode()).decode("ascii")
    auths[registry] = encoded
    raw = (json.dumps({"auths": {name: {"auth": auths[name]} for name in sorted(auths)}}, sort_keys=True, separators=(",", ":")) + "\n").encode()
    fd, temporary = tempfile.mkstemp(prefix=".registry-auth-", dir=auth_dir)
    try:
        os.fchmod(fd, 0o600)
        handle = os.fdopen(fd, "wb")
        fd = -1
        with handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        known_registries.add(registry)
    except OSError as error:
        raise RegistryAuthError("could not atomically write registry auth") from error
    finally:
        if fd != -1:
            os.close(fd)
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
