#!/usr/bin/env python3
"""Render the digest-bound Vault Helm image overlay from reviewed authority."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import stat
import tempfile
from typing import Any


_ACCOUNT = re.compile(r"^[0-9]{12}$")
_REGION = re.compile(r"^[a-z]{2}-[a-z0-9-]+-[0-9]+$")
_DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
_PRIVATE = re.compile(r"^[0-9]{12}\.dkr\.ecr\.[a-z]{2}-[a-z0-9-]+-[0-9]+\.amazonaws\.com/[a-z0-9][a-z0-9._/-]*@sha256:[a-f0-9]{64}$")
_MAX_EXISTING_OVERLAY_BYTES = 64 * 1024
_SYSTEM_SYMLINKS = {Path("/var"): "/private/var", Path("/tmp"): "/private/tmp"}


class RenderError(ValueError):
    pass


def _load_catalog(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RenderError("approved Vault catalog cannot be read") from error
    if not isinstance(data, dict) or set(data) != {"version", "helm_archives", "artifacts"} or data.get("version") != 1:
        raise RenderError("approved Vault catalog schema is invalid")
    return data


def _catalog_image(catalog: dict[str, Any], source_prefix: str, purpose: str) -> tuple[str, str]:
    matches = [item for item in catalog["artifacts"] if isinstance(item, dict) and item.get("source", "").startswith(source_prefix)]
    if len(matches) != 1:
        raise RenderError(f"approved {purpose} source is missing or ambiguous")
    item = matches[0]
    if set(item) != {"source", "destination", "ecrTag", "purpose"} or item.get("destination") != "vault":
        raise RenderError(f"approved {purpose} source schema is invalid")
    source = item["source"]
    digest = source.rsplit("@", 1)[-1] if isinstance(source, str) else ""
    if not _DIGEST.fullmatch(digest) or item.get("ecrTag") != digest.removeprefix("sha256:"):
        raise RenderError(f"approved {purpose} source is not digest/tag bound")
    return source, digest


def _require_image(value: str, repository: str, digest: str, label: str) -> None:
    if not isinstance(value, str) or not _PRIVATE.fullmatch(value) or value != f"{repository}@{digest}":
        raise RenderError(f"{label} does not equal its approved private digest reference")


def render(catalog_path: Path, account: str, region: str, vault_repository: str,
           server_image: str, agent_image: str, injector_image: str) -> dict[str, Any]:
    """Return the JSON-as-YAML Helm overlay for the three Vault chart images."""
    if not _ACCOUNT.fullmatch(account) or not _REGION.fullmatch(region):
        raise RenderError("account or Region is invalid")
    expected_repository = f"{account}.dkr.ecr.{region}.amazonaws.com/"
    if not isinstance(vault_repository, str) or not vault_repository.startswith(expected_repository) or "@" in vault_repository:
        raise RenderError("Vault repository is not in the selected private registry")
    catalog = _load_catalog(catalog_path)
    _, vault_digest = _catalog_image(catalog, "docker.io/hashicorp/vault@", "Vault server")
    _, injector_digest = _catalog_image(catalog, "docker.io/hashicorp/vault-k8s@", "Vault injector")
    _require_image(server_image, vault_repository, vault_digest, "Vault server image")
    _require_image(agent_image, vault_repository, vault_digest, "Vault agent image")
    _require_image(injector_image, vault_repository, injector_digest, "Vault injector image")
    def image(digest: str) -> dict[str, str]:
        return {"repository": vault_repository, "tag": f"{digest.removeprefix('sha256:')}@{digest}"}
    return {"server": {"image": image(vault_digest)}, "injector": {"agentImage": image(vault_digest), "image": image(injector_digest)}}


def _has_symlink_ancestor(path: Path, *, lstat=os.lstat, readlink=os.readlink) -> bool:
    """Reject a symlink at any component used to reach a reusable output."""
    current = path.parent
    while True:
        try:
            info = lstat(current)
            if stat.S_ISLNK(info.st_mode):
                # macOS exposes these two stable system aliases.  They are
                # not caller-selected indirections, but any other link in
                # the path (including under a private work directory) is.
                expected = _SYSTEM_SYMLINKS.get(current)
                target = readlink(current)
                resolved_target = os.path.normpath(
                    target if os.path.isabs(target) else os.path.join(current.parent, target)
                )
                if expected != resolved_target:
                    return True
        except OSError:
            return True
        if current == current.parent:
            return False
        current = current.parent


def _private_output_parent(path: Path) -> None:
    if not path.is_absolute() or _has_symlink_ancestor(path):
        raise RenderError("Vault overlay output must use a physical private directory")
    try:
        info = path.parent.lstat()
    except OSError as error:
        raise RenderError("Vault overlay output directory is unavailable") from error
    if not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) & 0o077:
        raise RenderError("Vault overlay output must be in a private directory")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise RenderError("existing Vault overlay has duplicate JSON keys")
        result[key] = value
    return result


def _same_value(actual: Any, expected: Any) -> bool:
    """JSON equality with types and exact object keys preserved."""
    if type(actual) is not type(expected):
        return False
    if isinstance(expected, dict):
        return set(actual) == set(expected) and all(
            _same_value(actual[key], expected[key]) for key in expected
        )
    if isinstance(expected, list):
        return len(actual) == len(expected) and all(
            _same_value(item, expected[index]) for index, item in enumerate(actual)
        )
    return actual == expected


def _reuse_identical(path: Path, value: dict[str, Any]) -> None:
    _private_output_parent(path)
    try:
        before = path.lstat()
    except OSError as error:
        raise RenderError("existing Vault overlay is unavailable") from error
    if not stat.S_ISREG(before.st_mode) or stat.S_IMODE(before.st_mode) & 0o077:
        raise RenderError("existing Vault overlay must be a private regular file")
    try:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(path, flags)
        try:
            opened = os.fstat(fd)
            if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
                raise RenderError("existing Vault overlay changed while being checked")
            data = os.read(fd, _MAX_EXISTING_OVERLAY_BYTES + 1)
            if len(data) > _MAX_EXISTING_OVERLAY_BYTES:
                raise RenderError("existing Vault overlay exceeds the reuse size limit")
        finally:
            os.close(fd)
        parsed = json.loads(data.decode("utf-8"), object_pairs_hook=_unique_object)
    except RenderError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RenderError("existing Vault overlay is not safe JSON") from error
    if not _same_value(parsed, value):
        raise RenderError("existing Vault overlay differs from the canonical approved value")


def _publish(path: Path, value: dict[str, Any], *, reuse_identical: bool = False) -> None:
    _private_output_parent(path)
    if os.path.lexists(path):
        if reuse_identical:
            _reuse_identical(path, value)
            return
        raise RenderError("Vault overlay output must be a new file in a private directory")
    fd, temporary = tempfile.mkstemp(prefix=".vault-image-overlay-", dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as output:
            output.write((json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode())
            output.flush()
            os.fsync(output.fileno())
        os.link(temporary, path)
    except OSError as error:
        raise RenderError("Vault overlay could not be published safely") from error
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Render the canonical digest-bound Vault Helm image overlay."
    )
    parser.add_argument("--approved-catalog", required=True, type=Path,
                        help="path to the reviewed approved-artifacts JSON catalog")
    parser.add_argument("--account", required=True,
                        help="selected 12-digit AWS account")
    parser.add_argument("--region", required=True,
                        help="selected AWS Region")
    parser.add_argument("--vault-repository", required=True,
                        help="selected private ECR Vault repository, without @digest")
    parser.add_argument("--server-image", required=True,
                        help="exact approved private Vault server image@sha256 reference")
    parser.add_argument("--agent-image", required=True,
                        help="exact approved private Vault agent image@sha256 reference")
    parser.add_argument("--injector-image", required=True,
                        help="exact approved private Vault injector image@sha256 reference")
    parser.add_argument("--output", required=True, type=Path,
                        help="absolute output in a private directory; existing output is rejected by default")
    parser.add_argument("--reuse-identical", action="store_true",
                        help="allow existing private output only if structurally identical JSON; preserve its bytes and inode, reject mismatch")
    args = parser.parse_args()
    try:
        _publish(args.output, render(args.approved_catalog, args.account, args.region, args.vault_repository,
                                     args.server_image, args.agent_image, args.injector_image),
                 reuse_identical=args.reuse_identical)
    except RenderError as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
