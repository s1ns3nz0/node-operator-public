#!/usr/bin/env python3
"""Create the private, release-bound installer artifact index.

This is deliberately an offline staging step.  It neither mirrors nor publishes
anything, and it records no account-specific destination registry information.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import stat
import tempfile
from typing import Any

SHA40 = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
IMAGE = re.compile(r"^[a-z0-9][a-z0-9._/-]*@sha256:[0-9a-f]{64}$")
MAX_JSON = 4 * 1024 * 1024


class ArtifactIndexError(ValueError):
    pass


def _duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ArtifactIndexError("duplicate JSON object key")
        result[key] = value
    return result


def _json_file(path: Path) -> Any:
    try:
        info = path.lstat()
    except OSError as error:
        raise ArtifactIndexError(f"cannot inspect {path}: {error}") from error
    if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_JSON:
        raise ArtifactIndexError(f"unsafe or oversized JSON input: {path}")
    try:
        raw = path.read_bytes()
        return json.loads(raw.decode("utf-8"), object_pairs_hook=_duplicates)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ArtifactIndexError) as error:
        raise ArtifactIndexError(f"invalid JSON input {path}: {error}") from error


def _exact(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise ArtifactIndexError(f"{label} has an unexpected schema")
    return value


def _text(value: Any, label: str, pattern: re.Pattern[str] | None = None) -> str:
    if not isinstance(value, str) or not value or (pattern is not None and not pattern.fullmatch(value)):
        raise ArtifactIndexError(f"{label} is invalid")
    return value


def _record(path: Path, component: str, release_sha: str, method: str) -> dict[str, Any]:
    value = _exact(_json_file(path), {"schema_version", "component", "kind", "release_revision", "build_revision", "third_party_source_revision", "image_ref", "manifest_digest", "input_sha256", "publication", "verification"}, "publication record")
    if value["schema_version"] != 1 or value["component"] != component or value["kind"] != "image":
        raise ArtifactIndexError("publication record identity is invalid")
    if _text(value["release_revision"], "record release revision", SHA40) != release_sha:
        raise ArtifactIndexError("publication record release revision does not match requested release")
    _text(value["build_revision"], "record build revision", SHA40)
    if value["third_party_source_revision"] is not None:
        raise ArtifactIndexError("first-party record has third-party source revision")
    image_ref = _text(value["image_ref"], "record image reference", IMAGE)
    digest = _text(value["manifest_digest"], "record manifest digest", DIGEST)
    if image_ref.rsplit("@", 1)[1] != digest:
        raise ArtifactIndexError("record image reference and manifest digest differ")
    _text(value["input_sha256"], "record input hash", SHA256)
    publication = _exact(value["publication"], {"workflow", "run_id", "invocation"}, "record publication")
    _text(publication["workflow"], "record workflow")
    _text(publication["invocation"], "record invocation")
    if not isinstance(publication["run_id"], (str, int)) or isinstance(publication["run_id"], bool) or not str(publication["run_id"]).isdigit():
        raise ArtifactIndexError("record publication run id is invalid")
    verification = _exact(value["verification"], {"method", "status"}, "record verification")
    if verification != {"method": method, "status": "passed"}:
        raise ArtifactIndexError("record verification is not the required passed method")
    return value


def _catalog_image(catalog: dict[str, Any], component: str, prefix: str) -> dict[str, Any]:
    matches = [item for item in catalog.get("artifacts", []) if isinstance(item, dict) and isinstance(item.get("source"), str) and item["source"].startswith(prefix)]
    if len(matches) != 1:
        raise ArtifactIndexError(f"catalog selection for {component} is ambiguous or missing")
    item = _exact(matches[0], {"source", "destination", "ecrTag", "purpose"}, f"catalog image {component}")
    image_ref = _text(item["source"], f"catalog image {component} source", IMAGE)
    digest = image_ref.rsplit("@", 1)[1]
    if item["ecrTag"] in {"latest", "last"} or not isinstance(item["destination"], str) or not item["destination"]:
        raise ArtifactIndexError(f"catalog image {component} has unsafe destination or tag")
    return {"kind": "image", "image_ref": image_ref, "manifest_digest": digest, "destination": item["destination"], "tag": item["ecrTag"]}


def _catalog_chart(catalog: dict[str, Any], component: str, name: str) -> dict[str, Any]:
    matches = [item for item in catalog.get("helm_archives", []) if isinstance(item, dict) and item.get("name") == name]
    if len(matches) != 1:
        raise ArtifactIndexError(f"catalog selection for {component} is ambiguous or missing")
    item = _exact(matches[0], {"name", "version", "source", "sha256", "ecrManifestDigest", "destination", "ecrTag", "purpose"}, f"catalog chart {component}")
    if not isinstance(item["source"], str) or not item["source"].startswith("https://") or not SHA256.fullmatch(item["sha256"]) or not DIGEST.fullmatch(item["ecrManifestDigest"]):
        raise ArtifactIndexError(f"catalog chart {component} is invalid")
    if not all(isinstance(item[key], str) and item[key] for key in ("version", "destination", "ecrTag")) or item["ecrTag"] in {"latest", "last"}:
        raise ArtifactIndexError(f"catalog chart {component} has unsafe destination or tag")
    return {"kind": "helm-chart", "approved_url": item["source"], "archive_sha256": item["sha256"], "expected_oci_manifest_digest": item["ecrManifestDigest"], "version": item["version"], "destination": item["destination"], "tag": item["ecrTag"]}


def build_index(release_sha: str, catalog_path: Path, bootstrap_path: Path, relay_path: Path, gitops_oci_mirror_path: Path) -> dict[str, Any]:
    if not SHA40.fullmatch(release_sha):
        raise ArtifactIndexError("release SHA must be an exact lowercase 40-hex revision")
    catalog = _exact(_json_file(catalog_path), {"version", "helm_archives", "artifacts"}, "approved catalog")
    if catalog["version"] != 1 or not isinstance(catalog["helm_archives"], list) or not isinstance(catalog["artifacts"], list):
        raise ArtifactIndexError("approved catalog is invalid")
    bootstrap = _record(bootstrap_path, "vault-bootstrap", release_sha, "input-hash-and-registry-digest")
    relay = _record(relay_path, "vault-audit-relay", release_sha, "cosign-and-slsa")
    gitops_oci_mirror = _record(gitops_oci_mirror_path, "gitops-oci-mirror", release_sha, "input-hash-and-registry-digest")
    components = {
        "vault-bootstrap": {"kind": "image", "build_revision": bootstrap["build_revision"], "third_party_source_revision": bootstrap["third_party_source_revision"], "image_ref": bootstrap["image_ref"], "manifest_digest": bootstrap["manifest_digest"], "input_sha256": bootstrap["input_sha256"], "publication": bootstrap["publication"], "verification": bootstrap["verification"]},
        "vault-audit-relay": {"kind": "image", "build_revision": relay["build_revision"], "third_party_source_revision": relay["third_party_source_revision"], "image_ref": relay["image_ref"], "manifest_digest": relay["manifest_digest"], "input_sha256": relay["input_sha256"], "publication": relay["publication"], "verification": relay["verification"]},
        "gitops-oci-mirror": {"kind": "image", "build_revision": gitops_oci_mirror["build_revision"], "third_party_source_revision": gitops_oci_mirror["third_party_source_revision"], "image_ref": gitops_oci_mirror["image_ref"], "manifest_digest": gitops_oci_mirror["manifest_digest"], "input_sha256": gitops_oci_mirror["input_sha256"], "publication": gitops_oci_mirror["publication"], "verification": gitops_oci_mirror["verification"]},
        "vault-server": _catalog_image(catalog, "vault-server", "docker.io/hashicorp/vault@"),
        "vault-injector": _catalog_image(catalog, "vault-injector", "docker.io/hashicorp/vault-k8s@"),
        "cert-manager-controller": _catalog_image(catalog, "cert-manager-controller", "quay.io/jetstack/cert-manager-controller@"),
        "cert-manager-webhook": _catalog_image(catalog, "cert-manager-webhook", "quay.io/jetstack/cert-manager-webhook@"),
        "cert-manager-cainjector": _catalog_image(catalog, "cert-manager-cainjector", "quay.io/jetstack/cert-manager-cainjector@"),
        "cert-manager-startupapicheck": _catalog_image(catalog, "cert-manager-startupapicheck", "quay.io/jetstack/cert-manager-startupapicheck@"),
        "vault-chart": _catalog_chart(catalog, "vault-chart", "vault"),
        "cert-manager-chart": _catalog_chart(catalog, "cert-manager-chart", "cert-manager"),
    }
    return {"schema_version": 1, "release_revision": release_sha, "components": components}


def _publish(output: Path, value: dict[str, Any]) -> None:
    if not output.is_absolute() or output.name != "installer-artifact-index.json":
        raise ArtifactIndexError("output must be an absolute installer-artifact-index.json path")
    parent = output.parent
    try:
        mode = parent.lstat().st_mode
    except OSError as error:
        raise ArtifactIndexError("output parent must already exist") from error
    if parent.is_symlink() or not stat.S_ISDIR(mode) or stat.S_IMODE(mode) != 0o700:
        raise ArtifactIndexError("output parent must be a non-symlink private 0700 directory")
    if output.exists() or output.is_symlink():
        raise ArtifactIndexError("refusing to overwrite artifact index")
    encoded = (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")
    fd, temporary = tempfile.mkstemp(prefix=".installer-artifact-index-", dir=parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(temporary, output)
        except FileExistsError as error:
            raise ArtifactIndexError("refusing to overwrite artifact index") from error
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release-sha", required=True)
    parser.add_argument("--approved-catalog", required=True, type=Path)
    parser.add_argument("--vault-bootstrap-record", required=True, type=Path)
    parser.add_argument("--audit-relay-record", required=True, type=Path)
    parser.add_argument("--gitops-oci-mirror-record", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        _publish(args.output, build_index(args.release_sha, args.approved_catalog, args.vault_bootstrap_record, args.audit_relay_record, args.gitops_oci_mirror_record))
    except ArtifactIndexError as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    main()
