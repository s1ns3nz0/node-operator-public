"""Validate the local authority chain for mirrored installer artifacts.

The baseline output is the source of destination-repository ownership. This
module only verifies that a fresh baseline binds receipt destinations to the
selected account and region; it does not establish ECR ownership itself.
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any

from installer_artifact_mirror import NAMES

SHA40 = re.compile(r"^[0-9a-f]{40}$")
DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
IMAGE = re.compile(r"^[a-z0-9][a-z0-9._/-]*@sha256:[a-f0-9]{64}$")
VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
CERT_MANAGER_VERSION = re.compile(r"^v?[0-9]+\.[0-9]+\.[0-9]+$")
TAG = re.compile(r"^[A-Za-z0-9._-]+$")
REPOSITORY = re.compile(r"^[a-z0-9]+(?:[._/-][a-z0-9]+)*$")
IMAGE_COMPONENTS = {"vault-bootstrap", "vault-audit-relay", "gitops-oci-mirror", "vault-server", "vault-injector", "cert-manager-controller", "cert-manager-webhook", "cert-manager-cainjector", "cert-manager-startupapicheck"}
CHART_COMPONENTS = {"vault-chart", "cert-manager-chart"}
RECEIPT_COMPONENTS = NAMES - {"gitops-oci-mirror"}
REPOSITORY_KEYS = {"vault", "vault_chart", "cert_manager", "cert_manager_chart"}
FIRST_PARTY_METHODS = {"vault-bootstrap": "input-hash-and-registry-digest", "vault-audit-relay": "cosign-and-slsa", "gitops-oci-mirror": "input-hash-and-registry-digest"}


class ReceiptError(ValueError):
    """A release index, mirror receipt, or destination binding is invalid."""


def validate_chart_version(name: str, version: Any) -> str:
    """Return an exact approved chart version without rewriting publisher syntax."""
    pattern = CERT_MANAGER_VERSION if name == "cert-manager-chart" else VERSION
    return _text(version, f"{name} version", pattern)


def _duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ReceiptError("duplicate JSON object key")
        value[key] = item
    return value


def _exact(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise ReceiptError(f"{label} has an unexpected schema")
    return value


def _text(value: Any, label: str, pattern: re.Pattern[str] | None = None) -> str:
    if not isinstance(value, str) or not value or (pattern and not pattern.fullmatch(value)):
        raise ReceiptError(f"{label} is invalid")
    return value


def _output(baseline: Any, key: str) -> Any:
    item = baseline.get(key) if isinstance(baseline, dict) else None
    if not isinstance(item, dict) or item.get("sensitive") is not False or "value" not in item:
        raise ReceiptError(f"baseline output {key} is unavailable")
    return item["value"]


def _ecr_repository(value: Any, account: str, region: str, label: str) -> str:
    repository = _text(value, label)
    prefix = f"{account}.dkr.ecr.{region}.amazonaws.com/"
    if not repository.startswith(prefix) or not REPOSITORY.fullmatch(repository[len(prefix):]):
        raise ReceiptError(f"{label} is not a selected-account ECR repository")
    return repository


def _validate_raw_index(index: dict[str, Any], index_bytes: bytes) -> str:
    try:
        raw = json.loads(index_bytes.decode("utf-8"), object_pairs_hook=_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError, ReceiptError) as error:
        raise ReceiptError("artifact index bytes are not safe JSON") from error
    if raw != index:
        raise ReceiptError("artifact index object does not bind supplied bytes")
    return hashlib.sha256(index_bytes).hexdigest()


def _validate_index(index: Any) -> dict[str, Any]:
    index = _exact(index, {"schema_version", "release_revision", "components"}, "artifact index")
    if type(index["schema_version"]) is not int or index["schema_version"] != 1:
        raise ReceiptError("artifact index identity is invalid")
    _text(index["release_revision"], "artifact index release revision", SHA40)
    components = _exact(index["components"], NAMES, "artifact index components")
    first_party = {"vault-bootstrap", "vault-audit-relay", "gitops-oci-mirror"}
    for name in IMAGE_COMPONENTS:
        keys = {"kind", "build_revision", "third_party_source_revision", "image_ref", "manifest_digest", "input_sha256", "publication", "verification"} if name in first_party else {"kind", "image_ref", "manifest_digest", "destination", "tag"}
        item = _exact(components[name], keys, f"{name} component")
        digest = _text(item["manifest_digest"], f"{name} manifest digest", DIGEST)
        image = _text(item["image_ref"], f"{name} image reference", IMAGE)
        if image.rsplit("@", 1)[1] != digest or item["kind"] != "image":
            raise ReceiptError(f"{name} source image does not bind its digest")
        if name not in first_party:
            _text(item["destination"], f"{name} catalog destination")
            _text(item["tag"], f"{name} catalog tag", TAG)
        else:
            _text(item["build_revision"], f"{name} build revision", SHA40)
            if item["third_party_source_revision"] is not None:
                raise ReceiptError(f"{name} source identity is invalid")
            _text(item["input_sha256"], f"{name} input digest", re.compile(r"^[a-f0-9]{64}$"))
            publication = _exact(item["publication"], {"workflow", "run_id", "invocation"}, f"{name} publication")
            _text(publication["workflow"], f"{name} publication workflow")
            _text(publication["invocation"], f"{name} publication invocation")
            if not isinstance(publication["run_id"], (str, int)) or isinstance(publication["run_id"], bool) or not str(publication["run_id"]).isdigit():
                raise ReceiptError(f"{name} publication run id is invalid")
            verification = _exact(item["verification"], {"method", "status"}, f"{name} verification")
            if verification != {"method": FIRST_PARTY_METHODS[name], "status": "passed"}:
                raise ReceiptError(f"{name} verification is invalid")
    for name in CHART_COMPONENTS:
        item = _exact(components[name], {"kind", "approved_url", "archive_sha256", "expected_oci_manifest_digest", "version", "destination", "tag"}, f"{name} component")
        if item["kind"] != "helm-chart" or not isinstance(item["approved_url"], str) or not item["approved_url"].startswith("https://"):
            raise ReceiptError(f"{name} chart authority is invalid")
        _text(item["archive_sha256"], f"{name} archive digest", re.compile(r"^[a-f0-9]{64}$"))
        _text(item["expected_oci_manifest_digest"], f"{name} manifest digest", DIGEST)
        # Preserve the publisher's exact chart version, including Jetstack's
        # leading v. Never rewrite the catalog value or broaden Vault versions.
        validate_chart_version(name, item["version"])
        _text(item["destination"], f"{name} catalog destination")
        _text(item["tag"], f"{name} catalog tag", TAG)
    return components


def _destinations(baseline: Any, discovery: dict[str, Any]) -> dict[str, str]:
    account = _text(discovery.get("aws_account_id"), "selected AWS account", re.compile(r"^[0-9]{12}$"))
    region = _text(discovery.get("aws_region"), "selected AWS region", re.compile(r"^[a-z0-9-]+$"))
    repositories = _output(baseline, "private_gitops_ecr_repository_urls")
    if not isinstance(repositories, dict) or not REPOSITORY_KEYS <= set(repositories):
        raise ReceiptError("baseline does not bind all private GitOps repositories")
    repos = {key: _ecr_repository(repositories[key], account, region, f"baseline repository {key}") for key in REPOSITORY_KEYS}
    relay = _ecr_repository(_output(baseline, "vault_audit_relay_ecr_repository_url"), account, region, "baseline audit relay repository")
    return {"vault-bootstrap": repos["vault"], "vault-server": repos["vault"], "vault-injector": repos["vault"], "cert-manager-controller": repos["cert_manager"], "cert-manager-webhook": repos["cert_manager"], "cert-manager-cainjector": repos["cert_manager"], "cert-manager-startupapicheck": repos["cert_manager"], "vault-audit-relay": relay, "vault-chart": repos["vault_chart"], "cert-manager-chart": repos["cert_manager_chart"]}


def validate(index: dict[str, Any], receipt: Any, baseline: Any, discovery: dict[str, Any], index_bytes: bytes) -> tuple[dict[str, Any], str]:
    """Return verified receipt artifacts only after the full local binding holds."""
    if not isinstance(index_bytes, bytes):
        raise ReceiptError("artifact index bytes are unavailable")
    index_hash = _validate_raw_index(index, index_bytes)
    components = _validate_index(index)
    if not isinstance(discovery, dict):
        raise ReceiptError("selected deployment context is invalid")
    _text(discovery.get("deployment_name"), "selected deployment name")
    receipt = _exact(receipt, {"schema_version", "status", "aws_account_id", "aws_region", "deployment_name", "release_revision", "index_sha256", "artifacts"}, "mirror receipt")
    if type(receipt["schema_version"]) is not int or receipt["schema_version"] != 1 or receipt["status"] != "verified":
        raise ReceiptError("mirror receipt status is invalid")
    for key in ("aws_account_id", "aws_region", "deployment_name"):
        if receipt[key] != discovery.get(key):
            raise ReceiptError("mirror receipt deployment context differs")
    if receipt["release_revision"] != index["release_revision"] or receipt["index_sha256"] != index_hash:
        raise ReceiptError("mirror receipt does not bind the release index")
    destinations = _destinations(baseline, discovery)
    artifacts = _exact(receipt["artifacts"], RECEIPT_COMPONENTS, "mirror receipt artifacts")
    for name, destination in destinations.items():
        chart = name in CHART_COMPONENTS
        item = _exact(artifacts[name], {"image_ref", "manifest_digest", "version"} if chart else {"image_ref", "manifest_digest"}, f"mirror receipt {name}")
        expected_digest = components[name]["expected_oci_manifest_digest"] if chart else components[name]["manifest_digest"]
        if item["manifest_digest"] != expected_digest or item["image_ref"] != f"{destination}@{expected_digest}":
            raise ReceiptError(f"mirror receipt {name} destination or digest differs from authority")
        if chart and item["version"] != components[name]["version"]:
            raise ReceiptError(f"mirror receipt {name} chart version differs from authority")
    return artifacts, index_hash
