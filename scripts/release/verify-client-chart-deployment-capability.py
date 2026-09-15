#!/usr/bin/env python3
"""Verify that one authorized Helm OCI chart digest supports deployment values.

This verifier deliberately does not trust a chart version as a capability
signal.  It retrieves only the authorized ECR manifest and chart layer, checks
the layer bytes against that manifest, validates the archive/schema, and asks
Helm to render the supplied deployment values.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
import re
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
from pathlib import Path
from typing import Any, Callable

MAX_LAYER = 32 * 1024 * 1024
MAX_UNPACKED = 64 * 1024 * 1024
MAX_MEMBERS = 512
IMAGE = re.compile(r"^([0-9]{12})\.dkr\.ecr\.([a-z]{2}-[a-z0-9-]+-[0-9]+)\.amazonaws\.com/([a-z0-9][a-z0-9._/-]*)@sha256:([a-f0-9]{64})$")
DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
PROFILE = re.compile(r"^[A-Za-z0-9_+=,.@-]+$")


class CapabilityError(RuntimeError):
    pass


class _BoundedRead:
    """Expose a streaming reader while capping total decompressed input."""
    def __init__(self, source: Any, limit: int):
        self.source = source
        self.limit = limit
        self.used = 0

    def read(self, size: int = -1) -> bytes:
        remaining = self.limit - self.used
        # Do not ask gzip to inflate an unbounded amount merely because a
        # downstream parser supplied read(-1).
        request = remaining + 1 if size < 0 else min(size, remaining + 1)
        data = self.source.read(request)
        self.used += len(data)
        if self.used > self.limit:
            raise CapabilityError("chart archive exceeds the unpacked safety limit")
        return data


def _run(command: list[str], runner: Callable[..., Any], environment: dict[str, str]) -> dict[str, Any]:
    try:
        result = runner(command, check=False, capture_output=True, text=True, timeout=30, env=environment)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise CapabilityError("authorized chart lookup failed") from error
    if result.returncode != 0:
        raise CapabilityError("authorized chart lookup failed")
    try:
        value = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise CapabilityError("authorized chart lookup returned invalid JSON") from error
    if not isinstance(value, dict):
        raise CapabilityError("authorized chart lookup returned invalid JSON")
    return value


def _download(url: str, opener: Callable[..., Any]) -> bytes:
    try:
        with opener(url, timeout=30) as response:
            data = response.read(MAX_LAYER + 1)
    except OSError as error:
        raise CapabilityError("authorized chart layer download failed") from error
    if len(data) > MAX_LAYER:
        raise CapabilityError("authorized chart layer exceeds the safety limit")
    return data


def fetch_authorized_layer(image_ref: str, aws_profile: str, runner: Callable[..., Any] = subprocess.run, opener: Callable[..., Any] = urllib.request.urlopen) -> bytes:
    match = IMAGE.fullmatch(image_ref)
    if match is None:
        raise CapabilityError("authorized chart image reference is invalid")
    account, region, repository, digest_hex = match.groups()
    if PROFILE.fullmatch(aws_profile) is None:
        raise CapabilityError("authorized chart lookup profile is invalid")
    digest = "sha256:" + digest_hex
    # The selected profile is the authorization boundary.  In particular, do
    # not let ambient credential, endpoint, role, or token variables override
    # it for either of the two digest-bound ECR reads.
    environment = {name: value for name, value in os.environ.items() if not name.startswith("AWS_")}
    environment.update({"AWS_PROFILE": aws_profile, "AWS_DEFAULT_REGION": region, "AWS_REGION": region})
    manifest_result = _run([
        "aws", "--profile", aws_profile, "ecr", "batch-get-image", "--registry-id", account, "--region", region,
        "--repository-name", repository, "--image-ids", "imageDigest=" + digest,
        "--accepted-media-types", "application/vnd.oci.image.manifest.v1+json", "--output", "json",
    ], runner, environment)
    images = manifest_result.get("images")
    if not isinstance(images, list) or len(images) != 1 or not isinstance(images[0], dict) or not isinstance(images[0].get("imageId"), dict) or images[0]["imageId"].get("imageDigest") != digest or not isinstance(images[0].get("imageManifest"), str):
        raise CapabilityError("authorized chart manifest is absent or mismatched")
    manifest_bytes = images[0]["imageManifest"].encode("utf-8")
    if hashlib.sha256(manifest_bytes).hexdigest() != digest_hex:
        raise CapabilityError("authorized chart manifest bytes differ from the requested digest")
    try:
        manifest = json.loads(images[0]["imageManifest"])
    except json.JSONDecodeError as error:
        raise CapabilityError("authorized chart manifest is invalid") from error
    layers = manifest.get("layers") if isinstance(manifest, dict) else None
    chart_layers = [layer for layer in layers if isinstance(layer, dict) and layer.get("mediaType") == "application/vnd.cncf.helm.chart.content.v1.tar+gzip"] if isinstance(layers, list) else []
    if len(chart_layers) != 1 or not isinstance(chart_layers[0].get("digest"), str) or DIGEST.fullmatch(chart_layers[0]["digest"]) is None:
        raise CapabilityError("authorized chart manifest has no unique Helm chart layer")
    layer_digest = chart_layers[0]["digest"]
    location = _run([
        "aws", "--profile", aws_profile, "ecr", "get-download-url-for-layer", "--registry-id", account, "--region", region,
        "--repository-name", repository, "--layer-digest", layer_digest, "--output", "json",
    ], runner, environment).get("downloadUrl")
    if not isinstance(location, str) or not location.startswith("https://"):
        raise CapabilityError("authorized chart layer URL is invalid")
    layer = _download(location, opener)
    if hashlib.sha256(layer).hexdigest() != layer_digest.removeprefix("sha256:"):
        raise CapabilityError("authorized chart layer digest differs from the manifest")
    return layer


def _members(layer: bytes, version: str) -> dict[str, bytes]:
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(layer)) as zipped, tarfile.open(fileobj=_BoundedRead(zipped, MAX_UNPACKED), mode="r|") as archive:
            members: dict[str, bytes] = {}
            entry_count = 0
            for item in archive:
                entry_count += 1
                path = Path(item.name)
                if item.name.startswith("/") or ".." in path.parts or entry_count > MAX_MEMBERS:
                    raise CapabilityError("chart archive has an unsafe member")
                if item.isdir():
                    continue
                if not item.isfile() or item.name in members:
                    raise CapabilityError("chart archive has an unsafe member")
                if item.size > MAX_UNPACKED:
                    raise CapabilityError("chart archive member exceeds the safety limit")
                handle = archive.extractfile(item)
                if handle is None:
                    raise CapabilityError("chart archive member is unavailable")
                members[item.name] = handle.read()
    except (OSError, tarfile.TarError) as error:
        raise CapabilityError("authorized chart layer is not a safe gzip tar archive") from error
    roots = {Path(path).parts[0] for path in members}
    if len(roots) != 1:
        raise CapabilityError("chart archive must have one root directory")
    root = next(iter(roots))
    for required in (f"{root}/Chart.yaml", f"{root}/values.schema.json"):
        if required not in members:
            raise CapabilityError("chart archive lacks its required capability metadata")
    chart = members[f"{root}/Chart.yaml"].decode("utf-8", "strict")
    if re.search(rf"(?m)^version:\s*['\"]?{re.escape(version)}['\"]?\s*$", chart) is None:
        raise CapabilityError("chart archive version differs from authorized version")
    return members


def _schema_field(schema: dict[str, Any], path: tuple[str, ...], expected_type: str) -> None:
    cursor: Any = schema
    for key in path:
        if not isinstance(cursor, dict) or cursor.get("type") != "object" or not isinstance(cursor.get("properties"), dict):
            raise CapabilityError("chart values schema lacks deployment capability")
        cursor = cursor["properties"].get(key)
    if not isinstance(cursor, dict) or cursor.get("type") != expected_type:
        raise CapabilityError("chart values schema lacks deployment capability")


def _values(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as error:
        raise CapabilityError("deployment values input is invalid") from error
    if not isinstance(value, dict):
        raise CapabilityError("deployment values input is invalid")
    try:
        deployment = value["deployment"]
        clients = value["clients"]
        nested = clients["deployment"]
        required = (deployment["storageKmsKeyId"], clients["vaultAgentImage"], nested["nethermindImage"], nested["prysmImage"], nested["prysmP2PHostIp"])
    except (KeyError, TypeError) as error:
        raise CapabilityError("deployment values input is incomplete") from error
    if deployment.get("profile") != "deployment" or value.get("dast", {}).get("enabled") is not False or not all(isinstance(item, str) and item for item in required):
        raise CapabilityError("deployment values input is not the required deployment profile")
    return value


def _helm(archive: Path, values: Path, dast: bool, runner: Callable[..., Any]) -> str:
    command = ["helm", "template", "node-operator-client", str(archive), "--values", str(values), "--set", "deployment.profile=deployment", "--set", f"dast.enabled={'true' if dast else 'false'}"]
    try:
        result = runner(command, check=False, capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise CapabilityError("Helm render failed") from error
    if result.returncode != 0 or not isinstance(result.stdout, str) or not result.stdout.strip():
        raise CapabilityError("Helm render failed")
    return result.stdout


def _objects(rendered: str, runner: Callable[..., Any]) -> list[dict[str, Any]]:
    parser = "require 'json'; require 'yaml'; docs = STDIN.read.split(/^---\\s*$/).map { |doc| Psych.safe_load(doc, permitted_classes: [], permitted_symbols: [], aliases: false) }.compact; puts JSON.generate(docs)"
    try:
        result = runner(["ruby", "-rjson", "-ryaml", "-e", parser], check=False, capture_output=True, text=True, input=rendered, timeout=60)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise CapabilityError("rendered Kubernetes objects could not be parsed safely") from error
    if result.returncode != 0 or not isinstance(result.stdout, str):
        raise CapabilityError("rendered Kubernetes objects could not be parsed safely")
    try:
        objects = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise CapabilityError("rendered Kubernetes objects could not be parsed safely") from error
    if not isinstance(objects, list) or not objects or not all(isinstance(item, dict) for item in objects):
        raise CapabilityError("rendered Kubernetes objects could not be parsed safely")
    return objects


def _named(objects: list[dict[str, Any]], kind: str, name: str) -> dict[str, Any]:
    matches = [item for item in objects if item.get("kind") == kind and isinstance(item.get("metadata"), dict) and item["metadata"].get("name") == name]
    if len(matches) != 1:
        raise CapabilityError("deployment render lacks a required Kubernetes object")
    return matches[0]


def _container(item: dict[str, Any], name: str, image: str) -> dict[str, Any]:
    try:
        containers = item["spec"]["template"]["spec"]["containers"]
    except (KeyError, TypeError) as error:
        raise CapabilityError("deployment render has an invalid workload shape") from error
    matches = [container for container in containers if isinstance(container, dict) and container.get("name") == name and container.get("image") == image]
    if len(matches) != 1:
        raise CapabilityError("deployment render does not bind the expected client image")
    return matches[0]


def _assert_render(objects: list[dict[str, Any]], values: dict[str, Any]) -> None:
    deployment = values["deployment"]
    clients = values["clients"]
    nested = clients["deployment"]
    for storage_class in ("nethermind-hoodi-gp3-kms", "prysm-hoodi-gp3-kms"):
        item = _named(objects, "StorageClass", storage_class)
        if item.get("parameters", {}).get("kmsKeyId") != deployment["storageKmsKeyId"]:
            raise CapabilityError("deployment render does not bind the expected KMS key")
    nethermind = _named(objects, "StatefulSet", "nethermind-execution")
    prysm = _named(objects, "StatefulSet", "prysm-beacon")
    for item in (nethermind, prysm):
        annotations = item.get("spec", {}).get("template", {}).get("metadata", {}).get("annotations", {})
        if not isinstance(annotations, dict) or annotations.get("vault.hashicorp.com/agent-image") != clients["vaultAgentImage"]:
            raise CapabilityError("deployment render does not bind the expected Vault agent image")
    _container(nethermind, "nethermind", nested["nethermindImage"])
    beacon = _container(prysm, "beacon-chain", nested["prysmImage"])
    if f"--p2p-host-ip={nested['prysmP2PHostIp']}" not in beacon.get("args", []):
        raise CapabilityError("deployment render does not bind the expected Prysm P2P address")
    for item in objects:
        metadata = item.get("metadata") if isinstance(item.get("metadata"), dict) else {}
        labels = metadata.get("labels") if isinstance(metadata.get("labels"), dict) else {}
        if labels.get("node-operator.io/dast-client") == "true" or metadata.get("name") == "private-dast-job-executor":
            raise CapabilityError("deployment render unexpectedly includes a DAST workload")


def verify_layer_capability(layer: bytes, chart_version: str, values_file: Path, runner: Callable[..., Any] = subprocess.run) -> None:
    if re.fullmatch(r"0\.1\.[0-9]+", chart_version) is None:
        raise CapabilityError("authorized chart version is invalid")
    values = _values(values_file)
    members = _members(layer, chart_version)
    root = next(iter({Path(path).parts[0] for path in members}))
    try:
        schema = json.loads(members[f"{root}/values.schema.json"].decode("utf-8", "strict"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CapabilityError("chart values schema is invalid") from error
    if not isinstance(schema, dict):
        raise CapabilityError("chart values schema is invalid")
    for path, expected in ((("deployment", "profile"), "string"), (("deployment", "storageKmsKeyId"), "string"), (("dast", "enabled"), "boolean"), (("clients", "vaultAgentImage"), "string"), (("clients", "deployment", "nethermindImage"), "string"), (("clients", "deployment", "prysmImage"), "string"), (("clients", "deployment", "prysmP2PHostIp"), "string")):
        _schema_field(schema, path, expected)
    with tempfile.TemporaryDirectory() as directory:
        archive = Path(directory) / "chart.tgz"
        archive.write_bytes(layer)
        disabled = _helm(archive, values_file, False, runner)
        try:
            _helm(archive, values_file, True, runner)
        except CapabilityError:
            pass
        else:
            raise CapabilityError("deployment profile accepted DAST enablement")
    _assert_render(_objects(disabled, runner), values)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--chart-image", required=True)
    parser.add_argument("--chart-version", required=True)
    parser.add_argument("--profile", required=True)
    parser.add_argument("--values", required=True, type=Path)
    args = parser.parse_args()
    try:
        verify_layer_capability(fetch_authorized_layer(args.chart_image, args.profile), args.chart_version, args.values)
    except CapabilityError as error:
        print(f"deployment chart capability rejected: {error}", file=sys.stderr)
        return 65
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
