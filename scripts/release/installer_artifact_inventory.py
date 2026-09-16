#!/usr/bin/env python3
"""Build an offline, fail-closed inventory of release artifact authority.

The inventory is deliberately only a statement of local release inputs.  It
does not contact a registry, read credentials, or claim that a destination has
been mirrored.  In particular, a Vault installer index is authority for its
own components only; it is not evidence for the wider GitOps or validator
artifact set.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import stat
import subprocess
from typing import Any
from prysm_release_authorization import PrysmReleaseAuthorizationError, validate_release_authorization
from fence_release_authorization import FenceReleaseAuthorizationError, validate_release_authorization as validate_fence_release_authorization
from client_chart_release_authorization import ClientChartAuthorizationError, validate_release_authorization as validate_client_chart_release_authorization
from signer_probe_release_authorization import SignerProbeReleaseAuthorizationError, validate_release_authorization as validate_signer_probe_release_authorization

from installer_artifact_receipt import NAMES as VAULT_COMPONENTS, ReceiptError, _validate_index

SHA40 = re.compile(r"^[0-9a-f]{40}$")
DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
IMAGE = re.compile(r"^[a-z0-9][a-z0-9._/-]*@sha256:[a-f0-9]{64}$")
ACCOUNT = re.compile(r"^[0-9]{12}$")
REGION = re.compile(r"^ap-northeast-[12]$")
NAME = re.compile(r"^[a-z][a-z0-9-]{1,18}[a-z0-9]$")
TAG = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$")
MAX_JSON = 4 * 1024 * 1024
PROFILE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
REPOSITORY = re.compile(r"^[a-z0-9][a-z0-9._/-]*$")
AWS_TIMEOUT = 30

class InventoryError(ValueError):
    """Raised when a checked-in authority source is malformed or unsafe."""


class DestinationVerificationError(RuntimeError):
    """Raised when a read-only destination-presence check cannot be trusted."""


def _duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise InventoryError("duplicate JSON object key")
        value[key] = item
    return value


def _json(path: Path) -> Any:
    try:
        info = path.lstat()
        if path.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_size > MAX_JSON:
            raise InventoryError(f"unsafe JSON input: {path}")
        return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_duplicates)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, InventoryError) as error:
        if isinstance(error, InventoryError):
            raise
        raise InventoryError(f"invalid JSON input: {path}") from error


def _exact(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise InventoryError(f"{label} has an unexpected schema")
    return value


def _text(value: Any, label: str, pattern: re.Pattern[str] | None = None) -> str:
    if not isinstance(value, str) or not value or (pattern and not pattern.fullmatch(value)):
        raise InventoryError(f"{label} is invalid")
    return value


def _registry(account: str, region: str) -> str:
    return f"{account}.dkr.ecr.{region}.amazonaws.com"


def _destination(account: str, region: str, repository: str, digest: str) -> str:
    return f"{_registry(account, region)}/{repository}@{digest}"


def _catalog(bundle: Path) -> list[dict[str, Any]] | None:
    path = bundle / ".ci/gitops/approved-oci-artifacts.json"
    if not path.exists() and not path.is_symlink():
        return None
    value = _exact(_json(path), {"version", "helm_archives", "artifacts"}, "approved GitOps catalog")
    if value["version"] != 1 or not isinstance(value["artifacts"], list) or not isinstance(value["helm_archives"], list):
        raise InventoryError("approved GitOps catalog is invalid")
    result: list[dict[str, Any]] = []
    for item in value["artifacts"]:
        entry = _exact(item, {"source", "destination", "ecrTag", "purpose"}, "approved GitOps artifact")
        source = _text(entry["source"], "approved GitOps source", IMAGE)
        destination = _text(entry["destination"], "approved GitOps destination")
        tag = _text(entry["ecrTag"], "approved GitOps tag", TAG)
        _text(entry["purpose"], "approved GitOps purpose")
        result.append({"source": source, "destination": destination, "tag": tag})
    return result


def _one(catalog: list[dict[str, Any]], component: str, prefix: str, destination: str) -> dict[str, Any]:
    matches = [item for item in catalog if item["source"].startswith(prefix) and item["destination"] == destination]
    if len(matches) != 1:
        raise InventoryError(f"approved GitOps catalog selection for {component} is ambiguous or missing")
    return matches[0]


def _vault_index(path: Path, release_sha: str) -> dict[str, dict[str, Any]] | None:
    if not path.exists() and not path.is_symlink():
        return None
    value = _exact(_json(path), {"schema_version", "release_revision", "components"}, "installer artifact index")
    if value.get("release_revision") != release_sha:
        raise InventoryError("installer artifact index is not the selected release index")
    try:
        components = _validate_index(value)
    except ReceiptError as error:
        raise InventoryError("installer artifact index is not strict shared authority") from error
    result: dict[str, dict[str, Any]] = {}
    for component, entry in components.items():
        if component in {"vault-chart", "cert-manager-chart"}:
            digest = _text(entry.get("expected_oci_manifest_digest"), f"{component} digest", DIGEST)
        else:
            digest = _text(entry.get("manifest_digest"), f"{component} digest", DIGEST)
            image = _text(entry.get("image_ref"), f"{component} image", IMAGE)
            if image.rsplit("@", 1)[1] != digest:
                raise InventoryError(f"{component} image and digest differ")
        result[component] = {"digest": digest, "source": entry.get("image_ref")}
    return result


def _entry(component: str, consumer: str, destination: str | None, source: str | None,
           authority: str | None, required: bool, unresolved: str | None = None,
           destination_tag: str | None = None) -> dict[str, Any]:
    value = {"component": component, "consumer": consumer, "required": required,
             "destination": destination, "source": source, "authority": authority,
             "status": "unresolved" if unresolved else "source-approved"}
    if unresolved:
        value["unresolved_authority"] = unresolved
    if destination_tag is not None:
        value["destination_tag"] = destination_tag
    return value


def _local_artifact_authority(path: Path, release_sha: str, account: str, region: str,
                              deployment_name: str) -> dict[str, dict[str, Any]]:
    """Read a fresh local publisher's immutable authority outside the bundle."""
    signature = path.with_suffix(".sigstore.json")
    public_key = path.with_suffix(".pub")
    for sidecar in (signature, public_key):
        try:
            info = sidecar.lstat()
            if sidecar.is_symlink() or not stat.S_ISREG(info.st_mode):
                raise InventoryError("local artifact authority signature material is unsafe")
        except OSError as error:
            raise InventoryError("local artifact authority signature material is unavailable") from error
    try:
        subprocess.run(["cosign", "verify-blob", "--insecure-ignore-tlog", "--key", str(public_key),
                        "--bundle", str(signature), str(path)], check=True, capture_output=True, text=True,
                       timeout=AWS_TIMEOUT)
    except (OSError, subprocess.TimeoutExpired, subprocess.CalledProcessError) as error:
        raise InventoryError("local artifact authority signature is invalid") from error
    value = _exact(_json(path), {"schema_version", "release_revision", "deployment", "artifacts"}, "local artifact authority")
    expected_deployment = {"aws_account_id": account, "aws_region": region, "deployment_name": deployment_name}
    if value["schema_version"] != 1 or value["release_revision"] != release_sha or value["deployment"] != expected_deployment or not isinstance(value["artifacts"], list):
        raise InventoryError("local artifact authority is not bound to this release and deployment")
    result: dict[str, dict[str, Any]] = {}
    for item in value["artifacts"]:
        item = _exact(item, {"component", "source", "destination", "authority"}, "local artifact authority entry")
        component = _text(item["component"], "local artifact component", re.compile(r"^[a-z0-9][a-z0-9-]*$"))
        source = _text(item["source"], "local artifact source", IMAGE)
        destination = item["destination"]
        if component == "gitops-oci-mirror":
            if destination is not None:
                raise InventoryError("local mirror tool authority must not declare a destination")
        else:
            destination = _text(destination, "local artifact destination")
            _, digest = _destination_parts(destination, account, region)
            if source.rsplit("@", 1)[1] != digest:
                raise InventoryError("local artifact authority source and destination differ")
        if item["authority"] != "local-build-sign-publish" or component in result:
            raise InventoryError("local artifact authority entry is invalid")
        result[component] = {"source": source, "destination": destination, "authority": item["authority"]}
    return result


def build_inventory(bundle_root: Path, release_sha: str, account: str, region: str,
                    deployment_name: str, require_signer_probe: bool = False,
                    local_artifact_authority: Path | None = None) -> dict[str, Any]:
    """Return the local authority map without performing any external operation."""
    if not bundle_root.is_absolute() or bundle_root.is_symlink() or not bundle_root.is_dir():
        raise InventoryError("bundle root must be an absolute non-symlink directory")
    _text(release_sha, "release SHA", SHA40)
    _text(account, "AWS account ID", ACCOUNT)
    _text(region, "AWS region", REGION)
    _text(deployment_name, "deployment name", NAME)

    source_root = bundle_root / "source" if (bundle_root / "source").is_dir() else bundle_root
    if source_root.is_symlink() or not source_root.is_dir():
        raise InventoryError("bundle source root is unsafe")
    catalog = _catalog(source_root)
    entries: list[dict[str, Any]] = []
    gitops_components = (
        ("argo-cd-chart", "ghcr.io/argoproj/argo-helm/argo-cd@", "argocd", "Argo CD Helm bootstrap"),
        # The reviewed GitOps catalog is the release-bound authority for the
        # bootstrap runner too. It is shipped in every public bundle and is
        # immutable by digest, unlike the removed operator-local historic
        # platform approval file.
        ("argocd-bootstrap", "ghcr.io/s1ns3nz0/node-operator/argocd-bootstrap@", "argocd", "private Argo bootstrap runner"),
        ("argo-cd", "quay.io/argoproj/argocd@", "argocd", "Argo CD runtime"),
        ("dex", "ghcr.io/dexidp/dex@", "argocd", "Argo CD runtime"),
        ("redis", "public.ecr.aws/docker/library/redis@", "argocd", "Argo CD runtime"),
        ("kyverno-chart", "ghcr.io/kyverno/charts/kyverno@", "charts", "Kyverno Helm bootstrap"),
        ("kyverno-preflight", "ghcr.io/kyverno/kyvernopre@", "nodes", "Kyverno runtime"),
        ("kyverno", "ghcr.io/kyverno/kyverno@", "nodes", "Kyverno runtime"),
        ("kyverno-background-controller", "ghcr.io/kyverno/background-controller@", "nodes", "Kyverno runtime"),
        ("kyverno-cleanup-controller", "ghcr.io/kyverno/cleanup-controller@", "nodes", "Kyverno runtime"),
        ("kyverno-reports-controller", "ghcr.io/kyverno/reports-controller@", "nodes", "Kyverno runtime"),
        ("kyverno-readiness-checker", "ghcr.io/kyverno/readiness-checker@", "nodes", "Kyverno runtime"),
        ("nethermind", "nethermind/nethermind@", "nodes", "Hoodi execution node"),
        ("prysm-beacon", "offchainlabs/prysm-beacon-chain@", "nodes", "Hoodi consensus node"),
    )
    # Older bundles did not approve a private CLI. Only a reviewed canonical
    # catalog row adds this authority; Kyverno bootstrap independently requires it.
    cli_prefix = "123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/node-operator-baseline-gitops-nodes@"
    if catalog is not None and any(item["source"].startswith(cli_prefix) for item in catalog):
        gitops_components += (("kyverno-cli", cli_prefix, "nodes", "Kyverno resource migration"),)
    for component, prefix, destination, consumer in gitops_components:
        if catalog is None:
            entries.append(_entry(component, consumer, None, None, None, True,
                                  "approved GitOps catalog is absent from the verified bundle source"))
        else:
            item = _one(catalog, component, prefix, destination)
            digest = item["source"].rsplit("@", 1)[1]
            repository = f"{deployment_name}-baseline-gitops-{destination}"
            # Terraform's Argo Helm upgrade consumes the nested OCI chart
            # repository; runtime images remain in the root Argo repository.
            if component == "argo-cd-chart":
                repository += "/argo-cd"
            entries.append(_entry(component, consumer,
                                  _destination(account, region, repository, digest),
                                  item["source"], "approved-gitops-catalog", True,
                                  destination_tag=item["tag"]))


    runtime = _exact(_json(source_root / ".ci/validator/approved-runtime-images.json"), {"schema_version", "images"}, "validator runtime catalog")
    if runtime["schema_version"] != 1 or not isinstance(runtime["images"], dict):
        raise InventoryError("validator runtime catalog is invalid")
    for component in ("web3signer", "postgres"):
        item = _exact(runtime["images"].get(component), {"source", "reference"}, f"{component} approval")
        source = _text(item["source"], f"{component} source", IMAGE)
        _text(item["reference"], f"{component} reference")
        digest = source.rsplit("@", 1)[1]
        entries.append(_entry(component, "validator runtime", _destination(account, region, f"{deployment_name}-baseline-validator-runtime-{component}", digest), source, "approved-validator-runtime-catalog", True))
    if "fluent-bit" not in runtime["images"]:
        # Older verified bundles lack this retained v0.1.20 authority record.
        # Preserve the destination shape but do not invent a digest.
        entries.append(_entry("validator-log-collector", "validator workload logs",
                              f"{_registry(account, region)}/{deployment_name}-baseline-validator-fluent-bit@<approved-digest>",
                              None, None, True,
                              "v0.1.20 retained collector digest approval is absent from this bundle"))
    else:
        collector = runtime["images"]["fluent-bit"]
        collector = _exact(collector, {"source", "reference"}, "fluent-bit approval")
        source = _text(collector["source"], "fluent-bit source", IMAGE)
        if not source.startswith("cr.fluentbit.io/fluent/fluent-bit@"):
            raise InventoryError("fluent-bit source is not the approved registry path")
        _text(collector["reference"], "fluent-bit reference")
        digest = source.rsplit("@", 1)[1]
        entries.append(_entry("validator-log-collector", "validator workload logs",
                              _destination(account, region, f"{deployment_name}-baseline-validator-fluent-bit", digest),
                              source, "approved-validator-runtime-catalog", True))

    clients = _exact(_json(source_root / ".ci/validator/approved-client-images.json"), {"schema_version", "images"}, "validator client catalog")
    if clients["schema_version"] != 2 or not isinstance(clients["images"], list):
        raise InventoryError("validator client catalog is invalid")
    authorization_path = bundle_root / "source/release/prysm-publication-authorization.json"
    record_path = bundle_root / "rendered/prysm-mtls-publication-record.json"
    authorization_present = authorization_path.exists() or authorization_path.is_symlink()
    record_present = record_path.exists() or record_path.is_symlink()
    prysm_authorization = None
    if authorization_present:
        try: prysm_authorization = validate_release_authorization(bundle_root, release_sha, "stage")
        except PrysmReleaseAuthorizationError as error: raise InventoryError("Prysm release authorization is invalid") from error
    elif record_present:
        raise InventoryError("Prysm publication record is orphaned from release authorization")
    # A task-scoped live activation is evidence for its already-selected live
    # deployment, never a default source for a fresh deployment. Keep it out
    # of the legacy fallback while retaining ambiguity rejection for global
    # manual approvals.
    manual = [
        item for item in clients["images"]
        if isinstance(item, dict)
        and item.get("component") == "prysm-validator"
        and item.get("activation_approved") is True
        and item.get("release_channel") == "manual-native-mtls"
        and not (
            isinstance(item.get("approval_basis"), dict)
            and item["approval_basis"].get("task_scoped_activation_approval") is True
        )
    ]
    if len(manual) != 1:
        raise InventoryError("selected manual-native-mtls Prysm approval is ambiguous or missing")
    if prysm_authorization is None:
        private = _text(manual[0].get("private_image"), "selected Prysm private image", IMAGE)
        digest = private.rsplit("@", 1)[1]
        entries.append(_entry("prysm-validator", "validator client", _destination(account, region, f"{deployment_name}-baseline-validator-prysm", digest), None, None, True, "selected manual-native-mtls Prysm approval has no reproducible immutable source or publication record"))
    else:
        source = _text(prysm_authorization["record"]["target"]["image_ref"], "authorized Prysm image", IMAGE)
        digest = source.rsplit("@", 1)[1]
        entries.append(_entry("prysm-validator", "validator client", _destination(account, region, f"{deployment_name}-baseline-validator-prysm", digest), source, "prysm-release-authorization", True))
    fence_authorization_path = bundle_root / "source/release/fence-publication-authorization.json"
    fence_record_path = bundle_root / "rendered/fence-release-verification.json"
    fence_authorization_present = fence_authorization_path.exists() or fence_authorization_path.is_symlink()
    fence_record_present = fence_record_path.exists() or fence_record_path.is_symlink()
    fence_authorization = None
    if fence_authorization_present:
        try: fence_authorization = validate_fence_release_authorization(bundle_root, release_sha, "stage")
        except FenceReleaseAuthorizationError as error: raise InventoryError("Fence release authorization is invalid") from error
    elif fence_record_present:
        raise InventoryError("Fence release record is orphaned from release authorization")
    if fence_authorization is None:
        entries.append(_entry("validator-signing-fence", "validator client fence", f"{_registry(account, region)}/{deployment_name}-baseline-validator-fence@<approved-digest>", None, None, True, "v0.1.20 has no canonical signing-fence publication record or approved default"))
    else:
        source = _text(fence_authorization["record"]["image"], "authorized Fence image", IMAGE)
        digest = source.rsplit("@", 1)[1]
        entries.append(_entry("validator-signing-fence", "validator client fence", _destination(account, region, f"{deployment_name}-baseline-validator-fence", digest), source, "fence-release-authorization", True))
    chart_auth_path = bundle_root / "source/release/client-chart-publication-authorization.json"
    chart_record_dir = bundle_root / "rendered/client-chart-publication-records"
    chart_auth_present = chart_auth_path.exists() or chart_auth_path.is_symlink()
    chart_records_present = chart_record_dir.exists() or chart_record_dir.is_symlink()
    chart_authorization = None
    if chart_auth_present:
        try: chart_authorization = validate_client_chart_release_authorization(bundle_root, release_sha, "stage")
        except ClientChartAuthorizationError as error: raise InventoryError("client chart release authorization is invalid") from error
    elif chart_records_present:
        raise InventoryError("client chart publication records are orphaned from release authorization")
    if chart_authorization is None:
        entries.append(_entry("node-operator-client-chart", "Argo client Application", f"{_registry(account, region)}/{deployment_name}-baseline-gitops-client/node-operator-client@<approved-digest>", None, None, True, "no release-bound client chart version, digest, and publication receipt is present"))
    else:
        target = chart_authorization["target"]; digest = target["manifest_digest"]
        entries.append(_entry("node-operator-client-chart", "Argo client Application", _destination(account, region, f"{deployment_name}-baseline-gitops-client/node-operator-client", digest), target["image_ref"], "client-chart-release-authorization", True, destination_tag=target["chart_version"]))
    signer_probe_auth_path = bundle_root / "source/release/signer-probe-publication-authorization.json"
    signer_probe_record_path = bundle_root / "rendered/signer-probe-publication-record.json"
    signer_probe_auth_present = signer_probe_auth_path.exists() or signer_probe_auth_path.is_symlink()
    signer_probe_record_present = signer_probe_record_path.exists() or signer_probe_record_path.is_symlink()
    signer_probe_authorization = None
    if signer_probe_auth_present:
        try:
            signer_probe_authorization = validate_signer_probe_release_authorization(bundle_root, release_sha, "stage")
        except SignerProbeReleaseAuthorizationError as error:
            raise InventoryError("signer-probe release authorization is invalid") from error
    elif signer_probe_record_present:
        raise InventoryError("signer-probe publication record is orphaned from release authorization")
    if signer_probe_authorization is None:
        if require_signer_probe:
            entries.append(_entry("validator-signer-identity-probe", "signer identity evidence", f"{_registry(account, region)}/{deployment_name}-baseline-validator-signer-identity-probe@<approved-digest>", None, None, True, "no approved signer identity probe source or publication record is present"))
    else:
        record = signer_probe_authorization["record"]
        source = _text(record["image_ref"], "authorized signer-probe image", IMAGE)
        digest = _text(record["manifest_digest"], "authorized signer-probe digest", DIGEST)
        if source.rsplit("@", 1)[1] != digest:
            raise InventoryError("authorized signer-probe image and digest differ")
        entries.append(_entry("validator-signer-identity-probe", "signer identity evidence",
                              _destination(account, region, f"{deployment_name}-baseline-validator-signer-identity-probe", digest),
                              source, "signer-probe-release-authorization", True))

    index = _vault_index(bundle_root / "rendered/installer-artifact-index.json", release_sha)
    vault_destinations = {"vault-bootstrap": f"{deployment_name}-baseline-gitops-vault", "vault-audit-relay": f"{deployment_name}-baseline-vault-audit-relay", "gitops-oci-mirror": None, "vault-server": f"{deployment_name}-baseline-gitops-vault", "vault-injector": f"{deployment_name}-baseline-gitops-vault", "cert-manager-controller": f"{deployment_name}-baseline-gitops-cert-manager", "cert-manager-webhook": f"{deployment_name}-baseline-gitops-cert-manager", "cert-manager-cainjector": f"{deployment_name}-baseline-gitops-cert-manager", "cert-manager-startupapicheck": f"{deployment_name}-baseline-gitops-cert-manager", "vault-chart": f"{deployment_name}-baseline-gitops-vault/vault", "cert-manager-chart": f"{deployment_name}-baseline-gitops-cert-manager/cert-manager"}
    for component in sorted(VAULT_COMPONENTS):
        if index is None:
            # Index-less public bundles have no publication records.  Retain
            # the fixed private repository shape so a locally signed authority
            # can resolve it, but never invent a digest or public source.
            repository = vault_destinations[component]
            destination = f"{_registry(account, region)}/{repository}@<local-digest>" if repository else None
            entries.append(_entry(component, "Vault installer", destination, None, None, True, "selected release has no installer artifact index; historical Vault catalog entries are not a fallback"))
            continue
        item = index[component]
        repository = vault_destinations[component]
        destination = _destination(account, region, repository, item["digest"]) if repository else None
        entries.append(_entry(component, "Vault installer", destination, item["source"], "installer-artifact-index", True))

    if local_artifact_authority is not None:
        if index is not None:
            raise InventoryError("local artifact authority is accepted only when the selected bundle has no installer artifact index")
        local = _local_artifact_authority(local_artifact_authority, release_sha, account, region, deployment_name)
        if set(local) - VAULT_COMPONENTS:
            raise InventoryError("local artifact authority contains a non-Vault component")
        for item in entries:
            replacement = local.get(item["component"])
            if replacement is None:
                continue
            expected_destination = item.get("destination")
            actual_destination = replacement["destination"]
            same_repository = ((expected_destination is None and actual_destination is None)
                               or (isinstance(expected_destination, str) and "@" in expected_destination
                                   and isinstance(actual_destination, str) and "@" in actual_destination
                                   and expected_destination.rsplit("@", 1)[0] == actual_destination.rsplit("@", 1)[0]))
            if not item.get("unresolved_authority") or not same_repository:
                raise InventoryError("local artifact authority attempts to replace signed release authority")
            item.update(replacement)
            item["status"] = "source-approved"
            item.pop("unresolved_authority")

    entries.sort(key=lambda item: item["component"])
    unresolved = [{"component": item["component"], "reason": item["unresolved_authority"]} for item in entries if item.get("unresolved_authority") and item["required"]]
    return {"schema_version": 1, "release_revision": release_sha, "deployment": {"aws_account_id": account, "aws_region": region, "deployment_name": deployment_name}, "artifacts": entries, "unresolved_authority": unresolved, "complete": not unresolved}


def _verification_env(profile: str, region: str) -> dict[str, str]:
    """Use the mirror's credential-scrubbed environment without touching GitHub auth."""
    # installer_artifact_mirror imports no inventory module, so this one-way
    # reuse has no import cycle and keeps profile/credential handling aligned.
    from installer_artifact_mirror import _mirror_env
    return _mirror_env(profile, region)


def _run_aws(command: list[str], env: dict[str, str], executor: Any) -> dict[str, Any]:
    try:
        result = executor(command, check=True, capture_output=True, text=True, env=env, timeout=AWS_TIMEOUT)
        value = json.loads(result.stdout)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError, json.JSONDecodeError, TypeError) as error:
        raise DestinationVerificationError("AWS destination presence verification failed") from error
    if not isinstance(value, dict):
        raise DestinationVerificationError("AWS destination presence response is malformed")
    return value


def _destination_parts(destination: str, account: str, region: str) -> tuple[str, str]:
    registry = _registry(account, region)
    prefix = registry + "/"
    if not isinstance(destination, str) or not destination.startswith(prefix) or destination.count("@") != 1:
        raise DestinationVerificationError("required artifact destination is invalid")
    repository, digest = destination[len(prefix):].rsplit("@", 1)
    if not REPOSITORY.fullmatch(repository) or not DIGEST.fullmatch(digest):
        raise DestinationVerificationError("required artifact destination is invalid")
    return repository, digest


def verify_destinations(bundle_root: Path, release_sha: str, account: str, region: str,
                        deployment_name: str, profile: str, require_signer_probe: bool = False,
                        *, executor: Any = subprocess.run) -> dict[str, Any]:
    """Verify every complete-inventory ECR destination exists by its exact digest.

    This is a read-only destination-presence check. It does not establish
    source authenticity, activation, or that a copy operation was performed.
    """
    if not isinstance(profile, str) or not PROFILE.fullmatch(profile):
        raise DestinationVerificationError("AWS profile is required for destination verification")
    inventory = build_inventory(bundle_root, release_sha, account, region, deployment_name, require_signer_probe)
    # No process, credential lookup, or network operation is permitted until
    # canonical local authority is complete.
    if inventory.get("complete") is not True:
        raise DestinationVerificationError("artifact authority inventory is incomplete")
    deployment = inventory.get("deployment")
    if not isinstance(deployment, dict) or deployment != {"aws_account_id": account, "aws_region": region, "deployment_name": deployment_name}:
        raise DestinationVerificationError("artifact authority inventory deployment is invalid")
    artifacts = inventory.get("artifacts")
    if not isinstance(artifacts, list):
        raise DestinationVerificationError("artifact authority inventory is malformed")
    targets: list[tuple[str, str, str, str, str | None]] = []
    exclusions: list[dict[str, str]] = []
    for item in artifacts:
        if not isinstance(item, dict) or item.get("required") is not True or not isinstance(item.get("component"), str):
            raise DestinationVerificationError("artifact authority inventory is malformed")
        component = item["component"]
        destination = item.get("destination")
        if component == "gitops-oci-mirror" and destination is not None:
            raise DestinationVerificationError("local transport tool must not have a destination")
        if destination is None:
            if component != "gitops-oci-mirror":
                raise DestinationVerificationError("required artifact has no destination")
            exclusions.append({"component": component, "reason": "local transport tool exclusion"})
            continue
        repository, digest = _destination_parts(destination, account, region)
        destination_tag = item.get("destination_tag")
        if destination_tag is not None and (not isinstance(destination_tag, str) or not TAG.fullmatch(destination_tag)):
            raise DestinationVerificationError("artifact destination tag is invalid")
        targets.append((component, destination, repository, digest, destination_tag))
    env = _verification_env(profile, region)
    identity = _run_aws([
        "aws", "sts", "get-caller-identity", "--cli-connect-timeout", "10",
        "--cli-read-timeout", "20", "--output", "json",
    ], env, executor)
    if identity.get("Account") != account or not ACCOUNT.fullmatch(identity.get("Account", "")):
        raise DestinationVerificationError("selected AWS profile is not the selected account")
    evidence: list[dict[str, str]] = []
    for component, destination, repository, digest, destination_tag in targets:
        response = _run_aws([
            "aws", "ecr", "describe-images", "--registry-id", account, "--region", region,
            "--repository-name", repository, "--image-ids", f"imageDigest={digest}",
            "--cli-connect-timeout", "10", "--cli-read-timeout", "20", "--output", "json",
        ], env, executor)
        rows = response.get("imageDetails")
        if not isinstance(rows, list) or len(rows) != 1 or not isinstance(rows[0], dict):
            raise DestinationVerificationError("ECR destination presence response is ambiguous")
        row = rows[0]
        if row.get("registryId") != account or row.get("repositoryName") != repository or row.get("imageDigest") != digest:
            raise DestinationVerificationError("ECR destination identity differs from target")
        if destination_tag is not None:
            tags = row.get("imageTags")
            if not isinstance(tags, list) or any(not isinstance(tag, str) for tag in tags) or tags.count(destination_tag) != 1:
                raise DestinationVerificationError("ECR destination tag does not resolve uniquely to target digest")
        item_evidence = {"component": component, "destination": destination, "repository": repository,
                         "manifest_digest": digest, "status": "present"}
        if destination_tag is not None:
            item_evidence["destination_tag"] = destination_tag
        evidence.append(item_evidence)
    return {"scope": "destination presence only", "release_revision": release_sha, "aws_account_id": account,
            "aws_region": region, "deployment_name": deployment_name, "artifacts": evidence,
            "exclusions": exclusions}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, epilog=("A complete inventory means every listed local source has an immutable approval record. Offline inventory does not contact AWS or attest that any private ECR destination exists. --verify-destinations performs read-only AWS presence checks. --require-signer-probe only includes that required artifact; it never executes a probe."))
    parser.add_argument("--bundle-root", required=True, type=Path)
    parser.add_argument("--release-sha", required=True)
    parser.add_argument("--aws-account-id", required=True)
    parser.add_argument("--aws-region", required=True)
    parser.add_argument("--deployment-name", required=True)
    parser.add_argument("--require-signer-probe", action="store_true")
    parser.add_argument("--local-artifact-authority", type=Path,
                        help="fresh local build/sign/publish authority outside the signed bundle")
    parser.add_argument("--verify-destinations", action="store_true",
                        help="read-only verify exact ECR destination digest presence")
    parser.add_argument("--profile", help="explicit AWS profile required with --verify-destinations")
    args = parser.parse_args()
    if args.verify_destinations and not args.profile:
        parser.error("--profile is required with --verify-destinations")
    try:
        if args.verify_destinations:
            if args.local_artifact_authority is not None:
                parser.error("--local-artifact-authority cannot be used with --verify-destinations")
            result = verify_destinations(args.bundle_root, args.release_sha, args.aws_account_id,
                                         args.aws_region, args.deployment_name, args.profile,
                                         args.require_signer_probe)
            print(json.dumps(result, sort_keys=True, separators=(",", ":")))
            return 0
        inventory = build_inventory(args.bundle_root, args.release_sha, args.aws_account_id, args.aws_region,
                                    args.deployment_name, args.require_signer_probe,
                                    args.local_artifact_authority)
    except (InventoryError, DestinationVerificationError) as error:
        parser.error(str(error))
    print(json.dumps(inventory, sort_keys=True, separators=(",", ":")))
    return 0 if inventory["complete"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
