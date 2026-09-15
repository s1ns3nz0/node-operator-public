#!/usr/bin/env python3
"""Bind the read-only validator observer to completed local release evidence."""
from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import re
import stat
import sys
from typing import Any

MAX_BYTES = 8 * 1024 * 1024
ACCOUNT = re.compile(r"[0-9]{12}\Z")
REGION = re.compile(r"[a-z]{2}-[a-z0-9-]+-[0-9]+\Z")
BUCKET = re.compile(r"[a-z0-9][a-z0-9.-]{2,62}\Z")
CLUSTER = re.compile(r"[a-z][a-z0-9-]{1,38}[a-z0-9]\Z")
ROLE = re.compile(r"arn:aws:iam::([0-9]{12}):role/[A-Za-z0-9+=,.@_-]{1,64}\Z")
KMS = re.compile(r"arn:aws:kms:([a-z]{2}-[a-z0-9-]+-[0-9]+):([0-9]{12}):key/[0-9a-f-]{36}\Z")


class ContextError(ValueError):
    """The observer has no single, validated local authority context."""


def strict_object(path: Path) -> tuple[dict[str, Any], bytes]:
    """Read one bounded regular JSON file without accepting duplicate keys."""
    try:
        info = path.lstat()
        if path.is_symlink() or not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= MAX_BYTES:
            raise ContextError("local observation input is unsafe")
        identity = (info.st_dev, info.st_ino, info.st_size)
        raw = path.read_bytes()
        after = path.lstat()
        if len(raw) != info.st_size or (after.st_dev, after.st_ino, after.st_size) != identity:
            raise ContextError("local observation input changed during read")
        def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
            result: dict[str, Any] = {}
            for key, value in items:
                if key in result:
                    raise ContextError("local observation JSON has duplicate keys")
                result[key] = value
            return result
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs)
        if not isinstance(value, dict):
            raise ContextError("local observation JSON is not an object")
        return value, raw
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ContextError("local observation input is unavailable") from error


def module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ContextError("release validator is unavailable")
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


def bundle_validators(bundle_root: Path):
    """Load resume and receipt rules from the verified bundle, not PATH."""
    release = bundle_root / "source/scripts/release"
    for filename in ("interactive-hoodi-resume.py", "installer_artifact_mirror.py", "installer_artifact_receipt.py"):
        path = release / filename
        try:
            info = path.lstat()
        except OSError as error:
            raise ContextError("release validator is unavailable") from error
        if path.is_symlink() or not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= MAX_BYTES:
            raise ContextError("release validator is unavailable")
    prior = {name: sys.modules.get(name) for name in ("installer_artifact_mirror", "installer_artifact_receipt")}
    try:
        resume = module(release / "interactive-hoodi-resume.py", "bundle_resume")
        mirror = module(release / "installer_artifact_mirror.py", "installer_artifact_mirror")
        sys.modules["installer_artifact_mirror"] = mirror
        receipt = module(release / "installer_artifact_receipt.py", "installer_artifact_receipt")
        return resume, receipt
    except (OSError, ImportError, AttributeError, ContextError) as error:
        raise ContextError("release artifact validator is unavailable") from error
    finally:
        for name, existing in prior.items():
            if existing is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = existing


def output(baseline: dict[str, Any], name: str) -> Any:
    item = baseline.get(name)
    if (not isinstance(item, dict) or set(item) != {"sensitive", "type", "value"}
            or item.get("sensitive") is not False or "type" not in item):
        raise ContextError("baseline observer output is unavailable")
    return item["value"]


def load_context(bundle_root: Path, work_dir: Path) -> dict[str, Any]:
    """Return validated non-secret reader and observer inputs for activation."""
    try:
        if not bundle_root.is_absolute() or not work_dir.is_absolute() or bundle_root.is_symlink() or work_dir.is_symlink():
            raise ContextError("bundle root or WORK_DIR is unsafe")
        bundle_root = bundle_root.resolve(strict=True); work_dir = work_dir.resolve(strict=True)
        manifest = bundle_root / "bundle-manifest.json"
        deployment = work_dir / "deployment-work"
        resume, receipt_validator = bundle_validators(bundle_root)
        saved = resume.read(work_dir, manifest)
        if saved.get("schema_version") != 2 or saved.get("phase") not in {"activated", "observing"}:
            raise ContextError("activation is not a valid observation starting point")
        continuation = saved.get("continuation")
        if not isinstance(continuation, dict):
            raise ContextError("activated release has no continuation context")
        index, index_raw = strict_object(bundle_root / "rendered/installer-artifact-index.json")
        baseline, _ = strict_object(deployment / "baseline-output.json")
        mirror, _ = strict_object(deployment / "vault-artifact-mirror-receipt.json")
        discovery = {key: saved[key] for key in ("aws_account_id", "aws_region", "deployment_name")}
        artifacts, index_sha256 = receipt_validator.validate(index, mirror, baseline, discovery, index_raw)
        if index.get("release_revision") != saved.get("release_revision"):
            raise ContextError("artifact index belongs to another release")
        activation, activation_raw = strict_object(work_dir / "evidence/activation-receipt.json")
        if hashlib.sha256(activation_raw).hexdigest() != continuation.get("activation_receipt_sha256"):
            raise ContextError("activation receipt changed after resume validation")
        audit, audit_raw = strict_object(work_dir / "audit/audit-challenge.json")
        if hashlib.sha256(audit_raw).hexdigest() != continuation.get("audit_completion_sha256"):
            raise ContextError("audit challenge changed after resume validation")
        audit_challenge = {key: audit.get(key) for key in ("marker_hmac", "after_ms", "request_id")}
        beacon = activation.get("private_beacon")
        if not isinstance(beacon, dict):
            raise ContextError("activation receipt has no private Beacon identity")
        account, region = saved["aws_account_id"], saved["aws_region"]
        baseline_account, cluster_name = output(baseline, "deployment_account_id"), output(baseline, "cluster_name")
        image = artifacts["vault-bootstrap"]["image_ref"]
        bucket, prefix = output(baseline, "validator_audit_bucket_name"), output(baseline, "validator_audit_prefix")
        namespace, service_account = output(baseline, "validator_audit_reader_namespace"), output(baseline, "validator_audit_reader_service_account")
        role_arn, kms_key_arn = output(baseline, "validator_audit_reader_role_arn"), output(baseline, "validator_audit_kms_key_arn")
        delivery_module = module(Path(__file__).resolve().with_name("operational_log_delivery.py"), "observation_delivery")
        delivery = delivery_module.validate_contract(output(baseline, "operational_log_delivery"))
        if (delivery["account_id"] != account or delivery["region"] != region
                or delivery["deployment_name"] != saved["deployment_name"]):
            raise ContextError("operational log destinations belong to another deployment")
        role_match = ROLE.fullmatch(role_arn) if isinstance(role_arn, str) else None
        kms_match = KMS.fullmatch(kms_key_arn) if isinstance(kms_key_arn, str) else None
        validator_index, head_slot = beacon.get("validator_index"), beacon.get("head_slot")
        if (not isinstance(account, str) or not ACCOUNT.fullmatch(account) or not isinstance(region, str) or not REGION.fullmatch(region)
                or not isinstance(image, str) or not re.fullmatch(r".+@sha256:[0-9a-f]{64}", image)
                or not isinstance(bucket, str) or not BUCKET.fullmatch(bucket) or prefix != "validator/"
                or baseline_account != account or cluster_name != saved["deployment_name"]
                or not isinstance(cluster_name, str) or not CLUSTER.fullmatch(cluster_name)
                or namespace != "validator-observability" or service_account != "validator-audit-reader"
                or role_match is None or role_match.group(1) != account or kms_match is None
                or kms_match.group(1) != region or kms_match.group(2) != account
                or not isinstance(audit_challenge["marker_hmac"], str) or not re.fullmatch(r"hmac-sha256:[0-9a-f]{64}", audit_challenge["marker_hmac"])
                or type(audit_challenge["after_ms"]) is not int or audit_challenge["after_ms"] < 0
                or not isinstance(audit_challenge["request_id"], str) or not re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", audit_challenge["request_id"])
                or not isinstance(validator_index, str) or not validator_index.isdigit()
                or type(head_slot) is not int or head_slot < 0):
            raise ContextError("observer context fields are invalid")
        return {
            "identity": {"validator_set": continuation["validator_set"], "validator_public_key": continuation["public_key"],
                         "validator_index": validator_index, "deployment_name": saved["deployment_name"],
                         "release_revision": saved["release_revision"], "activation_slot": str(head_slot)},
            "aws_account_id": account, "aws_region": region, "deployment_name": saved["deployment_name"], "cluster_name": cluster_name,
            "reader": {"image": image, "bucket": bucket, "prefix": prefix, "namespace": namespace,
                       "service_account": service_account, "role_arn": role_arn, "kms_key_arn": kms_key_arn},
            "operational_log_delivery": delivery,
            "audit_challenge": audit_challenge,
            "vault_security_log_group": f"/aws/eks/{saved['deployment_name']}/validator-security",
            "artifact_index_sha256": index_sha256,
            "activation_receipt_sha256": hashlib.sha256(activation_raw).hexdigest(),
        }
    except (KeyError, OSError, ValueError, TypeError, AttributeError) as error:
        if isinstance(error, ContextError):
            raise
        raise ContextError("observer context is unavailable or inconsistent") from error
