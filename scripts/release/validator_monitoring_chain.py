#!/usr/bin/env python3
"""Render bounded EMF from a fresh canonical finalized-observer result.

The caller must pass the direct result of ``observer.observe`` from the current
poll.  This module cannot verify chain cryptography, checkpoint provenance, or
continuous service health; it never reads a retained checkpoint.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path
import re
from typing import Any

_SPEC = importlib.util.spec_from_file_location("validator_monitoring_config", Path(__file__).with_name("validator_monitoring_config.py"))
if _SPEC is None or _SPEC.loader is None: raise RuntimeError("validator monitoring config module is unavailable")
_CONFIG = importlib.util.module_from_spec(_SPEC); _SPEC.loader.exec_module(_CONFIG)
build_config = _CONFIG.build_config

NAMESPACE = "NodeOperator/Validator"
DIMENSIONS = ["Deployment", "Network", "ValidatorSet", "Component"]
COMPONENT = "chain-observer"
MAX_EPOCHS = 128
IDENTITY_FIELDS = {"validator_set", "validator_public_key", "validator_index", "deployment_name", "release_revision", "activation_slot"}
RESULT_EXTRA_FIELDS = {"private_beacon_url", "public_beacon_url", "workload_proof_path", "log_delivery_proof_path"}
UINT = re.compile(r"0|[1-9][0-9]*\Z")
SHA = re.compile(r"[0-9a-f]{40}\Z")
METRIC_NAMES = ("ChainObservationAvailable", "VerifiedFinalizedEpochCount", "LatestVerifiedAttestationEpoch")


class ChainMonitoringError(ValueError): pass


def _identity(context: dict[str, Any]) -> dict[str, str]:
    if not isinstance(context, dict) or not {"identity", "aws_region"} <= set(context) or not isinstance(context["identity"], dict):
        raise ChainMonitoringError("invalid observation context")
    identity = context["identity"]
    if set(identity) != IDENTITY_FIELDS or not all(isinstance(value, str) and value for value in identity.values()):
        raise ChainMonitoringError("invalid expected identity")
    # Reuse the deployment/region/set/key input authority without emitting the key.
    build_config(identity["deployment_name"], context["aws_region"], identity["validator_set"], identity["validator_public_key"])
    if (UINT.fullmatch(identity["validator_index"]) is None or UINT.fullmatch(identity["activation_slot"]) is None or
            SHA.fullmatch(identity["release_revision"]) is None):
        raise ChainMonitoringError("invalid numeric identity")
    return identity


def _epochs(result: dict[str, Any], expected: dict[str, str]) -> list[int]:
    required = {"schema_version", "identity", "consecutive_finalized_epochs", "required_finalized_epochs", "complete"}
    if set(result) != required or type(result["schema_version"]) is not int or result["schema_version"] != 1:
        raise ChainMonitoringError("invalid observer result schema")
    identity = result["identity"]
    if not isinstance(identity, dict) or set(identity) != IDENTITY_FIELDS | RESULT_EXTRA_FIELDS:
        raise ChainMonitoringError("observer identity is not a direct canonical-observer identity")
    if any(identity[field] != expected[field] for field in IDENTITY_FIELDS) or any(not isinstance(identity[field], str) or not identity[field] for field in RESULT_EXTRA_FIELDS):
        raise ChainMonitoringError("observer identity differs from expected context")
    count = result["required_finalized_epochs"]
    if type(count) is not int or count not in (1, 2, 3) or type(result["complete"]) is not bool:
        raise ChainMonitoringError("invalid observer threshold state")
    rows = result["consecutive_finalized_epochs"]
    if not isinstance(rows, list) or len(rows) > MAX_EPOCHS:
        raise ChainMonitoringError("invalid finalized epoch sequence")
    values: list[int] = []
    for row in rows:
        if not isinstance(row, str) or UINT.fullmatch(row) is None:
            raise ChainMonitoringError("epoch must be a canonical decimal string")
        values.append(int(row))
    activation_epoch = int(expected["activation_slot"]) // 32
    # The observer proved the actual slot is after activation. An epoch equal
    # to activation_slot // 32 can therefore be valid; this renderer sees only
    # epoch labels and must not invent a stronger slot claim.
    if any(value < activation_epoch for value in values) or any(right != left + 1 for left, right in zip(values, values[1:])):
        raise ChainMonitoringError("epochs are not unique, post-activation, ordered, and contiguous")
    if result["complete"] != (len(values) >= count):
        raise ChainMonitoringError("observer complete flag contradicts fresh proofs")
    return values


def render(context: dict[str, Any], result: dict[str, Any] | None, available: bool, current_ms: int) -> dict[str, Any]:
    """Return one EMF object; unavailable input emits availability only."""
    expected = _identity(context)
    if type(available) is not bool or type(current_ms) is not int or not 0 <= current_ms <= 2**63 - 1:
        raise ChainMonitoringError("invalid availability or timestamp")
    event: dict[str, Any] = {"_aws": {"Timestamp": current_ms, "CloudWatchMetrics": [{"Namespace": NAMESPACE, "Dimensions": [DIMENSIONS], "Metrics": [{"Name": "ChainObservationAvailable", "Unit": "Count"}]}]},
                             "Deployment": expected["deployment_name"], "Network": "hoodi", "ValidatorSet": expected["validator_set"], "Component": COMPONENT,
                             "ChainObservationAvailable": 1 if available else 0}
    if not available:
        return event
    if not isinstance(result, dict): raise ChainMonitoringError("available observation needs a fresh result object")
    epochs = _epochs(result, expected)
    metrics = event["_aws"]["CloudWatchMetrics"][0]["Metrics"]
    metrics.append({"Name": "VerifiedFinalizedEpochCount", "Unit": "Count"})
    event["VerifiedFinalizedEpochCount"] = len(epochs)
    if epochs:
        metrics.append({"Name": "LatestVerifiedAttestationEpoch", "Unit": "Count"})
        event["LatestVerifiedAttestationEpoch"] = epochs[-1]
    return event
