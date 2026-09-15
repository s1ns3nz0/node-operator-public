#!/usr/bin/env python3
"""Render the bounded private Prometheus and CloudWatch Agent configurations.

This module intentionally has no filesystem, network, or YAML-library dependency.
It produces JSON-compatible Python dictionaries which a release renderer can encode as
YAML or JSON after the collector image and workload have separately been approved.
"""

from __future__ import annotations

import argparse
import json
import re
from typing import Any


class ConfigError(ValueError):
    """Raised when an identifier is unsafe for a fixed configuration value."""


_DNS_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_COMMERCIAL_REGION = re.compile(
    r"(?:us(?!-gov)|af|ap|ca|eu|il|me|sa)-[a-z0-9]+(?:-[a-z0-9]+)*-[1-9][0-9]*$"
)
# Prysm's validator metrics identify an account with a 0x-prefixed, 48-byte BLS
# public key.  Requiring canonical lowercase prevents a case-only filter miss.
_VALIDATOR_PUBLIC_KEY = re.compile(r"0x[0-9a-f]{96}$")
_VALIDATOR_CLIENT_SERVICE_PREFIX = "validator-"
_VALIDATOR_CLIENT_SERVICE_SUFFIX = "-client-headless"
_MAX_DNS_LABEL_LENGTH = 63
_MAX_VALIDATOR_SET_LENGTH = (
    _MAX_DNS_LABEL_LENGTH - len(_VALIDATOR_CLIENT_SERVICE_PREFIX) - len(_VALIDATOR_CLIENT_SERVICE_SUFFIX)
)

METRIC_ALLOWLIST = {
    "beacon": (
        "beacon_head_slot",
        "beacon_clock_time_slot",
        "beacon_finalized_epoch",
        "head_finalized_epoch",
    ),
    "execution": (
        "ethereum_blockchain_height",
        "ethereum_best_known_block_number",
        "ethereum_peer_count",
        "ethereum_peer_limit",
    ),
    "validator": (
        "validator_balance",
        "validator_last_attested_slot",
        "validator_correctly_voted_source",
        "validator_correctly_voted_target",
        "validator_correctly_voted_head",
        "validator_successful_attestations",
        "validator_failed_attestations",
    ),
}
_DIMENSIONS = ["Deployment", "Network", "ValidatorSet", "Component"]
# Agent v1.300071.0 uses these internal labels for metric type lookup and
# removes them before EMF output. Dropping them silently discards the batch.
_KEEP_LABELS = "^(__name__|Deployment|Network|ValidatorSet|Component|cwagent_saved_scrape_(job|instance|name))$"


def _require(pattern: re.Pattern[str], value: str, name: str) -> None:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise ConfigError(f"invalid {name}")


def _require_validator_set(validator_set: str) -> None:
    _require(_DNS_LABEL, validator_set, "validator set")
    if len(validator_set) > _MAX_VALIDATOR_SET_LENGTH:
        raise ConfigError("invalid validator set")


def _metric_regex(component: str) -> str:
    return "^(" + "|".join(METRIC_ALLOWLIST[component]) + ")$"


def _static_labels(deployment: str, validator_set: str, component: str) -> dict[str, str]:
    return {
        "Deployment": deployment,
        "Network": "hoodi",
        "ValidatorSet": validator_set,
        "Component": component,
    }


def _scrape_job(
    name: str, target: str, labels: dict[str, str], metric_regex: str, public_key: str | None = None
) -> dict[str, Any]:
    relabels: list[dict[str, Any]] = []
    if public_key is not None:
        # This is a source filter, not a static label: accounts other than the
        # selected validator never reach EMF, and the account label is then removed.
        relabels.append({"source_labels": ["pubkey"], "regex": public_key, "action": "keep"})
    relabels.extend(
        [
            {"source_labels": ["__name__"], "regex": metric_regex, "action": "keep"},
            {"action": "labelkeep", "regex": _KEEP_LABELS},
        ]
    )
    return {
        "job_name": name,
        "metrics_path": "/metrics",
        "sample_limit": 100,
        "static_configs": [{"targets": [target], "labels": labels}],
        "metric_relabel_configs": relabels,
    }


def build_config(deployment: str, region: str, validator_set: str, public_key: str) -> dict[str, dict[str, Any]]:
    """Return JSON-valid Prometheus and CloudWatch Agent configurations.

    The renderer does not assert that the proposed private metrics ports are exposed
    by a deployment. In particular, Nethermind's :6060 is a proposed renderer port.
    Client counters stay source counters: the CloudWatch Agent owns their delta export.
    """
    _require(_DNS_LABEL, deployment, "deployment")
    _require(_COMMERCIAL_REGION, region, "AWS commercial region")
    _require_validator_set(validator_set)
    _require(_VALIDATOR_PUBLIC_KEY, public_key, "validator public key")

    jobs = (
        ("validator-beacon", "prysm-beacon.node-operator.svc:8080", "beacon", None),
        ("validator-execution", "nethermind-execution.node-operator.svc:6060", "execution", None),
        (
            "validator-client",
            f"{_VALIDATOR_CLIENT_SERVICE_PREFIX}{validator_set}{_VALIDATOR_CLIENT_SERVICE_SUFFIX}.validator-operations.svc:8081",
            "validator",
            public_key,
        ),
    )
    prometheus = {
        "global": {"scrape_interval": "60s", "scrape_timeout": "10s"},
        "scrape_configs": [
            _scrape_job(name, target, _static_labels(deployment, validator_set, component), _metric_regex(component), key)
            for name, target, component, key in jobs
        ],
    }
    declarations = [
        {
            "source_labels": ["Component"],
            "label_matcher": f"^{component}$",
            "dimensions": [_DIMENSIONS],
            "metric_selectors": [_metric_regex(component)],
        }
        for component in ("beacon", "execution", "validator")
    ]
    cwagent = {
        "agent": {"region": region},
        "logs": {
            "metrics_collected": {
                "prometheus": {
                    "cluster_name": deployment,
                    "prometheus_config_path": "env:PROMETHEUS_CONFIG_CONTENT",
                    "log_group_name": f"/aws/eks/{deployment}/validator-metrics",
                    "emf_processor": {
                        "metric_namespace": "NodeOperator/Validator",
                        "metric_declaration": declarations,
                    },
                }
            }
        },
    }
    return {"prometheus": prometheus, "cwagent": cwagent}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Render bounded validator monitoring configuration as JSON")
    parser.add_argument("--deployment", required=True)
    parser.add_argument("--region", required=True)
    parser.add_argument("--validator-set", required=True)
    parser.add_argument("--public-key", required=True)
    args = parser.parse_args(argv)
    try:
        print(json.dumps(build_config(args.deployment, args.region, args.validator_set, args.public_key), sort_keys=True))
    except ConfigError as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
