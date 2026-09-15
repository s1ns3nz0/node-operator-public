#!/usr/bin/env python3
"""Build the bounded client telemetry and aggregate log-delivery dashboard.

The document is local JSON suitable for later reviewed Terraform binding. It
does not call AWS, read log events, or claim a deployed collector is healthy.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path
from typing import Any

_CONFIG_SPEC = importlib.util.spec_from_file_location(
    "validator_monitoring_config", Path(__file__).with_name("validator_monitoring_config.py")
)
if _CONFIG_SPEC is None or _CONFIG_SPEC.loader is None:
    raise RuntimeError("validator monitoring config module is unavailable")
_CONFIG_MODULE = importlib.util.module_from_spec(_CONFIG_SPEC)
_CONFIG_SPEC.loader.exec_module(_CONFIG_MODULE)
_CHAIN_SPEC = importlib.util.spec_from_file_location(
    "validator_monitoring_chain", Path(__file__).with_name("validator_monitoring_chain.py")
)
if _CHAIN_SPEC is None or _CHAIN_SPEC.loader is None:
    raise RuntimeError("validator chain monitoring module is unavailable")
_CHAIN_MODULE = importlib.util.module_from_spec(_CHAIN_SPEC)
_CHAIN_SPEC.loader.exec_module(_CHAIN_MODULE)
# Direct EMF is produced by the canonical observer, not scraped from a client.
# Never extend the Prometheus client allowlist with invented client metrics.
METRIC_ALLOWLIST = {**_CONFIG_MODULE.METRIC_ALLOWLIST, "chain-observer": _CHAIN_MODULE.METRIC_NAMES}
build_config = _CONFIG_MODULE.build_config

NAMESPACE = "NodeOperator/Validator"
DIMENSION_NAMES = ("Deployment", "Network", "ValidatorSet", "Component")
NETWORK = "hoodi"
PERIOD_SECONDS = 60


def _dimensions(deployment: str, validator_set: str, component: str) -> list[str]:
    return ["Deployment", deployment, "Network", NETWORK, "ValidatorSet", validator_set, "Component", component]


def _metric(
    name: str, component: str, deployment: str, region: str, validator_set: str, stat: str = "Maximum"
) -> list[Any]:
    if component not in METRIC_ALLOWLIST or name not in METRIC_ALLOWLIST[component]:
        raise ValueError("metric is not present in the approved collector allowlist")
    return [
        NAMESPACE,
        name,
        *_dimensions(deployment, validator_set, component),
        {"stat": stat, "period": PERIOD_SECONDS, "region": region},
    ]


def _metric_widget(title: str, metrics: list[list[Any]], x: int, y: int, width: int, height: int) -> dict[str, Any]:
    return {
        "type": "metric",
        "x": x,
        "y": y,
        "width": width,
        "height": height,
        "properties": {"title": title, "view": "timeSeries", "region": metrics[0][-1]["region"], "metrics": metrics},
    }


def _log_widget(title: str, query: str, region: str, y: int, height: int = 5) -> dict[str, Any]:
    return {"type": "log", "x": 0, "y": y, "width": 24, "height": height,
            "properties": {"title": title, "region": region, "view": "table", "query": query}}


def _workload_query(deployment: str, validator_set: str, component: str) -> str:
    # JSON parsing handles Fluent Bit's outer record; special-character label
    # names use Logs Insights map access. Only final aggregate fields display.
    return (
        f"SOURCE '/aws/eks/{deployment}/validator-workloads'"
        " | fields jsonParse(@message) as record"
        " | filter record.kubernetes.namespace_name = 'validator-operations'"
        f" and record.kubernetes.labels.`node-operator.io/deployment-name` = '{deployment}'"
        f" and record.kubernetes.labels.`node-operator.io/validator-set` = '{validator_set}'"
        f" and record.kubernetes.labels.`app.kubernetes.io/component` = '{component}'"
    )


def build_dashboard(deployment: str, region: str, validator_set: str, public_key: str) -> dict[str, Any]:
    """Return a JSON-valid staged dashboard using only renderer-allowlisted metrics."""
    # Reuse the authoritative input validation and metric allowlist source. The
    # public key is intentionally not put into a dashboard dimension or widget.
    build_config(deployment, region, validator_set, public_key)

    consensus_slots = [
        _metric(name, "beacon", deployment, region, validator_set)
        for name in ("beacon_head_slot", "beacon_clock_time_slot")
    ]
    finalized_epochs = [
        _metric(name, "beacon", deployment, region, validator_set)
        for name in ("beacon_finalized_epoch", "head_finalized_epoch")
    ]
    execution_blocks = [
        _metric(name, "execution", deployment, region, validator_set)
        for name in ("ethereum_blockchain_height", "ethereum_best_known_block_number")
    ]
    execution_peers = [
        _metric(name, "execution", deployment, region, validator_set)
        for name in ("ethereum_peer_count", "ethereum_peer_limit")
    ]
    validator_balance = [
        _metric("validator_balance", "validator", deployment, region, validator_set)
    ]
    validator_last_attested_slot = [
        _metric("validator_last_attested_slot", "validator", deployment, region, validator_set)
    ]
    validator_correct_votes = [
        _metric(name, "validator", deployment, region, validator_set)
        for name in (
            "validator_correctly_voted_head",
            "validator_correctly_voted_source",
            "validator_correctly_voted_target",
        )
    ]
    submissions = [
        _metric(name, "validator", deployment, region, validator_set, "Sum")
        for name in ("validator_successful_attestations", "validator_failed_attestations")
    ]

    log_group = f"/aws/eks/{deployment}/validator-metrics"
    return {
        "start": "-PT3H",
        "periodOverride": "inherit",
        "widgets": [
            {
                "type": "text",
                "x": 0,
                "y": 0,
                "width": 24,
                "height": 3,
                "properties": {
                    "markdown": (
                        "# Validator telemetry and aggregate log delivery\n"
                        "Missing telemetry is **unknown**, not healthy. Zero client replicas are expected to appear unavailable before activation. "
                        "Event age above 180 seconds is stale; absent rows or future timestamps are unknown. "
                        "A client-reported balance of 0 can mean unknown or pending and is not independent chain-balance proof. "
                        "Client metrics, signer results and Fence TCP intervals are not finalized duties. "
                        "Chain widgets require fresh dual-source observer EMF delivery; missing delivery is unknown. "
                        "A verified epoch count is the current consecutive proof window, not a lifetime total. "
                        "Log tables show aggregate delivery only. Empty results may mean idle, unavailable or delayed logs, not zero failures. "
                        "Counts include duplicate deliveries and are not unique operations. Log ages use CloudWatch event timestamps, not independent execution timestamps. "
                        "Vault delivery covers the shared deployment, not one validator or proof of successful Vault operations."
                    )
                },
            },
            {
                "type": "log",
                "x": 0,
                "y": 3,
                "width": 24,
                "height": 4,
                "properties": {
                    "title": "EMF event age: over 180s is stale (log presence only)",
                    "region": region,
                    "view": "table",
                    "query": (
                        f"SOURCE '{log_group}'"
                        f" | filter Deployment = '{deployment}' and Network = 'hoodi' and ValidatorSet = '{validator_set}'"
                        " | filter Component in ['beacon', 'execution', 'validator', 'chain-observer']"
                        " | stats max(@timestamp) as last_event_timestamp by Component"
                        " | fields Component, last_event_timestamp, (now() * 1000 - toMillis(last_event_timestamp)) / 1000 as age_seconds"
                        " | sort age_seconds desc"
                    ),
                },
            },
            _metric_widget("Consensus slots", consensus_slots, 0, 7, 12, 5),
            _metric_widget("Consensus finalized epochs", finalized_epochs, 12, 7, 12, 5),
            _metric_widget("Execution block numbers", execution_blocks, 0, 12, 12, 5),
            _metric_widget("Execution peers and peer limit", execution_peers, 12, 12, 12, 5),
            _metric_widget("Client-reported validator balance (ETH)", validator_balance, 0, 17, 12, 5),
            _metric_widget("Validator last attested slot", validator_last_attested_slot, 12, 17, 12, 5),
            _metric_widget("Client-reported correct-vote gauges", validator_correct_votes, 0, 22, 24, 5),
            _metric_widget("Client-reported submission counters (not finalized proof)", submissions, 0, 27, 24, 5),
            _log_widget(
                "Signer-reported results (not finalized duties)",
                _workload_query(deployment, validator_set, "validator-remote-signer")
                + " | parse record.log /signing_audit audit_request_id=[^ ]+ result=(?<signer_result>[A-Z_]+)/"
                + " | filter signer_result in ['SUCCESS', 'REJECTED_SLASHING', 'NOT_FOUND', 'INVALID_REQUEST']"
                + " | stats count() as delivered_records, max(@timestamp) as last_event_timestamp by signer_result"
                + " | fields signer_result, delivered_records, last_event_timestamp, (now() * 1000 - toMillis(last_event_timestamp)) / 1000 as age_seconds"
                + " | sort signer_result asc",
                region, 32,
            ),
            _log_widget(
                "Fence TCP interval results (not TLS or signing verification)",
                _workload_query(deployment, validator_set, "validator-signing-fence")
                + f" | filter record.log like /fence_connection validator_set={validator_set} /"
                + " | parse record.log / result=(?<connection_result>[a-z-]+)/"
                + " | filter connection_result in ['closed', 'upstream-dial-failed', 'authority-expired']"
                + " | stats count() as delivered_interval_records, max(@timestamp) as last_event_timestamp by connection_result"
                + " | fields connection_result, delivered_interval_records, last_event_timestamp, (now() * 1000 - toMillis(last_event_timestamp)) / 1000 as age_seconds"
                + " | sort connection_result asc",
                region, 37,
            ),
            _log_widget(
                "Vault audit relay delivery (shared deployment; no raw audit records)",
                f"SOURCE '/aws/eks/{deployment}/validator-security'"
                + " | fields jsonParse(@message) as record"
                + " | filter record.kubernetes.namespace_name = 'vault'"
                + " and record.kubernetes.container_name = 'vault-validator-audit-relay'"
                + r" | parse record.log /^(?:[0-9TZ:.+-]+ (?:stdout|stderr) [FP] )?(?<relay_json>\{.*\})\s*$/"
                + " | fields jsonParse(relay_json) as relay"
                + " | filter relay.schema_version = 1 and relay.audit_source in ['file', 'socket']"
                + " | stats count() as delivered_records, max(@timestamp) as last_event_timestamp by relay.audit_source"
                + " | fields relay.audit_source, delivered_records, last_event_timestamp, (now() * 1000 - toMillis(last_event_timestamp)) / 1000 as age_seconds"
                + " | sort relay.audit_source asc",
                region, 42,
            ),
            _metric_widget(
                "Fresh chain observation available (0 unavailable; missing unknown)",
                [_metric("ChainObservationAvailable", "chain-observer", deployment, region, validator_set, "Minimum")],
                0, 47, 24, 5,
            ),
            _metric_widget(
                "Verified consecutive finalized epochs (not lifetime total)",
                [_metric("VerifiedFinalizedEpochCount", "chain-observer", deployment, region, validator_set)],
                0, 52, 12, 5,
            ),
            _metric_widget(
                "Latest freshly verified attestation epoch",
                [_metric("LatestVerifiedAttestationEpoch", "chain-observer", deployment, region, validator_set)],
                12, 52, 12, 5,
            ),
        ],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Render a staged validator CloudWatch dashboard JSON document")
    parser.add_argument("--deployment", required=True)
    parser.add_argument("--region", required=True)
    parser.add_argument("--validator-set", required=True)
    parser.add_argument("--public-key", required=True)
    args = parser.parse_args(argv)
    try:
        print(json.dumps(build_dashboard(args.deployment, args.region, args.validator_set, args.public_key), sort_keys=True))
    except ValueError as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
