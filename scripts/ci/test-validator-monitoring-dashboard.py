#!/usr/bin/env python3
# Check objective: Validate the staged validator monitoring dashboard.
"""Offline contract tests for the staged validator monitoring dashboard."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
RELEASE = ROOT / "scripts/release"
sys.path.insert(0, str(RELEASE))
spec = importlib.util.spec_from_file_location("dashboard", RELEASE / "validator_monitoring_dashboard.py")
dashboard = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(dashboard)

DEPLOYMENT = "hoodi-node"
REGION = "ap-northeast-2"
VALIDATOR_SET = "hoodi-a"
PUBLIC_KEY = "0x" + "a" * 96


class ValidatorMonitoringDashboardTest(unittest.TestCase):
    def setUp(self):
        self.document = dashboard.build_dashboard(DEPLOYMENT, REGION, VALIDATOR_SET, PUBLIC_KEY)
        self.widgets = self.document["widgets"]
        self.metric_widgets = [widget for widget in self.widgets if widget["type"] == "metric"]

    def test_dashboard_has_bounded_layout_and_truthful_header(self):
        self.assertEqual(self.document["periodOverride"], "inherit")
        self.assertEqual(len(self.widgets), 16)
        for widget in self.widgets:
            self.assertGreaterEqual(widget["x"], 0)
            self.assertGreaterEqual(widget["y"], 0)
            self.assertGreater(widget["width"], 0)
            self.assertGreater(widget["height"], 0)
            self.assertLessEqual(widget["x"] + widget["width"], 24)
            self.assertLessEqual(widget["y"] + widget["height"], 100)
        for index, left in enumerate(self.widgets):
            for right in self.widgets[index + 1:]:
                horizontal_overlap = left["x"] < right["x"] + right["width"] and right["x"] < left["x"] + left["width"]
                vertical_overlap = left["y"] < right["y"] + right["height"] and right["y"] < left["y"] + left["height"]
                self.assertFalse(horizontal_overlap and vertical_overlap, f"widgets overlap: {left} {right}")
        header = self.widgets[0]["properties"]["markdown"].lower()
        self.assertIn("missing telemetry is **unknown**", header)
        self.assertIn("zero client replicas", header)
        self.assertIn("balance of 0 can mean unknown or pending", header)
        self.assertIn("not independent chain-balance proof", header)
        self.assertIn("fresh dual-source observer emf delivery", header)
        self.assertIn("not a lifetime total", header)

    def test_metrics_are_allowlisted_dimensionally_consistent_and_input_bound(self):
        expected_dimensions = ["Deployment", DEPLOYMENT, "Network", "hoodi", "ValidatorSet", VALIDATOR_SET]
        for widget in self.metric_widgets:
            self.assertEqual(widget["properties"]["region"], REGION)
            for metric in widget["properties"]["metrics"]:
                namespace, name, *dimensions, options = metric
                self.assertEqual(namespace, dashboard.NAMESPACE)
                self.assertEqual(dimensions[:6], expected_dimensions)
                self.assertEqual(dimensions[6], "Component")
                component = dimensions[7]
                self.assertIn(component, dashboard.METRIC_ALLOWLIST)
                self.assertIn(name, dashboard.METRIC_ALLOWLIST[component])
                self.assertEqual(options["period"], 60)
                self.assertEqual(options["region"], REGION)

    def test_submission_counters_use_sum_without_counter_derivative_or_fill(self):
        submissions = next(widget["properties"] for widget in self.metric_widgets if "submission counters" in widget["properties"]["title"])
        self.assertEqual({metric[1] for metric in submissions["metrics"]}, {
            "validator_successful_attestations", "validator_failed_attestations"
        })
        self.assertTrue(all(metric[-1]["stat"] == "Sum" for metric in submissions["metrics"]))
        serialized = json.dumps(self.document).upper()
        self.assertNotIn("FILL(", serialized)
        self.assertNotIn("RATE(", serialized)
        self.assertNotIn("DERIVATIVE", serialized)

    def test_freshness_query_is_a_component_table_of_event_timestamps_only(self):
        log_widget = next(widget for widget in self.widgets if widget["type"] == "log")
        query = log_widget["properties"]["query"]
        self.assertEqual(log_widget["properties"]["region"], REGION)
        self.assertIn(f"SOURCE '/aws/eks/{DEPLOYMENT}/validator-metrics'", query)
        self.assertEqual(log_widget["properties"]["view"], "table")
        self.assertIn("stats max(@timestamp) as last_event_timestamp by Component", query)
        self.assertIn(f"Deployment = '{DEPLOYMENT}'", query)
        self.assertIn(f"ValidatorSet = '{VALIDATOR_SET}'", query)
        self.assertIn("Network = 'hoodi'", query)
        self.assertIn("now() * 1000 - toMillis(last_event_timestamp)", query)
        self.assertIn("as age_seconds", query)
        self.assertIn("absent rows or future timestamps are unknown", self.widgets[0]["properties"]["markdown"])
        self.assertNotIn("@message", query)
        self.assertIn("log presence only", log_widget["properties"]["title"].lower())

    def test_each_metric_widget_has_one_homogeneous_unit_family(self):
        metric_names_by_title = {
            widget["properties"]["title"]: {metric[1] for metric in widget["properties"]["metrics"]}
            for widget in self.metric_widgets
        }
        self.assertEqual(metric_names_by_title, {
            "Consensus slots": {"beacon_head_slot", "beacon_clock_time_slot"},
            "Consensus finalized epochs": {"beacon_finalized_epoch", "head_finalized_epoch"},
            "Execution block numbers": {"ethereum_blockchain_height", "ethereum_best_known_block_number"},
            "Execution peers and peer limit": {"ethereum_peer_count", "ethereum_peer_limit"},
            "Client-reported validator balance (ETH)": {"validator_balance"},
            "Validator last attested slot": {"validator_last_attested_slot"},
            "Client-reported correct-vote gauges": {
                "validator_correctly_voted_head", "validator_correctly_voted_source", "validator_correctly_voted_target"
            },
            "Client-reported submission counters (not finalized proof)": {
                "validator_successful_attestations", "validator_failed_attestations"
            },
            "Fresh chain observation available (0 unavailable; missing unknown)": {"ChainObservationAvailable"},
            "Verified consecutive finalized epochs (not lifetime total)": {"VerifiedFinalizedEpochCount"},
            "Latest freshly verified attestation epoch": {"LatestVerifiedAttestationEpoch"},
        })

    def test_dashboard_contains_no_secret_or_public_key_and_no_invented_finalized_proof(self):
        serialized = json.dumps(self.document).lower()
        self.assertNotIn(PUBLIC_KEY, serialized)
        for prohibited in ("secret", "password", "access_key", "private key"):
            self.assertNotIn(prohibited, serialized)
        titles = [widget["properties"].get("title", "").lower() for widget in self.widgets]
        self.assertFalse(any("finalized attestation" in title for title in titles))

    def test_log_widgets_are_scoped_aggregates_not_raw_records_or_health_claims(self):
        logs = [w["properties"] for w in self.widgets if w["type"] == "log"][1:]
        self.assertEqual(len(logs), 3)
        for props in logs:
            query = props["query"]
            self.assertEqual(props["region"], REGION)
            self.assertIn(" | stats count()", query)
            self.assertIn("as age_seconds", query)
            # Sensitive source objects can be parsed, but only count/time and
            # bounded result/source names survive the final stats projection.
            final = query.split(" | stats ", 1)[1]
            for field in ("record.log", "relay.log", "@message", "signing_root", "public_key"):
                self.assertNotIn(field, final)
        for props in logs[:2]:
            self.assertIn(f"node-operator.io/deployment-name` = '{DEPLOYMENT}'", props["query"])
            self.assertIn(f"node-operator.io/validator-set` = '{VALIDATOR_SET}'", props["query"])
        self.assertIn("'SUCCESS', 'REJECTED_SLASHING', 'NOT_FOUND', 'INVALID_REQUEST'", logs[0]["query"])
        self.assertIn("not TLS or signing", logs[1]["title"])
        self.assertIn("'closed', 'upstream-dial-failed', 'authority-expired'", logs[1]["query"])
        self.assertIn("shared deployment", logs[2]["title"])
        self.assertIn("container_name = 'vault-validator-audit-relay'", logs[2]["query"])
        self.assertIn("['file', 'socket']", logs[2]["query"])
        self.assertIn("not zero failures", self.widgets[0]["properties"]["markdown"])
        self.assertIn("not unique operations", self.widgets[0]["properties"]["markdown"])

    def test_chain_metrics_use_actual_producer_without_inventing_prometheus_targets(self):
        self.assertEqual(dashboard.METRIC_ALLOWLIST["chain-observer"], dashboard._CHAIN_MODULE.METRIC_NAMES)
        self.assertNotIn("chain-observer", dashboard._CONFIG_MODULE.METRIC_ALLOWLIST)
        availability = next(w["properties"] for w in self.metric_widgets if "observation available" in w["properties"]["title"])
        self.assertEqual(availability["metrics"][0][-1]["stat"], "Minimum")

    def test_standalone_isolated_cli_renders_json_without_ambient_python_path(self):
        command = [
            sys.executable, "-I", "-B", str(RELEASE / "validator_monitoring_dashboard.py"),
            "--deployment", DEPLOYMENT, "--region", REGION, "--validator-set", VALIDATOR_SET,
            "--public-key", PUBLIC_KEY,
        ]
        rendered = subprocess.run(command, check=True, capture_output=True, text=True, timeout=10)
        self.assertEqual(json.loads(rendered.stdout)["widgets"][0]["type"], "text")


if __name__ == "__main__":
    unittest.main()
