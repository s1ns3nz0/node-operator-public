#!/usr/bin/env python3
# Check objective: Validate validator monitoring configuration rendering.
"""Contract tests for the pure validator monitoring configuration renderer.

These local tests prove selection and bounded configuration only. They do not prove
that a collector runs, an endpoint is reachable, or CloudWatch ingests a metric.
"""

from __future__ import annotations

import importlib.util
import json
import pathlib
import re
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "scripts/release/validator_monitoring_config.py"
SPEC = importlib.util.spec_from_file_location("validator_monitoring_config", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

KEY = "0x" + "ab" * 48


def apply_metric_relabels(sample, relabels):
    """Small local model of the keep/labelkeep rules in this generated config.

    It tests configuration selection semantics only; it is not a CloudWatch Agent
    execution or ingestion test.
    """
    kept = dict(sample)
    for rule in relabels:
        if rule["action"] == "keep":
            value = rule.get("separator", ";").join(kept.get(label, "") for label in rule["source_labels"])
            if re.fullmatch(rule["regex"], value) is None:
                return None
        elif rule["action"] == "labelkeep":
            kept = {key: value for key, value in kept.items() if re.fullmatch(rule["regex"], key)}
        else:
            raise AssertionError(f"unexpected test rule: {rule['action']}")
    return kept


class ValidatorMonitoringConfigTests(unittest.TestCase):
    def render(self):
        return MODULE.build_config("node-operator", "ap-northeast-2", "hoodi-test-001", KEY)

    def test_json_valid_fixed_targets_and_intervals(self):
        rendered = self.render()
        self.assertEqual(json.loads(json.dumps(rendered)), rendered)
        prometheus = rendered["prometheus"]
        self.assertEqual(prometheus["global"], {"scrape_interval": "60s", "scrape_timeout": "10s"})
        jobs = {job["job_name"]: job for job in prometheus["scrape_configs"]}
        self.assertEqual(jobs["validator-beacon"]["static_configs"][0]["targets"], ["prysm-beacon.node-operator.svc:8080"])
        self.assertEqual(jobs["validator-execution"]["static_configs"][0]["targets"], ["nethermind-execution.node-operator.svc:6060"])
        self.assertEqual(jobs["validator-client"]["static_configs"][0]["targets"], ["validator-hoodi-test-001-client-headless.validator-operations.svc:8081"])
        self.assertTrue(all(job["sample_limit"] == 100 for job in jobs.values()))

    def test_only_allowlisted_metrics_and_selected_validator_survive(self):
        jobs = {job["job_name"]: job for job in self.render()["prometheus"]["scrape_configs"]}
        validator_relabels = jobs["validator-client"]["metric_relabel_configs"]
        self.assertEqual(validator_relabels[0], {"source_labels": ["pubkey"], "regex": KEY, "action": "keep"})
        self.assertEqual(validator_relabels[-1], {"action": "labelkeep", "regex": "^(__name__|Deployment|Network|ValidatorSet|Component|cwagent_saved_scrape_(job|instance|name))$"})
        for job in jobs.values():
            allowed = job["metric_relabel_configs"][-2]["regex"]
            self.assertTrue(allowed.startswith("^("))
            self.assertTrue(allowed.endswith(")$"))
            self.assertNotIn("up", allowed)
            self.assertNotIn("sync", allowed)

        labels = jobs["validator-client"]["static_configs"][0]["labels"]
        sample = {"__name__": "validator_balance", "pubkey": KEY, "index": "17", "instance": "private:8081", **labels}
        self.assertEqual(
            apply_metric_relabels(sample, validator_relabels),
            {"__name__": "validator_balance", **labels},
        )
        internal = {
            "cwagent_saved_scrape_job": "validator-client",
            "cwagent_saved_scrape_instance": "private:8081",
            "cwagent_saved_scrape_name": "validator_balance",
        }
        self.assertEqual(
            apply_metric_relabels({**sample, **internal}, validator_relabels),
            {"__name__": "validator_balance", **labels, **internal},
        )
        other_key = {**sample, "pubkey": "0x" + "cd" * 48}
        self.assertIsNone(apply_metric_relabels(other_key, validator_relabels))
        self.assertIsNone(apply_metric_relabels({key: value for key, value in sample.items() if key != "pubkey"}, validator_relabels))
        self.assertIsNone(apply_metric_relabels({**sample, "__name__": "validator_statuses"}, validator_relabels))

    def test_emf_uses_one_bounded_dimension_set_and_expected_namespace(self):
        prometheus = self.render()["cwagent"]["logs"]["metrics_collected"]["prometheus"]
        self.assertEqual(prometheus["cluster_name"], "node-operator")
        self.assertEqual(prometheus["prometheus_config_path"], "env:PROMETHEUS_CONFIG_CONTENT")
        self.assertEqual(prometheus["log_group_name"], "/aws/eks/node-operator/validator-metrics")
        self.assertEqual(prometheus["emf_processor"]["metric_namespace"], "NodeOperator/Validator")
        declarations = prometheus["emf_processor"]["metric_declaration"]
        self.assertEqual([declaration["dimensions"] for declaration in declarations], [[ ["Deployment", "Network", "ValidatorSet", "Component"] ]] * 3)
        self.assertEqual({item["label_matcher"] for item in declarations}, {"^beacon$", "^execution$", "^validator$"})

    def test_missing_scrape_target_has_no_synthetic_health_metric(self):
        # A static target may be unreachable at runtime. This renderer neither
        # emits `up` nor replaces absent source samples with a healthy zero.
        rendered = self.render()
        encoded = json.dumps(rendered, sort_keys=True)
        self.assertNotIn('"up"', encoded)
        self.assertNotIn('"sync"', encoded)
        for job in rendered["prometheus"]["scrape_configs"]:
            self.assertTrue(all(rule["action"] in {"keep", "labelkeep"} for rule in job["metric_relabel_configs"]))

    def test_invalid_identifiers_and_keys_fail_before_any_config(self):
        invalid = [
            ("../node-operator", "ap-northeast-2", "hoodi-test-001", KEY),
            ("node-operator", "us-gov-west-1", "hoodi-test-001", KEY),
            ("node-operator", "cn-north-1", "hoodi-test-001", KEY),
            ("node-operator", "us-east", "hoodi-test-001", KEY),
            ("node-operator", "us--east-1", "hoodi-test-001", KEY),
            ("node-operator", "ap-northeast-2", "other/set", KEY),
            ("node-operator", "ap-northeast-2", "a" * 38, KEY),
            ("node-operator", "ap-northeast-2", "hoodi-test-001", "0X" + "ab" * 48),
            ("node-operator", "ap-northeast-2", "hoodi-test-001", "0x" + "AB" * 48),
            ("node-operator", "ap-northeast-2", "hoodi-test-001", "0x" + "ab" * 47),
        ]
        for values in invalid:
            with self.subTest(values=values):
                with self.assertRaises(MODULE.ConfigError):
                    MODULE.build_config(*values)

    def test_commercial_regions_and_generated_service_name_boundary_are_accepted(self):
        for region in ("us-east-1", "us-west-2", "eu-central-1", "ap-northeast-2"):
            with self.subTest(region=region):
                self.assertEqual(MODULE.build_config("node-operator", region, "hoodi-test-001", KEY)["cwagent"]["agent"]["region"], region)
        validator_set = "a" * 37
        target = MODULE.build_config("node-operator", "us-east-1", validator_set, KEY)["prometheus"]["scrape_configs"][2]["static_configs"][0]["targets"][0]
        self.assertEqual(target.split(".", 1)[0], f"validator-{validator_set}-client-headless")
        self.assertEqual(len(target.split(".", 1)[0]), 63)


if __name__ == "__main__":
    unittest.main()
