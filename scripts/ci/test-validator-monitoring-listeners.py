#!/usr/bin/env python3
# Check objective: Validate private validator metrics listener manifests.
"""Static contracts for private validator metrics listeners.

These tests inspect manifests only. They do not start clients, a collector, or
CloudWatch delivery.
"""

from __future__ import annotations

import importlib.util
import json
import pathlib
import subprocess
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
RENDERER_SPEC = importlib.util.spec_from_file_location(
    "validator_monitoring_config", ROOT / "scripts/release/validator_monitoring_config.py"
)
assert RENDERER_SPEC and RENDERER_SPEC.loader
RENDERER = importlib.util.module_from_spec(RENDERER_SPEC)
RENDERER_SPEC.loader.exec_module(RENDERER)
KEY = "0x" + "ab" * 48


def yaml_documents(path: pathlib.Path):
    program = "require 'yaml'; require 'json'; print JSON.generate(YAML.load_stream(File.read(ARGV.fetch(0))).compact)"
    result = subprocess.run(["ruby", "-e", program, str(path)], check=True, capture_output=True, text=True)
    return json.loads(result.stdout)


def document(documents, kind, name):
    return next(item for item in documents if item["kind"] == kind and item["metadata"]["name"] == name)


COLLECTOR_FROM = [{
    "namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "validator-observability"}},
    "podSelector": {"matchLabels": {"app.kubernetes.io/component": "validator-metrics-collector"}},
}]


class ValidatorMonitoringListenersTests(unittest.TestCase):
    def test_listeners_and_services_match_renderer_private_targets(self):
        jobs = {
            item["job_name"]: item
            for item in RENDERER.build_config("node-operator", "ap-northeast-2", "hoodi-test-001", KEY)["prometheus"]["scrape_configs"]
        }
        cases = (
            ("prysm", "prysm-beacon", "beacon-chain", "validator-beacon", 8080, ["--monitoring-host=0.0.0.0", "--monitoring-port=8080"]),
            ("nethermind", "nethermind-execution", "nethermind", "validator-execution", 6060, ["--Metrics.Enabled=true", "--Metrics.ExposeHost=0.0.0.0", "--Metrics.ExposePort=6060"]),
        )
        for directory, service_name, container_name, job_name, port, flags in cases:
            with self.subTest(service=service_name):
                statefulset = yaml_documents(ROOT / f"deploy/{directory}/statefulset.yaml")[0]
                service = yaml_documents(ROOT / f"deploy/{directory}/service.yaml")[0]
                container = next(item for item in statefulset["spec"]["template"]["spec"]["containers"] if item["name"] == container_name)
                self.assertTrue(set(flags).issubset(container["args"]))
                self.assertIn({"name": "metrics", "containerPort": port, "protocol": "TCP"}, container["ports"])
                self.assertIn({"name": "metrics", "port": port, "protocol": "TCP", "targetPort": "metrics"}, service["spec"]["ports"])
                self.assertEqual(jobs[job_name]["static_configs"][0]["targets"], [f"{service_name}.node-operator.svc:{port}"])

    def test_validator_client_metrics_service_and_listener_preserve_zero_activation_boundary(self):
        documents = yaml_documents(ROOT / "deploy/validator/client-template.yaml")
        service = document(documents, "Service", "validator-REPLACE_WITH_VALIDATOR_SET-client-headless")
        client = document(documents, "StatefulSet", "validator-REPLACE_WITH_VALIDATOR_SET-client")
        container = client["spec"]["template"]["spec"]["containers"][0]
        self.assertEqual(client["spec"]["replicas"], 0)
        self.assertIn("--monitoring-host=0.0.0.0", container["args"])
        self.assertIn("--monitoring-port=8081", container["args"])
        self.assertNotIn("--disable-account-metrics", container["args"])
        self.assertIn({"name": "metrics", "containerPort": 8081, "protocol": "TCP"}, container["ports"])
        self.assertEqual(service["spec"]["ports"], [{"name": "metrics", "port": 8081, "targetPort": "metrics"}])
        self.assertEqual(
            RENDERER.build_config("node-operator", "ap-northeast-2", "hoodi-test-001", KEY)["prometheus"]["scrape_configs"][2]["static_configs"][0]["targets"],
            ["validator-hoodi-test-001-client-headless.validator-operations.svc:8081"],
        )

    def test_metric_ingress_is_only_the_dedicated_collector_and_metric_port(self):
        cases = (
            (ROOT / "deploy/prysm/network-policies.yaml", "allow-prysm-metrics-ingress", 8080),
            (ROOT / "deploy/nethermind/network-policies.yaml", "allow-nethermind-metrics-ingress", 6060),
            (ROOT / "deploy/validator/client-template.yaml", "validator-REPLACE_WITH_VALIDATOR_SET-client-metrics-ingress", 8081),
        )
        for path, name, port in cases:
            with self.subTest(policy=name):
                policy = document(yaml_documents(path), "NetworkPolicy", name)
                self.assertEqual(policy["spec"]["policyTypes"], ["Ingress"])
                self.assertEqual(policy["spec"]["ingress"], [{"from": COLLECTOR_FROM, "ports": [{"protocol": "TCP", "port": port}]}])

    def test_existing_non_metrics_ingress_ports_and_images_are_not_widened(self):
        prysm = yaml_documents(ROOT / "deploy/prysm/network-policies.yaml")
        nethermind = yaml_documents(ROOT / "deploy/nethermind/network-policies.yaml")
        client = yaml_documents(ROOT / "deploy/validator/client-template.yaml")
        self.assertEqual(document(nethermind, "NetworkPolicy", "allow-prysm-engine-api-ingress")["spec"]["ingress"][0]["ports"], [{"protocol": "TCP", "port": 8551}])
        self.assertEqual(document(client, "NetworkPolicy", "validator-REPLACE_WITH_VALIDATOR_SET-beacon-ingress")["spec"]["ingress"][0]["ports"], [{"protocol": "TCP", "port": 3500}])
        for path, container_name in ((ROOT / "deploy/prysm/statefulset.yaml", "beacon-chain"), (ROOT / "deploy/nethermind/statefulset.yaml", "nethermind")):
            statefulset = yaml_documents(path)[0]
            image = next(item["image"] for item in statefulset["spec"]["template"]["spec"]["containers"] if item["name"] == container_name)
            self.assertIn("@sha256:", image)
            self.assertNotIn(":latest", image)
        validator = document(client, "StatefulSet", "validator-REPLACE_WITH_VALIDATOR_SET-client")["spec"]["template"]["spec"]["containers"][0]
        self.assertEqual(validator["image"], "REPLACE_WITH_PRYSM_VALIDATOR_IMAGE")


if __name__ == "__main__":
    unittest.main()
