#!/usr/bin/env python3
# Check objective: Validate private validator metrics networking plans.
"""Offline contract and plan checks for private validator metrics networking.

This test never refreshes, applies, or contacts AWS. It exercises Terraform's
first-plan behavior so endpoint ENIs computed during creation cannot become an
invalid ``for_each`` key set.
"""
from __future__ import annotations

import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / "infra/terraform"
SOURCE = (MODULE / "validator-monitoring-network.tf").read_text()
PLAN_JSON: Path | None = None


def block(kind: str, resource_type: str, name: str, source: str = SOURCE) -> str:
    match = re.search(rf'{re.escape(kind)} "{re.escape(resource_type)}" "{re.escape(name)}" \{{', source)
    if not match:
        raise AssertionError(f"missing {kind} {resource_type} {name}")
    depth = 0
    for index in range(match.end() - 1, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[match.start():index + 1]
    raise AssertionError(f"unterminated {kind} {resource_type} {name}")


def output_block(name: str, source: str = SOURCE) -> str:
    match = re.search(rf'output "{re.escape(name)}" \{{', source)
    if not match:
        raise AssertionError(f"missing output {name}")
    depth = 0
    for index in range(match.end() - 1, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[match.start():index + 1]
    raise AssertionError(f"unterminated output {name}")


class ValidatorMonitoringNetworkTest(unittest.TestCase):
    def test_metric_ingress_is_cross_pool_reference_only(self):
        for name, port, client in (
            ("hoodi_nodes_prysm_metrics_from_nodes", 8080, "Prysm"),
            ("hoodi_nodes_nethermind_metrics_from_nodes", 6060, "Nethermind"),
            ("hoodi_nodes_validator_client_metrics_from_nodes", 8081, "Validator client"),
        ):
            with self.subTest(rule=name):
                rule = block("resource", "aws_vpc_security_group_ingress_rule", name)
                self.assertIn(f'description                  = "{client} metrics from system-pool validator collector nodes"', rule)
                self.assertIn("security_group_id            = aws_security_group.hoodi_nodes.id", rule)
                self.assertIn("referenced_security_group_id = aws_security_group.nodes.id", rule)
                self.assertIn(f"from_port                    = {port}", rule)
                self.assertIn(f"to_port                      = {port}", rule)
                self.assertIn('ip_protocol                  = "tcp"', rule)
                self.assertNotRegex(rule, r"cidr_(?:ipv4|blocks)\s*=")

        self.assertNotRegex(SOURCE, r"0\.0\.0\.0/0|::/0")
        self.assertNotRegex(SOURCE, r"(?m)^\s*egress\s*\{")

    def test_unpinned_validator_client_requires_cross_pool_metrics_rule(self):
        client = (ROOT / "deploy/validator/client-template.yaml").read_text()
        self.assertNotIn("nodeSelector:", client)
        rule = block(
            "resource",
            "aws_vpc_security_group_ingress_rule",
            "hoodi_nodes_validator_client_metrics_from_nodes",
        )
        self.assertIn("from_port                    = 8081", rule)
        self.assertIn("to_port                      = 8081", rule)

    def test_logs_eni_lookup_uses_stable_subnet_keys_and_exact_filters(self):
        lookup = block("data", "aws_network_interface", "validator_metrics_logs_endpoint")
        self.assertIn("for_each = local.validator_metrics_logs_endpoint_subnets", lookup)
        self.assertIn('name   = "network-interface-id"', lookup)
        self.assertIn('values = tolist(aws_vpc_endpoint.required_interface["logs"].network_interface_ids)', lookup)
        self.assertIn('name   = "subnet-id"', lookup)
        self.assertIn("values = [each.value]", lookup)
        self.assertIn('name   = "interface-type"', lookup)
        self.assertIn('values = ["vpc_endpoint"]', lookup)
        self.assertNotIn('name   = "vpc-endpoint-id"', lookup)
        self.assertIn("for index, subnet_id in local.system_subnet_ids : tostring(index) => subnet_id", SOURCE)
        self.assertNotIn("for_each = toset(aws_vpc_endpoint.required_interface", SOURCE)

    def test_outputs_expose_exact_logs_destination_and_runtime_binding(self):
        ips = output_block("validator_metrics_logs_endpoint_private_ips")
        bindings = output_block("validator_metrics_logs_endpoint_bindings")
        self.assertIn("index => eni.private_ip", ips)
        self.assertIn("endpoint_id = aws_vpc_endpoint.required_interface[\"logs\"].id", bindings)
        self.assertIn("subnet_ids  = local.validator_metrics_logs_endpoint_subnets", bindings)
        self.assertNotRegex(ips + bindings, r"0\.0\.0\.0/0|::/0")

    def test_offline_first_plan_accepts_deferred_logs_eni_reads(self):
        if PLAN_JSON is not None:
            self.assertTrue(PLAN_JSON.is_absolute(), "--plan-json must be an absolute path")
            self.assertTrue(PLAN_JSON.is_file(), f"missing --plan-json file: {PLAN_JSON}")
            plan = json.loads(PLAN_JSON.read_text())
        else:
            self.assertIsNotNone(
                shutil.which("terraform"),
                "terraform is required without --plan-json; CI must pass its pinned root plan explicitly",
            )
            self._assert_local_offline_plan()
            return
        self._assert_plan_has_static_network_resources(plan)

    def _assert_local_offline_plan(self):
        with tempfile.TemporaryDirectory(prefix="validator-monitoring-network.") as temporary:
            output = Path(temporary) / "offline"
            result = subprocess.run(
                [
                    "bash", str(ROOT / "scripts/ci/validate-terraform-offline.sh"),
                    str(MODULE), str(output), "fixtures/offline-baseline.tfvars",
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            plan = json.loads((output / "plan.json").read_text())
        self._assert_plan_has_static_network_resources(plan)

    def _assert_plan_has_static_network_resources(self, plan):
        changes = {change["address"]: change["change"]["actions"] for change in plan["resource_changes"]}
        self.assertEqual(changes["aws_vpc_security_group_ingress_rule.hoodi_nodes_prysm_metrics_from_nodes"], ["create"])
        self.assertEqual(changes["aws_vpc_security_group_ingress_rule.hoodi_nodes_nethermind_metrics_from_nodes"], ["create"])
        self.assertEqual(changes["aws_vpc_security_group_ingress_rule.hoodi_nodes_validator_client_metrics_from_nodes"], ["create"])
        eni_reads = {
            address for address in changes
            if address.startswith("data.aws_network_interface.validator_metrics_logs_endpoint[")
        }
        self.assertEqual(eni_reads, {
            'data.aws_network_interface.validator_metrics_logs_endpoint["0"]',
            'data.aws_network_interface.validator_metrics_logs_endpoint["1"]',
        })


if __name__ == "__main__":
    arguments = sys.argv[1:]
    if len(arguments) == 2 and arguments[0] == "--plan-json":
        PLAN_JSON = Path(arguments[1])
    elif arguments:
        raise SystemExit("usage: test-validator-monitoring-network.py [--plan-json ABSOLUTE_PATH]")
    sys.argv = [sys.argv[0]]
    unittest.main()
