#!/usr/bin/env python3
"""Check the displayed approved network against Terraform's literal defaults.

This is an offline profile consistency check, not proof that an operator's
peered networks have no overlapping ranges.
"""
import ipaddress
import json
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[2]


def literal_default(source, name):
    block = re.search(r'variable "' + re.escape(name) + r'"\s*\{(.*?)\n\}', source, re.S)
    if block is None:
        raise ValueError("missing profile variable")
    value = re.search(r'^\s*default\s*=\s*(\[[^\n]*\]|"[^"\n]*")\s*$', block[1], re.M)
    if value is None:
        raise ValueError("profile default is no longer a reviewed literal")
    return json.loads(value[1])


class NetworkProfileTests(unittest.TestCase):
    def test_profile_is_private_bounded_nonoverlapping_and_displayed(self):
        source = (ROOT / "infra/foundation-network/variables.tf").read_text()
        vpc = literal_default(source, "vpc_cidr")
        subnets = literal_default(source, "system_subnet_cidrs") + [
            literal_default(source, "hoodi_subnet_cidrs"),
            literal_default(source, "public_subnet_cidr"),
        ]
        parent = ipaddress.IPv4Network(vpc, strict=True)
        networks = [ipaddress.IPv4Network(value, strict=True) for value in subnets]
        self.assertTrue(parent.is_private)
        for i, subnet in enumerate(networks):
            self.assertTrue(subnet.subnet_of(parent))
            self.assertTrue(subnet.is_private)
            for other in networks[i + 1:]:
                self.assertFalse(subnet.overlaps(other))
        wrapper = (ROOT / "scripts/release/interactive-hoodi-release.sh").read_text()
        summary = next(line for line in wrapper.splitlines() if "Planned topology before IAM mutation:" in line)
        for value in [vpc, *subnets]:
            self.assertIn(value, summary)
        self.assertLess(wrapper.index(summary), wrapper.index("aws iam create-role"))
        baseline = (ROOT / "infra/terraform/variables.tf").read_text()
        self.assertEqual(literal_default(baseline, "vpc_cidr"), vpc)
        self.assertEqual(literal_default(baseline, "private_subnet_cidrs"), subnets[:2])


if __name__ == "__main__":
    unittest.main()
