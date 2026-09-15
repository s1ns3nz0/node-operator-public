#!/usr/bin/env python3
# Check objective: Reject incomplete EKS CIS reports and redact raw audit details.
"""Offline tests for the EKS worker-node CIS result normalizer."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/ci/normalize-eks-cis.py"
SPEC = importlib.util.spec_from_file_location("cis_normalizer", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)
IDS = ["3.1.1", "3.1.2", "3.2.1"]


def profile():
    return {"cis_eks": {"benchmark": "eks-1.5.0", "source_revision": "a" * 40, "target": "node", "required_check_ids": IDS}}


def source(statuses=("PASS", "FAIL", "WARN")):
    return {"Controls": [{"version": "eks-1.5.0", "node_type": "node", "tests": [{"results": [
        {"test_number": identifier, "status": status, "audit": "sensitive command", "actual_value": "secret", "remediation": "do this"}
        for identifier, status in zip(IDS, statuses)
    ]}]}], "Totals": {"total_pass": 999}}


class CisNormalizerTests(unittest.TestCase):
    def test_real_opa_wrapper_with_canonical_profile(self):
        canonical = json.loads((ROOT / "policy/data/cis_eks.json").read_text())["cis_eks"]
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            raw = directory / "raw.json"
            for status, expected in (("PASS", 0), ("WARN", 1), ("FAIL", 1), ("INFO", 1)):
                rows = [{"test_number": identifier, "status": status} for identifier in canonical["required_check_ids"]]
                raw.write_text(json.dumps({"Controls": [{"version": canonical["benchmark"], "node_type": "node", "tests": [{"results": rows}]}], "Totals": {"total_pass": 999}}))
                output = directory / status
                result = subprocess.run(
                    ["bash", str(ROOT / "scripts/ops/evaluate-eks-cis.sh"), str(raw), "synthetic-node", str(output)],
                    capture_output=True, text=True, timeout=30,
                )
                self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
                self.assertFalse(json.loads((output / "assessment.json").read_text())["full_cluster_compliance"])
                self.assertTrue((output / "opa-decision.json").is_file())

    def paths(self):
        temporary = tempfile.TemporaryDirectory(); root = Path(temporary.name)
        input_path, profile_path, output = root / "input.json", root / "profile.json", root / "output.json"
        profile_path.write_text(json.dumps(profile())); input_path.write_text(json.dumps(source()))
        return temporary, input_path, profile_path, output

    def test_cli_preserves_statuses_recomputes_counts_and_redacts(self):
        temporary, input_path, profile_path, output = self.paths()
        with temporary:
            run = subprocess.run([sys.executable, str(SCRIPT), "--input", str(input_path), "--profile", str(profile_path), "--node", "ip-10-0-0-1", "--output", str(output)], capture_output=True, text=True)
            self.assertEqual(run.returncode, 0, run.stderr)
            normalized = json.loads(output.read_text())
            self.assertEqual([item["status"] for item in normalized["results"]], ["PASS", "FAIL", "WARN"])
            self.assertEqual(normalized["counts"], {"PASS": 1, "FAIL": 1, "WARN": 1, "INFO": 0})
            self.assertFalse(normalized["full_cluster_compliance"])
            self.assertNotIn("sensitive command", output.read_text())
            self.assertEqual(set(normalized), {"schema_version", "benchmark", "source_revision", "scope", "node", "raw_sha256", "results", "counts", "full_cluster_compliance"})

    def test_missing_duplicate_invented_summary_and_unknown_status_fail(self):
        temporary, input_path, profile_path, output = self.paths()
        with temporary:
            bad = source(); bad["Controls"][0]["tests"][0]["results"].pop(); input_path.write_text(json.dumps(bad))
            with self.assertRaises(MODULE.NormalizeError): MODULE.normalize(input_path, profile_path, "node", output)
            input_path.write_text(json.dumps(source(("PASS", "PASS", "PASS"))))
            profile_path.write_text(json.dumps(profile() | {"Totals": {"PASS": 3}}))
            with self.assertRaises(MODULE.NormalizeError): MODULE.normalize(input_path, profile_path, "node", output)
            profile_path.write_text(json.dumps(profile())); bad = source(); bad["Controls"][0]["tests"][0]["results"][0]["status"] = "MAYBE"; input_path.write_text(json.dumps(bad))
            with self.assertRaises(MODULE.NormalizeError): MODULE.normalize(input_path, profile_path, "node", output)

    def test_duplicate_json_and_array_no_totals(self):
        temporary, input_path, profile_path, output = self.paths()
        with temporary:
            input_path.write_text('{"Controls":[],"Controls":[],"Totals":{}}')
            with self.assertRaises(MODULE.NormalizeError): MODULE.normalize(input_path, profile_path, "node", output)
            controls = source(("INFO", "PASS", "FAIL"))["Controls"]; input_path.write_text(json.dumps(controls))
            result = MODULE.normalize(input_path, profile_path, "node", output, no_totals=True)
            self.assertEqual(result["counts"], {"PASS": 1, "FAIL": 1, "WARN": 0, "INFO": 1})


if __name__ == "__main__":
    unittest.main()
