#!/usr/bin/env python3
# Check objective: Verify Vault runtime scan evidence acceptance and rejection without registry access.
"""Offline positive/negative evidence checks; no registry or AWS access."""
import copy
import importlib.util
import json
import sys
import unittest
from pathlib import Path

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("scan", Path(__file__).with_name("summarize-vault-runtime-scan.py"))
scan = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scan)
DIGEST = "sha256:" + "a" * 64
SBOM = json.dumps({"bomFormat": "CycloneDX", "metadata": {"component": {"version": DIGEST}},
                   "components": [{"name": "synthetic"}]}).encode()
RAW = {"matches": [], "ignoredMatches": [], "descriptor": {"name": "grype", "version": "test",
       "db": {"status": {"valid": True, "built": "2026-09-09T00:00:00Z", "schemaVersion": 6}},
       "configuration": {"exclude": [], "only-fixed": False, "only-notfixed": False, "show-suppressed": True}}}
RAW["source"] = {"type": "image", "target": {"manifestDigest": DIGEST}}


class ScanTests(unittest.TestCase):
    def test_clean_is_not_deployment_approval(self):
        summary = scan.summarize(SBOM, RAW, DIGEST)
        self.assertEqual(summary["status"], "passed")
        self.assertFalse(summary["deployment_authorized"])
        self.assertEqual(summary["build_provenance"], "not_established_by_this_verification")

    def test_all_blocking_severities_retained(self):
        for severity in ("Critical", "High", "Unknown", "unrecognized"):
            with self.subTest(severity=severity):
                raw = copy.deepcopy(RAW)
                raw["matches"] = [{"vulnerability": {"id": "GO-2026-5932", "severity": severity}}]
                summary = scan.summarize(SBOM, raw, DIGEST)
                self.assertEqual(summary["status"], "blocked")
                self.assertEqual(sum(summary["findings"].values()), 1)

    def test_medium_not_hidden(self):
        raw = copy.deepcopy(RAW)
        raw["matches"] = [{"vulnerability": {"severity": "Medium"}}]
        self.assertEqual(scan.summarize(SBOM, raw, DIGEST)["findings"]["medium"], 1)

    def test_grype_omitted_empty_ignored_matches(self):
        raw = copy.deepcopy(RAW)
        del raw["ignoredMatches"]
        self.assertEqual(scan.summarize(SBOM, raw, DIGEST)["status"], "passed")

    def test_raw_subject_mismatch_rejected(self):
        raw = copy.deepcopy(RAW)
        raw["source"]["target"]["manifestDigest"] = "sha256:" + "b" * 64
        with self.assertRaises(ValueError):
            scan.summarize(SBOM, raw, DIGEST)

    def test_incomplete_filtered_or_invalid_rejected(self):
        cases = []
        for key, value in (("exclude", ["**"]), ("only-fixed", True),
                           ("only-notfixed", True), ("show-suppressed", False)):
            raw = copy.deepcopy(RAW)
            raw["descriptor"]["configuration"][key] = value
            cases.append(raw)
        raw = copy.deepcopy(RAW)
        raw["ignoredMatches"] = [{"vulnerability": {"severity": "High"}}]
        cases.append(raw)
        raw = copy.deepcopy(RAW)
        raw["descriptor"]["db"]["status"]["valid"] = False
        cases.append(raw)
        raw = copy.deepcopy(RAW)
        raw["matches"] = [{}]
        cases.append(raw)
        raw = copy.deepcopy(RAW)
        del raw["matches"]
        cases.append(raw)
        for raw in cases:
            with self.assertRaises(ValueError):
                scan.summarize(SBOM, raw, DIGEST)

    def test_wrong_digest_or_empty_inventory_rejected(self):
        with self.assertRaises(ValueError):
            scan.summarize(SBOM, RAW, "sha256:" + "b" * 64)
        with self.assertRaises(ValueError):
            scan.summarize(SBOM, RAW, "tag:latest")
        sbom = json.loads(SBOM)
        sbom["components"] = []
        with self.assertRaises(ValueError):
            scan.summarize(json.dumps(sbom).encode(), RAW, DIGEST)


if __name__ == "__main__":
    unittest.main()
