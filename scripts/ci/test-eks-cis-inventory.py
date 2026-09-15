#!/usr/bin/env python3
# Check objective: Require complete EKS node assessment coverage without claiming live execution.
"""Offline tests for complete local EKS CIS inventory aggregation."""
import json
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/ops/evaluate-eks-cis-inventory.py"
PROFILE = json.loads((ROOT / "policy/data/cis_eks.json").read_text())["cis_eks"]


def node(name, region="ap-northeast-2"):
    return {"metadata": {"name": name, "labels": {}}, "spec": {"providerID": f"aws:///{region}a/i-0123456789abcdef0"}, "status": {"nodeInfo": {"operatingSystem": "linux", "osImage": "Amazon Linux 2023", "architecture": "amd64"}}}


def report(status="PASS"):
    rows = [{"test_number": item, "status": status, "audit": "raw-audit-must-not-leak", "actual_value": "raw-value-must-not-leak"} for item in PROFILE["required_check_ids"]]
    return {"Controls": [{"version": PROFILE["benchmark"], "node_type": "node", "tests": [{"results": rows}]}], "Totals": {"total_pass": len(rows)}}


class EksCisInventoryTests(unittest.TestCase):
    def test_timeout_continues_and_fifo_is_rejected(self):
        spec = importlib.util.spec_from_file_location("aggregate", SCRIPT)
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            inventory = root / "nodes.json"
            inventory.write_text(json.dumps({"metadata": {}, "items": [node("node-a"), node("node-b")]}))
            reports = {}
            for name in ("node-a", "node-b"):
                raw = root / f"{name}.json"; raw.write_text(json.dumps(report()))
                reports[name] = str(raw)
            manifest = root / "reports.json"; manifest.write_text(json.dumps({"reports": reports}))
            output = root / "out"
            with patch.object(module.subprocess, "run", side_effect=subprocess.TimeoutExpired("hidden", 60)) as run:
                self.assertFalse(module.evaluate(inventory, "ap-northeast-2", manifest, output))
                self.assertEqual(run.call_count, 2)
            self.assertEqual(len(json.loads((output / "aggregate.json").read_text())["node_assessments"]), 2)
            fifo = root / "fifo"; os.mkfifo(fifo)
            with self.assertRaises(module.InventoryError): module._regular_raw(fifo)
            with self.assertRaises(module.InventoryError):
                module.evaluate(fifo, "ap-northeast-2", manifest, root / "fifo-output")

    def test_original_replacement_after_snapshot_cannot_change_evaluator_input(self):
        spec = importlib.util.spec_from_file_location("aggregate", SCRIPT)
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); raw = root / "raw.json"; raw.write_text(json.dumps(report()))
            inventory = root / "nodes.json"; inventory.write_text(json.dumps({"metadata": {"continue": "", "remainingItemCount": 0}, "items": [node("node-a")]}))
            manifest = root / "reports.json"; manifest.write_text(json.dumps({"reports": {"node-a": str(raw)}}))
            real_run = subprocess.run
            def replace_original_then_run(args, **kwargs):
                raw.write_text(json.dumps(report("FAIL")))
                self.assertNotEqual(Path(args[2]), raw)
                return real_run(args, **kwargs)
            with patch.object(module.subprocess, "run", side_effect=replace_original_then_run):
                self.assertTrue(module.evaluate(inventory, "ap-northeast-2", manifest, root / "out"))
            aggregate = (root / "out" / "aggregate.json").read_text()
            self.assertNotIn("raw-audit-must-not-leak", aggregate)
            self.assertNotIn("raw-value-must-not-leak", aggregate)

    def invoke(self, root, nodes, mapping, region="ap-northeast-2", output="aggregate"):
        inventory = root / "nodes.json"
        inventory.write_text(json.dumps({"metadata": {"continue": "", "remainingItemCount": 0}, "items": nodes}))
        manifest = root / "reports.json"; manifest.write_text(json.dumps({"reports": mapping}))
        return subprocess.run([sys.executable, str(SCRIPT), "--nodes", str(inventory), "--region", region, "--reports", str(manifest), "--output", str((root / output).resolve())], capture_output=True, text=True, timeout=90), root / output

    def test_all_pass_retains_each_redacted_assessment_only(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); names = ["node-a", "node-b"]
            raws = {name: root / f"{name}.json" for name in names}
            for raw in raws.values(): raw.write_text(json.dumps(report()))
            result, output = self.invoke(root, [node(name) for name in names], {name: str(raw) for name, raw in raws.items()})
            self.assertEqual(result.returncode, 0, result.stderr)
            aggregate = json.loads((output / "aggregate.json").read_text())
            self.assertTrue(aggregate["accepted"]); self.assertFalse(aggregate["full_cluster_compliance"])
            self.assertEqual([entry["node"] for entry in aggregate["node_assessments"]], names)
            self.assertTrue(all(entry["assessment"] and entry["assessment"]["full_cluster_compliance"] is False for entry in aggregate["node_assessments"]))
            self.assertNotIn("raw-audit-must-not-leak", (output / "aggregate.json").read_text())

    def test_failure_is_nonzero_and_keeps_all_assessments(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); first, second = root / "first.json", root / "second.json"
            first.write_text(json.dumps(report())); second.write_text(json.dumps(report("FAIL")))
            result, output = self.invoke(root, [node("node-a"), node("node-b")], {"node-a": str(first), "node-b": str(second)})
            self.assertEqual(result.returncode, 1, result.stderr)
            aggregate = json.loads((output / "aggregate.json").read_text())
            self.assertFalse(aggregate["accepted"])
            self.assertTrue(all(entry["assessment"] is not None for entry in aggregate["node_assessments"]))

    def test_missing_duplicate_and_wrong_region_are_rejected_without_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); raw = root / "raw.json"; raw.write_text(json.dumps(report()))
            cases = [
                ([node("node-a"), node("node-b")], {"node-a": str(raw)}),
                ([node("node-a")], {"node-a": str(raw), "unexpected-node": str(raw)}),
                ([node("node-a"), node("node-b")], {"node-a": str(raw), "node-b": str(raw)}),
                ([node("node-a"), node("node-a")], {"node-a": str(raw)}),
                ([node("node-a", "us-east-1")], {"node-a": str(raw)}),
            ]
            for index, (nodes, mapping) in enumerate(cases):
                with self.subTest(case=index):
                    result, output = self.invoke(root, nodes, mapping, output=f"rejected-{index}")
                    self.assertEqual(result.returncode, 2)
                    self.assertFalse(output.exists())
                    self.assertNotIn("raw-audit-must-not-leak", result.stderr)

    def test_duplicate_json_unsafe_report_and_output_overwrite_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); raw = root / "raw.json"; raw.write_text(json.dumps(report()))
            inventory = root / "nodes.json"; inventory.write_text(json.dumps({"metadata": {"continue": "", "remainingItemCount": 0}, "items": [node("node-a")]}))
            manifest = root / "reports.json"; manifest.write_text('{"reports":{"node-a":"' + str(raw) + '","node-a":"' + str(raw) + '"}}')
            output = root / "duplicate-json"
            result = subprocess.run([sys.executable, str(SCRIPT), "--nodes", str(inventory), "--region", "ap-northeast-2", "--reports", str(manifest), "--output", str(output.resolve())], capture_output=True, text=True, timeout=90)
            self.assertEqual(result.returncode, 2); self.assertFalse(output.exists())
            symlink = root / "raw-link.json"; symlink.symlink_to(raw)
            manifest.write_text(json.dumps({"reports": {"node-a": str(symlink)}}))
            result = subprocess.run([sys.executable, str(SCRIPT), "--nodes", str(inventory), "--region", "ap-northeast-2", "--reports", str(manifest), "--output", str(output.resolve())], capture_output=True, text=True, timeout=90)
            self.assertEqual(result.returncode, 2); self.assertFalse(output.exists())
            manifest.write_text(json.dumps({"reports": {"node-a": str(raw)}})); output.mkdir()
            result = subprocess.run([sys.executable, str(SCRIPT), "--nodes", str(inventory), "--region", "ap-northeast-2", "--reports", str(manifest), "--output", str(output.resolve())], capture_output=True, text=True, timeout=90)
            self.assertEqual(result.returncode, 2)


if __name__ == "__main__":
    unittest.main()
