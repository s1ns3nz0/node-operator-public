#!/usr/bin/env python3
"""Aggregate complete, local EKS worker-node CIS assessments without raw reports."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
EVALUATOR = ROOT / "scripts/ops/evaluate-eks-cis.sh"
RENDERER = ROOT / "scripts/ops/render-eks-cis-jobs.py"
MAX_INPUT = 16 * 1024 * 1024


class InventoryError(ValueError):
    pass


def _renderer():
    spec = importlib.util.spec_from_file_location("eks_cis_renderer", RENDERER)
    if spec is None or spec.loader is None:
        raise InventoryError("inventory rejected")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _pairs(items):
    value = {}
    for key, item in items:
        if key in value:
            raise InventoryError("report manifest rejected")
        value[key] = item
    return value


def _read_json(path: Path, maximum: int):
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > maximum:
                raise InventoryError("unsafe input")
            raw = stream.read(maximum + 1)
    except OSError as error:
        raise InventoryError("cannot read input") from error
    if len(raw) > maximum:
        raise InventoryError("unsafe input")
    try:
        return json.loads(raw, object_pairs_hook=_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise InventoryError("malformed JSON") from error


def _snapshot_reports(path: Path, nodes: list[str], scratch: Path) -> dict[str, Path]:
    """Bind each report to bytes read from one non-following file descriptor."""
    value = _read_json(path, MAX_INPUT)
    if not isinstance(value, dict) or set(value) != {"reports"} or not isinstance(value["reports"], dict):
        raise InventoryError("report manifest rejected")
    reports = value["reports"]
    if set(reports) != set(nodes) or not all(isinstance(name, str) and isinstance(raw, str) for name, raw in reports.items()):
        raise InventoryError("report manifest does not exactly cover inventory")
    result, identities = {}, set()
    for index, name in enumerate(nodes):
        raw = Path(reports[name])
        if not raw.is_absolute():
            raise InventoryError("report manifest rejected")
        try:
            descriptor = os.open(raw, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(descriptor, "rb") as source:
                info = os.fstat(source.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_INPUT:
                    raise InventoryError("unsafe report")
                identity = (info.st_dev, info.st_ino)
                if identity in identities:
                    raise InventoryError("duplicate report")
                contents = source.read(MAX_INPUT + 1)
        except OSError as error:
            raise InventoryError("unsafe report") from error
        if len(contents) > MAX_INPUT:
            raise InventoryError("unsafe report")
        identities.add(identity)
        destination = scratch / f"report-{index:03d}.json"
        try:
            descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "wb") as target:
                target.write(contents)
        except OSError as error:
            raise InventoryError("cannot snapshot report") from error
        result[name] = destination
    return result


def _regular_raw(path: Path) -> tuple[int, int]:
    if not path.is_absolute():
        raise InventoryError("report manifest rejected")
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, "rb") as stream:
            info = os.fstat(stream.fileno())
    except OSError as error:
        raise InventoryError("unsafe report") from error
    if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_INPUT:
        raise InventoryError("unsafe report")
    return info.st_dev, info.st_ino


def _create_output(output: Path) -> None:
    if not output.is_absolute() or output.exists() or output.is_symlink() or output.parent.is_symlink() or not output.parent.is_dir():
        raise InventoryError("unsafe output")
    try:
        output.mkdir(mode=0o700)
    except OSError as error:
        raise InventoryError("unsafe output") from error


def _assessment(path: Path) -> dict | None:
    if not path.is_file() or path.is_symlink():
        return None
    value = _read_json(path, MAX_INPUT)
    return value if isinstance(value, dict) else None


def evaluate(nodes_path: Path, region: str, reports_path: Path, output: Path) -> bool:
    try:
        nodes = _renderer().selected_nodes(nodes_path, region)
    except Exception as error:
        raise InventoryError("inventory rejected") from error
    with tempfile.TemporaryDirectory(prefix="eks-cis-reports-") as temporary:
        reports = _snapshot_reports(reports_path, nodes, Path(temporary))
        _create_output(output)
        entries, accepted = [], True
        for index, node in enumerate(nodes):
            node_output = output / f"node-{index:03d}-{hashlib.sha256(node.encode()).hexdigest()[:12]}"
            try:
                result = subprocess.run(
                    ["bash", str(EVALUATOR), str(reports[node]), node, str(node_output)],
                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    check=False, timeout=60,
                )
                evaluator_passed = result.returncode == 0
            except (OSError, subprocess.TimeoutExpired):
                evaluator_passed = False
            normalized = _assessment(node_output / "assessment.json")
            node_ok = evaluator_passed and normalized is not None
            # Keep every normalized assessment, including one that OPA rejected.
            entries.append({"node": node, "accepted": node_ok, "assessment": normalized})
            accepted = accepted and node_ok
        aggregate = {
            "schema_version": 1,
            "scope": "eks-worker-node",
            "region": region,
            "node_assessments": entries,
            "accepted": accepted,
            "full_cluster_compliance": False,
        }
        with (output / "aggregate.json").open("x", encoding="utf-8") as stream:
            json.dump(aggregate, stream, sort_keys=True, separators=(",", ":"))
            stream.write("\n")
        return accepted


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--nodes", type=Path, required=True)
    parser.add_argument("--region", required=True)
    parser.add_argument("--reports", type=Path, required=True, help="JSON {\"reports\": {node: absolute_raw_report_path}}")
    parser.add_argument("--output", type=Path, required=True, help="new absolute local directory")
    args = parser.parse_args(argv)
    try:
        return 0 if evaluate(args.nodes, args.region, args.reports, args.output) else 1
    except (InventoryError, OSError, subprocess.TimeoutExpired):
        # Do not echo raw report paths, report content, or other custody data.
        print("EKS CIS inventory assessment rejected", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
