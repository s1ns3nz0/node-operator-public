#!/usr/bin/env python3
"""Normalize bounded kube-bench worker-node results without retaining audit detail."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

MAX_INPUT = 16 * 1024 * 1024
MAX_PROFILE = 1024 * 1024
SHA40 = re.compile(r"[0-9a-f]{40}$")
STATUSES = ("PASS", "FAIL", "WARN", "INFO")


class NormalizeError(ValueError):
    pass


def _pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise NormalizeError("duplicate JSON key")
        result[key] = value
    return result


def _read(path: Path, maximum: int) -> bytes:
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError as error:
        raise NormalizeError("cannot open input") from error
    try:
        with os.fdopen(descriptor, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > maximum:
                raise NormalizeError("unsafe input file")
            value = stream.read(maximum + 1)
    except OSError as error:
        raise NormalizeError("cannot read input") from error
    if len(value) > maximum:
        raise NormalizeError("unsafe input file")
    return value


def _json(path: Path, maximum: int) -> tuple[object, bytes]:
    raw = _read(path, maximum)
    try:
        return json.loads(raw, object_pairs_hook=_pairs), raw
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise NormalizeError("malformed JSON") from error


def _profile(path: Path) -> dict:
    value, _ = _json(path, MAX_PROFILE)
    if not isinstance(value, dict) or set(value) != {"cis_eks"} or not isinstance(value["cis_eks"], dict):
        raise NormalizeError("invalid CIS profile wrapper")
    profile = value["cis_eks"]
    if set(profile) != {"benchmark", "source_revision", "target", "required_check_ids"}:
        raise NormalizeError("invalid CIS profile fields")
    ids = profile["required_check_ids"]
    if not (profile["benchmark"] == "eks-1.5.0" and profile["target"] == "node" and isinstance(profile["source_revision"], str)
            and SHA40.fullmatch(profile["source_revision"]) and isinstance(ids, list) and ids
            and all(isinstance(item, str) and item for item in ids) and len(set(ids)) == len(ids)):
        raise NormalizeError("invalid CIS profile values")
    return profile


def _controls(value: object, no_totals: bool) -> list:
    if isinstance(value, list):
        if not no_totals:
            raise NormalizeError("array input requires --no-totals")
        controls = value
    elif isinstance(value, dict) and set(value) == {"Controls", "Totals"} and isinstance(value["Totals"], dict):
        if no_totals:
            raise NormalizeError("--no-totals requires array input")
        controls = value["Controls"]
    else:
        raise NormalizeError("invalid kube-bench input envelope")
    if not isinstance(controls, list) or not controls:
        raise NormalizeError("kube-bench controls are empty")
    return controls


def normalize(input_path: Path, profile_path: Path, node: str, output: Path, no_totals: bool = False) -> dict:
    if not isinstance(node, str) or not node or len(node) > 253 or any(ord(char) < 33 for char in node):
        raise NormalizeError("invalid node")
    profile = _profile(profile_path)
    source, raw = _json(input_path, MAX_INPUT)
    found = {}
    for control in _controls(source, no_totals):
        if not isinstance(control, dict) or not {"version", "node_type", "tests"} <= set(control):
            raise NormalizeError("invalid kube-bench control")
        if control["version"] != profile["benchmark"] or control["node_type"] != profile["target"] or not isinstance(control["tests"], list):
            raise NormalizeError("kube-bench target does not match profile")
        for test in control["tests"]:
            if not isinstance(test, dict) or not isinstance(test.get("results"), list):
                raise NormalizeError("invalid kube-bench test")
            for result in test["results"]:
                if not isinstance(result, dict) or not isinstance(result.get("test_number"), str) or result.get("status") not in STATUSES:
                    raise NormalizeError("invalid kube-bench result")
                identifier = result["test_number"]
                if identifier in found:
                    raise NormalizeError("duplicate kube-bench check")
                found[identifier] = result["status"]
    expected = profile["required_check_ids"]
    if set(found) != set(expected):
        raise NormalizeError("kube-bench checks do not exactly match profile")
    results = [{"id": identifier, "status": found[identifier]} for identifier in expected]
    counts = {status: sum(item["status"] == status for item in results) for status in STATUSES}
    output_value = {
        "schema_version": 1, "benchmark": profile["benchmark"], "source_revision": profile["source_revision"],
        "scope": "eks-worker-node", "node": node, "raw_sha256": hashlib.sha256(raw).hexdigest(),
        "results": results, "counts": counts, "full_cluster_compliance": False,
    }
    if output.exists() or output.is_symlink() or not output.parent.is_dir() or output.parent.is_symlink():
        raise NormalizeError("unsafe output")
    try:
        with output.open("x", encoding="utf-8") as stream:
            json.dump(output_value, stream, sort_keys=True, separators=(",", ":"))
            stream.write("\n")
    except OSError as error:
        raise NormalizeError("cannot create output") from error
    return output_value


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--profile", type=Path, required=True)
    parser.add_argument("--node", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--no-totals", action="store_true")
    args = parser.parse_args(argv)
    try:
        normalize(args.input, args.profile, args.node, args.output, args.no_totals)
    except NormalizeError as error:
        print(f"CIS normalization rejected: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
