#!/usr/bin/env python3
# Check objective: Verify unsigned Vault runtime verification statements obey their evidence boundary.
"""Synthetic boundary tests for the unsigned runtime verification statement."""
import hashlib
import importlib.util
import json
import shutil
import tempfile
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/ci/vault-runtime-verification-statement.py"
spec = importlib.util.spec_from_file_location("runtime_statement", SCRIPT)
statement = importlib.util.module_from_spec(spec)
spec.loader.exec_module(statement)

REVISION = "a" * 40


def write_json(path, value):
    path.write_text(json.dumps(value, sort_keys=True), encoding="utf-8")


def fixture(root):
    now = datetime.now(timezone.utc).replace(microsecond=0)
    scanned = (now - timedelta(minutes=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    built = (now - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    for component in statement.COMPONENTS:
        directory = root / ("vault-runtime-" + component + "-verification")
        directory.mkdir()
        for name in ("version.txt", "binary.sha256", "dependencies.txt", "advisory-current.json", "sbom.json", "runtime-identity.json"):
            (directory / name).write_text(name + "\n", encoding="utf-8")
        write_json(directory / "grype.json", {"descriptor": {"name": "grype", "version": "0.118.0", "db": {"status": {"built": built}}}})
        write_json(directory / "scan-summary.json", {"scanner": {"version": "0.118.0", "database_built": built}, "scanned_at": scanned})
        write_json(directory / "verification-run.json", statement.expected_context(component, REVISION, "123", "4"))
        write_json(directory / "applicability-decision.json", fake_assessment(component))
    return root


def fake_assessment(component):
    return {"schema_version": "v1", "component": component, "status": "passed",
            "expires_at": "2099-01-01T00:00:00Z", "build_provenance": "not_established_by_this_assessment",
            "deployment_authorized": False}


def expect_block(action):
    try:
        action()
    except ValueError:
        return
    raise AssertionError("unsafe mutation was accepted")


original_assess = statement._assessor.assess
statement._assessor.assess = lambda component, evidence: fake_assessment(component)
try:
    with tempfile.TemporaryDirectory() as temporary:
        evidence = fixture(Path(temporary))
        built = statement.build(evidence, REVISION, "123", "4")
        assert built["_type"] == statement.STATEMENT_TYPE
        assert len(built["subject"]) == 3
        assert built["predicate"]["build_provenance"] == "not_established"
        assert built["predicate"]["deployment_authorized"] is False
        output = evidence / "statement.json"
        output.write_text(statement.canonical(built) + "\n", encoding="utf-8")
        assert statement.verify(evidence, REVISION, "123", "4", output) == built
        assert statement.build(evidence, REVISION, "123", "4") == built

        # Metadata binding, evidence digest binding and semantic payload equality.
        wrong = evidence / "vault-runtime-server-verification" / "verification-run.json"
        context = json.loads(wrong.read_text()); context["source_revision"] = "b" * 40; write_json(wrong, context)
        expect_block(lambda: statement.build(evidence, REVISION, "123", "4"))
        write_json(wrong, statement.expected_context("server", REVISION, "123", "4"))
        expect_block(lambda: statement.build(evidence, REVISION, "124", "4"))
        expect_block(lambda: statement.build(evidence, REVISION, "123", "5"))
        (evidence / "vault-runtime-agent-verification" / "version.txt").write_text("changed\n")
        expect_block(lambda: statement.verify(evidence, REVISION, "123", "4", output))
        (evidence / "vault-runtime-agent-verification" / "version.txt").write_text("version.txt\n")

        summary = evidence / "vault-runtime-injector-verification" / "scan-summary.json"
        changed = json.loads(summary.read_text()); changed["scanned_at"] = "2000-01-01T00:00:00Z"; write_json(summary, changed)
        expect_block(lambda: statement.build(evidence, REVISION, "123", "4"))
        changed["scanned_at"] = "2099-01-01T00:00:00Z"; write_json(summary, changed)
        expect_block(lambda: statement.build(evidence, REVISION, "123", "4"))

        shutil.rmtree(evidence / "vault-runtime-injector-verification")
        expect_block(lambda: statement.build(evidence, REVISION, "123", "4"))
    with tempfile.TemporaryDirectory() as temporary:
        evidence = fixture(Path(temporary))
        link = evidence / "vault-runtime-server-verification" / "version.txt"
        target = evidence / "target.txt"; target.write_text("version.txt\n")
        link.unlink(); link.symlink_to(target)
        expect_block(lambda: statement.build(evidence, REVISION, "123", "4"))
    with tempfile.TemporaryDirectory() as temporary:
        evidence = fixture(Path(temporary))
        decision = evidence / "vault-runtime-agent-verification" / "applicability-decision.json"
        changed = json.loads(decision.read_text()); changed["status"] = "blocked"; write_json(decision, changed)
        expect_block(lambda: statement.build(evidence, REVISION, "123", "4"))
    with tempfile.TemporaryDirectory() as temporary:
        evidence = fixture(Path(temporary))
        raw = evidence / "vault-runtime-agent-verification" / "grype.json"
        changed = json.loads(raw.read_text()); changed["descriptor"]["db"]["status"]["built"] = "2000-01-01T00:00:00Z"; write_json(raw, changed)
        expect_block(lambda: statement.build(evidence, REVISION, "123", "4"))
    with tempfile.TemporaryDirectory() as temporary:
        evidence = fixture(Path(temporary))
        built = statement.build(evidence, REVISION, "123", "4")
        output = evidence / "statement.json"; output.write_text(statement.canonical(built) + "\n")
        claim = json.loads(output.read_text()); claim["predicate"]["deployment_authorized"] = True; write_json(output, claim)
        expect_block(lambda: statement.verify(evidence, REVISION, "123", "4", output))
finally:
    statement._assessor.assess = original_assess

print("PASS: deterministic runtime verification statement rejects bound metadata, freshness, decision, symlink, digest, and claim mutations")
