#!/usr/bin/env python3
"""Build and semantically verify bounded Vault runtime verification statements.

This deliberately does not sign anything.  The calling workflow verifies the
signature separately; this program only makes the unsigned payload stable and
replays the local applicability assessor before it is accepted.
"""
import hashlib
import importlib.util
import json
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
COMPONENTS = ("server", "agent", "injector")
REQUIRED_EVIDENCE = (
    "version.txt", "binary.sha256", "dependencies.txt", "advisory-current.json",
    "grype.json", "sbom.json", "scan-summary.json", "runtime-identity.json",
    "applicability-decision.json", "verification-run.json",
)
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PREDICATE_TYPE = "https://github.com/s1ns3nz0/node-operator/attestations/runtime-verification/v1"
REPOSITORY = "s1ns3nz0/node-operator"
REVISION = re.compile(r"^[a-f0-9]{40}$")
DIGITS = re.compile(r"^[1-9][0-9]*$")
DIGEST = re.compile(r"^sha256:([a-f0-9]{64})$")

_spec = importlib.util.spec_from_file_location(
    "vault_runtime_assessor", ROOT / "scripts/ci/assess-vault-runtime-applicability.py"
)
_assessor = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_assessor)


def fail(message):
    raise ValueError(message)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def object_json(path, label):
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        fail("invalid %s: %s" % (label, exc))
    if not isinstance(value, dict):
        fail("%s must be an object" % label)
    return value


def regular(path, label):
    if path.is_symlink() or not path.is_file():
        fail("%s must be a regular file" % label)
    return path


def directory(path, label):
    if path.is_symlink() or not path.is_dir():
        fail("%s must be a real directory" % label)
    return path


def sha256(path):
    return hashlib.sha256(regular(path, path.name).read_bytes()).hexdigest()


def utc(value, label):
    if not isinstance(value, str) or not value.endswith("Z"):
        fail("invalid %s" % label)
    try:
        result = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        fail("invalid %s" % label)
    if result.tzinfo is None:
        fail("invalid %s" % label)
    return result.astimezone(timezone.utc)


def expected_context(component, revision, run_id, attempt):
    return {"repository": REPOSITORY, "source_revision": revision, "run_id": run_id,
            "run_attempt": attempt, "component": component, "ref": "refs/heads/main"}


def policy_hashes():
    paths = {
        "candidate_allowlist": ROOT / ".ci/vault-runtime-candidates.json",
        "applicability_policy": ROOT / ".ci/vault-runtime-applicability.json",
        "pinned_go_advisory": ROOT / ".ci/vault-runtime-applicability/GO-2026-5932.json",
        "agent_dependency_closure": ROOT / ".ci/vault-runtime-applicability/agent-dependencies.txt",
    }
    return {name: sha256(path) for name, path in paths.items()}


def candidate_allowlist():
    allow = object_json(regular(ROOT / ".ci/vault-runtime-candidates.json", "candidate allowlist"), "candidate allowlist")
    if set(allow.get("candidates", {})) != set(COMPONENTS) or not isinstance(allow.get("registry"), str):
        fail("invalid candidate allowlist")
    return allow


def validate_times(summary, raw, assessment):
    scanner = summary.get("scanner")
    if not isinstance(scanner, dict) or scanner.get("version") != "0.118.0":
        fail("unexpected scanner version")
    descriptor = raw.get("descriptor")
    if not isinstance(descriptor, dict) or descriptor.get("name") != "grype" or descriptor.get("version") != "0.118.0":
        fail("unexpected raw scanner version")
    scanned_at = utc(summary.get("scanned_at"), "scanned_at")
    database_built = utc(scanner.get("database_built"), "database_built")
    # The raw scan must report the same database timestamp as its summary.
    raw_built = descriptor.get("db", {}).get("status", {}).get("built")
    if raw_built != scanner.get("database_built"):
        fail("raw scanner database differs from summary")
    now = datetime.now(timezone.utc)
    if scanned_at > now + timedelta(minutes=5) or database_built > now + timedelta(minutes=5):
        fail("evidence timestamp is in the future")
    if now - scanned_at > timedelta(hours=24):
        fail("scan evidence is stale")
    if now - database_built > timedelta(hours=48):
        fail("scanner database is stale")
    if utc(assessment.get("expires_at"), "assessment expiry") <= now:
        fail("applicability assessment expired")
    return scanned_at.strftime("%Y-%m-%dT%H:%M:%SZ")


def component_claim(evidence_root, component, revision, run_id, attempt, allow):
    evidence = directory(evidence_root / ("vault-runtime-" + component + "-verification"), component + " evidence")
    files = {name: regular(evidence / name, component + "/" + name) for name in REQUIRED_EVIDENCE}
    context = object_json(files["verification-run.json"], "verification context")
    if context != expected_context(component, revision, run_id, attempt):
        fail("verification context differs for %s" % component)
    summary = object_json(files["scan-summary.json"], "scan summary")
    raw = object_json(files["grype.json"], "raw scan")
    stored = object_json(files["applicability-decision.json"], "applicability decision")
    try:
        replayed = _assessor.assess(component, evidence)
    except (ValueError, OSError, KeyError, TypeError, AttributeError) as exc:
        fail("applicability replay failed for %s: %s" % (component, exc))
    if replayed != stored:
        fail("stored applicability decision differs for %s" % component)
    scanned_at = validate_times(summary, raw, replayed)
    candidate = allow["candidates"][component]
    digest = candidate.get("digest") if isinstance(candidate, dict) else None
    digest_match = DIGEST.fullmatch(digest or "")
    repository = candidate.get("repository") if isinstance(candidate, dict) else None
    if not digest_match or repository != "node-operator-baseline-vault-runtime-" + component:
        fail("unreviewed candidate for %s" % component)
    subject_name = allow["registry"] + "/" + repository
    return ({"component": component, "subject": subject_name + "@" + digest,
             "scanned_at": scanned_at, "assessment": replayed,
             "evidence_sha256": {name: sha256(path) for name, path in files.items()}},
            {"name": subject_name, "digest": {"sha256": digest_match.group(1)}})


def build(evidence_root, revision, run_id, attempt):
    if not REVISION.fullmatch(revision) or not DIGITS.fullmatch(run_id) or not DIGITS.fullmatch(attempt):
        fail("invalid revision or run metadata")
    root = directory(Path(evidence_root), "evidence root")
    allow = candidate_allowlist()
    claims, subjects = zip(*(component_claim(root, component, revision, run_id, attempt, allow) for component in COMPONENTS))
    return {"_type": STATEMENT_TYPE, "subject": list(subjects), "predicateType": PREDICATE_TYPE,
            "predicate": {"schema_version": "v1", "repository": REPOSITORY,
                          "source_revision": revision, "run_id": run_id, "run_attempt": attempt,
                          "ref": "refs/heads/main", "policy_sha256": policy_hashes(),
                          "components": list(claims), "build_provenance": "not_established",
                          "deployment_authorized": False}}


def verify(evidence_root, revision, run_id, attempt, statement_file):
    observed_path = regular(Path(statement_file), "statement")
    try:
        raw = observed_path.read_text(encoding="utf-8")
        observed = json.loads(raw)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        fail("invalid statement: %s" % exc)
    expected = build(evidence_root, revision, run_id, attempt)
    if observed != expected or raw != canonical(expected) + "\n":
        fail("statement semantic contents differ")
    return expected


def main(argv):
    if len(argv) == 6 and argv[1] == "build":
        return build(Path(argv[2]), argv[3], argv[4], argv[5])
    if len(argv) == 7 and argv[1] == "verify":
        return verify(Path(argv[2]), argv[3], argv[4], argv[5], argv[6])
    fail("usage: vault-runtime-verification-statement.py build EVIDENCE_ROOT REVISION RUN_ID RUN_ATTEMPT | verify EVIDENCE_ROOT REVISION RUN_ID RUN_ATTEMPT STATEMENT_FILE")


if __name__ == "__main__":
    try:
        print(canonical(main(sys.argv)))
    except (ValueError, OSError) as exc:
        print("verification statement blocked: %s" % exc, file=sys.stderr)
        sys.exit(1)
