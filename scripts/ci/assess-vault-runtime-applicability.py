#!/usr/bin/env python3
"""Assess narrowly pinned, expiring Vault runtime package non-applicability.

This consumes evidence; it never changes the raw scan or asserts a build or
deployment provenance claim.
"""
import hashlib
import importlib.util
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location("vault_scan_summary", ROOT / "scripts/ci/summarize-vault-runtime-scan.py")
_summary = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_summary)

ADVISORY_ID = "GO-2026-5932"
PREFIX = "golang.org/x/crypto/openpgp"
UNKNOWN_ARTIFACT = ("golang.org/x/crypto", "v0.56.0")
HEX = re.compile(r"^[a-f0-9]{64}$")
DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")


def fail(message):
    raise ValueError(message)


def read_json(path):
    try:
        return json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        fail("invalid JSON evidence %s: %s" % (path.name, exc))


def object_file(path, label):
    value = read_json(path)
    if not isinstance(value, dict):
        fail("%s must be an object" % label)
    return value


def utc_time(value):
    if not isinstance(value, str) or not value.endswith("Z"):
        fail("invalid expiry")
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        fail("invalid expiry")


def sha_file(path):
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as exc:
        fail("missing evidence %s" % exc.filename)


def candidate_subject(allow, component, digest):
    registry = allow.get("registry")
    candidate = allow.get("candidates", {}).get(component)
    if not isinstance(registry, str) or not isinstance(candidate, dict):
        fail("unreviewed component")
    repository = candidate.get("repository")
    if not isinstance(repository, str) or not DIGEST.fullmatch(digest):
        fail("invalid candidate identity")
    return candidate, "%s/%s@%s" % (registry, repository, digest)


def check_advisory(advisory, manifest, advisory_bytes):
    if advisory.get("id") != ADVISORY_ID or manifest.get("advisory_id") != ADVISORY_ID:
        fail("unexpected advisory")
    if not isinstance(manifest.get("advisory_url"), str) or not manifest["advisory_url"]:
        fail("missing advisory URL")
    if manifest.get("affected_package_prefix") != PREFIX:
        fail("unexpected affected package prefix")
    if manifest.get("advisory_sha256") != hashlib.sha256(advisory_bytes).hexdigest():
        fail("advisory hash differs from manifest")
    affected = advisory.get("affected")
    if not isinstance(affected, list) or not affected:
        fail("malformed advisory scope")
    for item in affected:
        imports = item.get("ecosystem_specific", {}).get("imports") if isinstance(item, dict) else None
        if not isinstance(imports, list) or not imports:
            fail("malformed advisory import scope")
        for imported in imports:
            path = imported.get("path") if isinstance(imported, dict) else None
            if not isinstance(path, str) or not (path == PREFIX or path.startswith(PREFIX + "/")):
                fail("advisory affects import outside approved prefix")


def check_identity(identity, subject, candidate):
    if identity.get("subject") != subject or identity.get("Os") != "linux" or identity.get("Architecture") != "amd64":
        fail("runtime identity differs")
    repos = identity.get("RepoDigests")
    if not isinstance(repos, list) or subject not in repos:
        fail("runtime digest absent from RepoDigests")
    user = identity.get("user")
    expected_user = candidate.get("user")
    if user != expected_user or not isinstance(user, str) or not re.match(r"^[1-9][0-9]*(?::[0-9]+)?$", user):
        fail("runtime user is root or differs")
    if identity.get("entrypoint") != [candidate.get("entrypoint")]:
        fail("runtime entrypoint differs")


def is_allowed_unknown(match):
    vulnerability = match.get("vulnerability") if isinstance(match, dict) else None
    artifact = match.get("artifact") if isinstance(match, dict) else None
    return (isinstance(vulnerability, dict) and vulnerability.get("id") == ADVISORY_ID
            and str(vulnerability.get("severity", "")).lower() == "unknown"
            and isinstance(artifact, dict)
            and (artifact.get("name"), artifact.get("version")) == UNKNOWN_ARTIFACT)


def assess(component, evidence_directory, *, now=None, root=ROOT):
    """Return a decision document or raise ValueError for invalid/blocked evidence."""
    root = Path(root)
    evidence = Path(evidence_directory)
    manifest = object_file(root / ".ci/vault-runtime-applicability.json", "manifest")
    allow = object_file(root / ".ci/vault-runtime-candidates.json", "candidate allowlist")
    advisory_path = root / ".ci/vault-runtime-applicability" / (ADVISORY_ID + ".json")
    try:
        advisory_bytes = advisory_path.read_bytes()
    except OSError as exc:
        fail("missing advisory: %s" % exc)
    try:
        advisory = json.loads(advisory_bytes)
    except json.JSONDecodeError as exc:
        fail("invalid advisory: %s" % exc)
    if manifest.get("schema_version") != "v1":
        fail("unsupported manifest")
    check_advisory(advisory, manifest, advisory_bytes)
    current = object_file(evidence / "advisory-current.json", "current advisory")
    if current != advisory:
        fail("current advisory differs from pinned advisory")
    expiry = utc_time(manifest.get("expires_at"))
    current_time = now or datetime.now(timezone.utc)
    if current_time.tzinfo is None:
        fail("now must be timezone aware")
    if current_time.astimezone(timezone.utc) >= expiry:
        fail("applicability decision expired")
    candidates = manifest.get("candidates")
    entry = candidates.get(component) if isinstance(candidates, dict) else None
    if component not in ("server", "agent", "injector") or not isinstance(entry, dict):
        fail("unreviewed component")
    digest = entry.get("digest")
    allowed, subject = candidate_subject(allow, component, digest)
    if allowed.get("digest") != digest:
        fail("manifest digest differs from candidate allowlist")
    for key in ("binary_path", "binary_sha256", "dependency_sha256", "dependency_count"):
        if key not in entry:
            fail("missing candidate %s" % key)
    if not isinstance(entry["binary_path"], str) or not entry["binary_path"].startswith("/"):
        fail("invalid binary path")
    if not all(isinstance(entry[k], str) and HEX.fullmatch(entry[k]) for k in ("binary_sha256", "dependency_sha256")):
        fail("invalid pinned hash")
    if not isinstance(entry["dependency_count"], int) or entry["dependency_count"] < 0:
        fail("invalid dependency count")
    if component == "agent":
        if entry.get("dependency_path") is not None:
            fail("agent dependency path must be null")
    elif not isinstance(entry.get("dependency_path"), str) or not entry["dependency_path"].startswith("/"):
        fail("invalid dependency path")
    required = ("sbom.json", "grype.json", "scan-summary.json", "runtime-identity.json", "binary.sha256", "dependencies.txt", "advisory-current.json")
    for name in required:
        if not (evidence / name).is_file():
            fail("missing evidence %s" % name)
    sbom_path, raw_path, summary_path = evidence / "sbom.json", evidence / "grype.json", evidence / "scan-summary.json"
    sbom_bytes = sbom_path.read_bytes()
    raw = object_file(raw_path, "raw scan")
    try:
        expected_summary = _summary.summarize(sbom_bytes, raw, digest)
    except (ValueError, KeyError, TypeError, AttributeError) as exc:
        fail("invalid raw scan evidence: %s" % exc)
    observed_summary = object_file(summary_path, "scan summary")
    if not isinstance(observed_summary.get("scanned_at"), str) or not observed_summary["scanned_at"]:
        fail("scan summary missing scanned_at")
    if {k: v for k, v in observed_summary.items() if k != "scanned_at"} != {k: v for k, v in expected_summary.items() if k != "scanned_at"}:
        fail("scan summary differs from raw scan")
    identity = object_file(evidence / "runtime-identity.json", "runtime identity")
    check_identity(identity, subject, allowed)
    binary_line = (evidence / "binary.sha256").read_bytes()
    expected_line = (entry["binary_sha256"] + "  " + entry["binary_path"] + "\n").encode()
    if binary_line != expected_line:
        fail("binary hash line differs from reviewed binary")
    dependencies = (evidence / "dependencies.txt").read_bytes()
    if hashlib.sha256(dependencies).hexdigest() != entry["dependency_sha256"] or dependencies.count(b"\n") != entry["dependency_count"]:
        fail("dependency closure differs from reviewed candidate")
    if any(line == PREFIX.encode() or line.startswith((PREFIX + "/").encode()) for line in dependencies.splitlines()):
        fail("affected package is present in dependency closure")
    matches = raw.get("matches")
    unknown = [m for m in matches if str(m.get("vulnerability", {}).get("severity", "")).lower() == "unknown"]
    blocking = [m for m in matches if str(m.get("vulnerability", {}).get("severity", "")).lower() in ("critical", "high")]
    if blocking:
        fail("critical or high raw finding")
    # summarize() classifies every non-standard severity as unknown.  Do not
    # let a spelling variation bypass the exact, reviewed Unknown exception.
    if expected_summary["findings"]["unknown"] != len(unknown):
        fail("nonstandard severity is unresolved")
    if unknown and (len(unknown) != 1 or not is_allowed_unknown(unknown[0])):
        fail("unresolved or additional unknown finding")
    not_affected = []
    if unknown:
        not_affected.append({"advisory_id": ADVISORY_ID, "decision": "not_affected", "reason": "affected import prefix absent from reviewed dependency closure", "artifact": {"name": UNKNOWN_ARTIFACT[0], "version": UNKNOWN_ARTIFACT[1]}})
    return {"schema_version": "v1", "component": component, "status": "passed", "raw_scan_status": observed_summary.get("status"), "raw_findings": observed_summary.get("findings"), "not_affected": not_affected, "unresolved_unknown": 0, "artifact_digest": digest, "sbom_sha256": hashlib.sha256(sbom_bytes).hexdigest(), "raw_sha256": sha_file(raw_path), "advisory_id": ADVISORY_ID, "advisory_sha256": hashlib.sha256(advisory_bytes).hexdigest(), "expires_at": manifest["expires_at"], "proof": {"dependency_sha256": entry["dependency_sha256"], "dependency_count": entry["dependency_count"], "binary_sha256": entry["binary_sha256"], "binary_path": entry["binary_path"]}, "build_provenance": "not_established_by_this_assessment", "deployment_authorized": False}


def main(argv):
    if len(argv) != 3:
        raise ValueError("usage: assess-vault-runtime-applicability.py COMPONENT EVIDENCE_DIRECTORY")
    return assess(argv[1], argv[2])


if __name__ == "__main__":
    try:
        print(json.dumps(main(sys.argv), sort_keys=True))
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        print("assessment blocked: %s" % exc, file=sys.stderr)
        sys.exit(1)
