#!/usr/bin/env python3
"""Summarize one fresh, unfiltered scan; never waive a finding or attest a build."""
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path


def summarize(sbom_bytes, raw, digest):
    if not re.fullmatch(r"sha256:[a-f0-9]{64}", digest):
        raise ValueError("invalid digest")
    sbom = json.loads(sbom_bytes)
    if (sbom.get("bomFormat") != "CycloneDX"
            or sbom.get("metadata", {}).get("component", {}).get("version") != digest
            or not isinstance(sbom.get("components"), list) or not sbom["components"]):
        raise ValueError("missing or mismatched SBOM identity/inventory")
    descriptor = raw.get("descriptor", {})
    if raw.get("source", {}).get("target", {}).get("manifestDigest") != digest:
        raise ValueError("raw scan subject differs from SBOM subject")
    database = descriptor.get("db", {}).get("status", {})
    config = descriptor.get("configuration", {})
    if descriptor.get("name") != "grype" or not descriptor.get("version"):
        raise ValueError("missing scanner identity")
    if database.get("valid") is not True or not database.get("built"):
        raise ValueError("invalid scanner database")
    # Grype adds built-in Linux-header rules even with ignore: []; reject every
    # actually ignored match instead of assuming that configuration is empty.
    if (config.get("exclude") != []
            or config.get("only-fixed") is not False
            or config.get("only-notfixed") is not False
            or config.get("show-suppressed") is not True
            or raw.get("ignoredMatches") not in (None, [])):
        raise ValueError("filtered or incomplete scanner evidence")
    if not isinstance(raw.get("matches"), list):
        raise ValueError("missing scan matches")
    counts = dict.fromkeys(("critical", "high", "medium", "low", "unknown"), 0)
    for match in raw["matches"]:
        severity = match.get("vulnerability", {}).get("severity")
        if not isinstance(severity, str) or not severity:
            raise ValueError("missing finding severity")
        severity = severity.lower()
        counts[severity if severity in counts else "unknown"] += 1
    return {
        "schema_version": "v1", "tool": "grype", "artifact_digest": digest,
        "sbom_sha256": hashlib.sha256(sbom_bytes).hexdigest(),
        "scanner": {"version": descriptor["version"], "database_built": database["built"],
                    "database_schema_version": str(database.get("schemaVersion", ""))},
        "scanned_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "findings": counts,
        "status": "blocked" if any(counts[k] for k in ("critical", "high", "unknown")) else "passed",
        "build_provenance": "not_established_by_this_verification",
        "deployment_authorized": False,
    }


if __name__ == "__main__":
    if len(sys.argv) != 4:
        sys.exit("usage: summarize-vault-runtime-scan.py SBOM_JSON RAW_SCAN_JSON DIGEST")
    try:
        result = summarize(Path(sys.argv[1]).read_bytes(), json.loads(Path(sys.argv[2]).read_text()), sys.argv[3])
    except (ValueError, KeyError, TypeError, AttributeError) as exc:
        sys.exit(f"invalid scan evidence: {exc}")
    print(json.dumps(result, indent=2))
