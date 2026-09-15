#!/usr/bin/env python3
"""Read-only local preflight for PR144 candidates, not publication permission.

Usage: python3 scripts/ops/prepare-vault-runtime-publication.py BUILD_EVIDENCE_DIR
Prints only public image identities, scan counts and proposed publication targets.
Does not log in, build, push, sign, modify allowlists or access live Vault.
"""
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
REVISION = "9cd8d84fe177235db33d6761b3ac570d7ab846d7"
EVIDENCE = ROOT / "plans/2026-09-09-vault-grpc-security-patch/evidence.json"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def docker(*args):
    return subprocess.check_output(["docker", *args], text=True, timeout=60)


def prepare(directory):
    reviewed = json.loads(EVIDENCE.read_text())
    targets = []
    for component in ("server", "agent"):
        proof = reviewed[component]
        image_id = proof["local_image"]
        require((directory / f"{component}.iid").read_text().strip() == image_id,
                f"{component}: local build identity changed")
        scan_file = directory / f"{component}-grype.json"
        sbom_file = directory / f"{component}-sbom.json"
        require(sha(scan_file) == proof["raw_scan_sha256"], f"{component}: scan changed")
        require(sha(sbom_file) == proof["sbom_sha256"], f"{component}: SBOM changed")
        scan = json.loads(scan_file.read_text())
        counts = {}
        for match in scan["matches"]:
            severity = match["vulnerability"]["severity"].lower()
            counts[severity] = counts.get(severity, 0) + 1
        require(counts.get("critical", 0) == counts.get("high", 0) == 0,
                f"{component}: Critical/High findings present")
        identity = json.loads(docker("image", "inspect", image_id))[0]
        entrypoint = "/bin/vault" if component == "server" else "vault"
        binary = "/bin/vault" if component == "server" else "/usr/local/bin/vault"
        require(identity["Id"] == image_id, f"{component}: image identity mismatch")
        require(identity["Os"] == "linux" and identity["Architecture"] == "amd64",
                f"{component}: platform mismatch")
        require(identity["Config"]["User"] == "100:1000"
                and identity["Config"]["Entrypoint"] == [entrypoint],
                f"{component}: runtime configuration mismatch")
        actual = docker("run", "--rm", "--pull", "never", "--platform", "linux/amd64",
                        "--network", "none", "--read-only", "--cap-drop", "ALL",
                        "--security-opt", "no-new-privileges", "--pids-limit", "64",
                        "--memory", "512m", "--cpus", "1", "--entrypoint", "/bin/sh",
                        image_id, "-ec", 'sha256sum "$1"', "metadata", binary)
        fields = actual.split()
        require(bool(fields) and fields[0] == proof["binary_sha256"],
                f"{component}: binary mismatch or missing hash")
        repository = f"node-operator-baseline-vault-runtime-{component}"
        targets.append({
            "component": component, "local_image_id": image_id,
            "binary_sha256": proof["binary_sha256"], "repository": repository,
            "proposed_tag": f"manual-grpc-1.83.2-{REVISION[:12]}",
            "registry_manifest_digest": None,
            "retained_scan": {"findings": counts,
                              "database_built": scan["descriptor"]["db"]["status"]["built"],
                              "fresh_remote_scan_required": True},
        })
    return {"status": "local_preflight_passed", "source_revision": REVISION,
            "registry": "123456789012.dkr.ecr.ap-northeast-2.amazonaws.com",
            "targets": targets, "publication_authorized": False,
            "deployment_authorized": False, "ci_build_provenance": False,
            "remaining": ["Authorize exact two candidate pushes",
                          "Read back registry manifest digests and verify config identity",
                          "Review new candidate and applicability proof bindings",
                          "Fresh hosted scan and separate applicability decision",
                          "Honest signature/attestation verification before live rollout"]}


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: prepare-vault-runtime-publication.py BUILD_EVIDENCE_DIR")
    try:
        print(json.dumps(prepare(Path(sys.argv[1])), indent=2))
    except (ValueError, KeyError, OSError, subprocess.SubprocessError) as exc:
        sys.exit(f"publication preflight failed: {exc}")
