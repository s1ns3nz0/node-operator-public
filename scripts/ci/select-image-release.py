#!/usr/bin/env python3
# Check objective: Select only images affected by changed inputs, with explicit manual targets and conservative missing-baseline handling.
# Purpose: Determine which release-image jobs are eligible from trusted event inputs and changed paths.
# Inputs: GitHub event, checkout SHA, git history, and optional workflow_dispatch target.
# Outputs: Boolean family flags and a bounded toolchain matrix in GITHUB_OUTPUT.
# Side effects: Read-only local Git inspection and GITHUB_OUTPUT append; never builds or publishes images.
import json
import os
from pathlib import Path
import re
import subprocess

TOOLCHAINS = [
    {"image": name, "dockerfile": f".ci/toolchains/{name}.Dockerfile", "input_file": extra}
    for name, extra in (
        ("terraform-validation", ""), ("release-build", ""), ("vault-release-signer", ""),
        ("gitops-oci-mirror", ""),
        ("argocd-bootstrap", "docs/gitops/argocd-private-values.example.yaml"),
        ("vault-bootstrap", "docs/gitops/vault-values.example.yaml,scripts/ops/verify-hoodi-vault-readiness.sh,docs/gitops/vault-gp3-encrypted-storageclass.yaml,scripts/ops/ensure-vault-encrypted-storageclass.sh"),
    )
]
SHARED = {".github/workflows/image-publish.yml", "scripts/ci/select-image-release.py"}
IMAGE_SBOM_INPUTS = {
    "scripts/ci/generate-image-sbom.sh", "scripts/ci/image_sbom_evidence.py",
    "policy/image_sbom.rego", "scripts/ci/install-policy-tools.sh",
    "scripts/release/sign-ci-image-evidence.sh", "scripts/ci/ci_image_attestation.py",
    "scripts/ci/install-validator-signing-fence-release-tools.sh",
}
SIGNING = {
    "scripts/ci/lib/common.sh",
    "scripts/ci/install-validator-signing-fence-release-tools.sh",
    "scripts/ci/scan-release-sbom.sh", "scripts/ci/verify-release-scan-attestation.sh",
    "scripts/ci/test-release-scan-cosign-roundtrip.sh",
}


def select(paths=(), target=None, all_inputs=False):
    paths = set(paths)
    all_inputs = all_inputs or bool(paths & SHARED) or target == "all"
    allowed = {"all", "installer-prerequisites", "scanner", "toolchains", "fence", "relay", "prysm-mtls", "signer-probe", "kyverno-cli"} | {item["image"] for item in TOOLCHAINS}
    if target is not None and target not in allowed:
        raise ValueError("unknown image release target")
    scanner = all_inputs or target == "scanner" or bool(paths & IMAGE_SBOM_INPUTS) or any(
        path.startswith(".ci/scanners/") or path in {
            "scripts/ci/collect-pr-evidence.sh", "scripts/ci/collect-security-evidence.sh",
            "scripts/ci/lib/common.sh", "scripts/release/build-scanner-image.sh",
            "scripts/release/publish-scanner-image.sh",
        } for path in paths)
    toolchain_all = all_inputs or target == "toolchains" or bool(paths & IMAGE_SBOM_INPUTS) or bool(paths & {
        "scripts/release/build-toolchain-image.sh", "scripts/release/publish-toolchain-image.sh",
        ".ci/toolchains/release-toolchain-image.sh",
    })
    installer_prerequisites = target == "installer-prerequisites"
    selected = [item for item in TOOLCHAINS if toolchain_all or target == item["image"] or
                (installer_prerequisites and item["image"] in {"vault-bootstrap", "gitops-oci-mirror"}) or
                item["dockerfile"] in paths or any(path in paths for path in item["input_file"].split(",") if path)]
    common_go = bool(paths & {"go.mod", "go.sum"})
    fence = all_inputs or target == "fence" or common_go or bool(paths & SIGNING) or any(
        path.startswith(("cmd/validator-signing-fence/", ".ci/validator-signing-fence/", ".ci/fence-security/")) or
        path.startswith(("scripts/ci/run-fence-security-", "scripts/ci/test-fence-security-")) or path in {
            ".github/workflows/fence-security.yml", "scripts/release/publish-fence-image.sh",
            "scripts/release/fence_build_inputs.py", "scripts/ci/install-fence-security-tools.sh",
            "scripts/ci/collect-validator-signing-fence-release-evidence.sh",
        } for path in paths)
    relay = installer_prerequisites or all_inputs or target == "relay" or common_go or bool(paths & SIGNING) or any(
        path.startswith(("cmd/vault-audit-relay/", ".ci/vault-audit-relay/")) or
        path == "scripts/release/publish-vault-audit-relay.sh" for path in paths)
    prysm_mtls = all_inputs or target == "prysm-mtls" or bool(paths & SIGNING) or any(
        path.startswith(".ci/prysm-mtls/") or path in {
            "scripts/release/publish-prysm-mtls-image.sh",
            "scripts/release/prysm_publication_record.py",
            "scripts/ci/verify-prysm-mtls-source-build.sh",
        } for path in paths)
    signer_probe = all_inputs or target == "signer-probe" or "go.mod" in paths or bool(paths & SIGNING) or any(
        path.startswith((".ci/validator-signer-identity-probe/", "cmd/validator-signer-identity-probe/")) or path in {
            "scripts/release/signer_probe_build_inputs.py",
            "scripts/release/signer_probe_publication_record.py",
            "scripts/release/publish-signer-identity-probe.sh",
            "scripts/release/fence_build_inputs.py",
        } for path in paths)
    kyverno_cli = all_inputs or target == "kyverno-cli" or bool(paths & SIGNING) or any(
        path.startswith(".ci/kyverno-cli/") or path in {
            "scripts/release/kyverno_cli_publication_record.py",
            "scripts/release/generate-kyverno-cli-manifest-approval.py",
            "scripts/release/publish-kyverno-cli-image.sh",
        } for path in paths)
    return {"scanner": bool(scanner), "toolchains": bool(selected), "fence": bool(fence), "relay": bool(relay),
            "prysm_mtls": bool(prysm_mtls), "signer_probe": bool(signer_probe), "kyverno_cli": bool(kyverno_cli),
            "toolchain_matrix": {"include": selected}}


def git(*args):
    return subprocess.run(["git", *args], check=True, capture_output=True).stdout


def from_event(event_name, event, sha):
    if not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise ValueError("invalid checkout SHA")
    if git("rev-parse", "HEAD").decode().strip() != sha:
        raise ValueError("checkout does not match event SHA")
    if event_name == "workflow_dispatch":
        return select(target=event.get("inputs", {}).get("target", "all"))
    if event_name != "push" or event.get("after") != sha:
        raise ValueError("unsupported or mismatched image release event")
    before = event.get("before", "")
    if not re.fullmatch(r"[0-9a-f]{40}", before):
        raise ValueError("invalid push baseline")
    if before == "0" * 40:
        return select(all_inputs=True)
    try:
        git("cat-file", "-e", before + "^{commit}")
    except subprocess.CalledProcessError:
        return select(all_inputs=True)
    # --no-renames includes both deleted and added paths when an input moves.
    changed = git("diff", "--no-renames", "--name-only", "-z", before, sha).decode().split("\0")
    return select(path for path in changed if path)


def main():
    event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
    result = from_event(os.environ["GITHUB_EVENT_NAME"], event, os.environ["GITHUB_SHA"])
    with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as output:
        for key, value in result.items():
            output.write(key + "=" + json.dumps(value, separators=(",", ":")) + "\n")
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
