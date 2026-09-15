#!/usr/bin/env python3
# Check objective: Enforce Vault runtime signing workflow and crypto-before-content boundaries.
"""Scoped signing workflow and crypto-before-content boundary regressions."""
from pathlib import Path
import os
import re
import runpy
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]


def job_source(workflow, name):
    start = workflow.index("\n  " + name + ":")
    remainder = workflow[start + 1:]
    match = re.search(r"\n  [A-Za-z0-9_-]+:\n", remainder[len(name) + 3:])
    return remainder if match is None else remainder[:len(name) + 3 + match.start()]


def validate(workflow, verifier):
    assert "default: false" in workflow
    readonly = job_source(workflow, "verify")
    signing = job_source(workflow, "sign-evidence")
    assert "verification-run.json" in readonly
    for required in ("needs: verify", "inputs.sign_evidence", "needs.verify.result == 'success'",
                     "github.ref == 'refs/heads/main'", "actions: read", "id-token: write",
                     'gh run download "$GITHUB_RUN_ID"', '"$GITHUB_RUN_ATTEMPT"',
                     'test "$(git rev-parse HEAD)" = "$GITHUB_SHA"',
                     "cosign sign-blob --yes --bundle", "verify-vault-runtime-signed-evidence.sh",
                     'verify-release-source-eligibility.sh "$GITHUB_SHA"', "fetch-depth: 0",
                     "retention-days: 30", "if-no-files-found: error"):
        assert required in signing, required
    assert signing.index("verification-statement.py build") < signing.index("cosign sign-blob") < signing.index("bash scripts/ci/verify-vault-runtime-signed-evidence.sh")
    assert not re.search(r"aws\s|docker\s|kubectl\s|terraform\s|continue-on-error|if: always\(\)", signing)
    assert "cosign" not in readonly
    for forbidden in ("--insecure", "--key ", "--certificate-identity-regexp", "--certificate-oidc-issuer-regexp"):
        assert forbidden not in verifier, forbidden
    for required in ("cosign verify-blob --bundle", "--certificate-identity \"$identity\"",
                     "'https://github.com/s1ns3nz0/node-operator/.github/workflows/operations-verification.yml@refs/heads/main'",
                     "'https://github.com/s1ns3nz0/node-operator/.github/workflows/vault-runtime-candidate-verification.yml@refs/heads/main'",
                     "--certificate-oidc-issuer 'https://token.actions.githubusercontent.com'",
                     '--certificate-github-workflow-sha "$revision"',
                     "--certificate-github-workflow-trigger workflow_dispatch"):
        assert required in verifier, required
    assert verifier.index("operations-verification.yml") < verifier.index("vault-runtime-candidate-verification.yml")
    assert verifier.index("cosign verify-blob") < verifier.index('python3 "$root/scripts/ci/vault-runtime-verification-statement.py" verify')


workflow = (ROOT / ".github/workflows/operations-verification.yml").read_text()
workflow = runpy.run_path(str(ROOT / "scripts/ci/lib/workflow-source.py"))["expand_text"](workflow)
verifier = (ROOT / "scripts/ci/verify-vault-runtime-signed-evidence.sh").read_text()
validate(workflow, verifier)
mutations = [
    (workflow.replace("default: false", "default: true"), verifier),
    (workflow.replace("needs: verify", "needs: []"), verifier),
    (workflow.replace("inputs.sign_evidence", "true"), verifier),
    (workflow.replace("needs.verify.result == 'success'", "true"), verifier),
    (workflow.replace('gh run download "$GITHUB_RUN_ID"', 'gh run download 1'), verifier),
    (workflow.replace('"$GITHUB_RUN_ATTEMPT"', '"1"'), verifier),
    (workflow + "\n          aws ecr put-image\n", verifier),
    (workflow, verifier.replace("cosign verify-blob", "cosign verify-blob --insecure-ignore-tlog")),
    (workflow, verifier.replace('--certificate-github-workflow-sha "$revision"', "")),
]
for bad_workflow, bad_verifier in mutations:
    try:
        validate(bad_workflow, bad_verifier)
    except (AssertionError, ValueError):
        continue
    raise AssertionError("unsafe signing mutation accepted")

# A failed cryptographic verification must terminate before semantic validation.
with tempfile.TemporaryDirectory() as tmp:
    directory = Path(tmp)
    for filename in ("verification-statement.json", "verification-statement.sigstore.json"):
        (directory / filename).write_text("{}")
    (directory / "cosign").write_text("#!/bin/sh\nexit 37\n")
    (directory / "python3").write_text("#!/bin/sh\necho should-not-run >&2\nexit 99\n")
    for filename in ("cosign", "python3"):
        (directory / filename).chmod(0o700)
    process = subprocess.run(["bash", str(ROOT / "scripts/ci/verify-vault-runtime-signed-evidence.sh"),
                              tmp, "a" * 40, "123", "1"],
                             env={**os.environ, "PATH": tmp + os.pathsep + os.environ["PATH"]},
                             text=True, capture_output=True)
    assert process.returncode != 0, process.stderr
    assert "should-not-run" not in process.stderr
print("PASS: opt-in signing and nine unsafe mutations; crypto failure blocks semantic validation")
