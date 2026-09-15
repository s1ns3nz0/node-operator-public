#!/usr/bin/env python3
# Check objective: Enforce the Vault runtime verification source contract without deployment actions.
"""Focused source contract with negative mutations, not an end-to-end CI test."""
import json
import re
import runpy
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def job_source(workflow, name):
    start = workflow.index("\n  " + name + ":")
    remainder = workflow[start + 1:]
    match = re.search(r"\n  [A-Za-z0-9_-]+:\n", remainder[len(name) + 3:])
    return remainder if match is None else remainder[:len(name) + 3 + match.start()]


def validate(script, workflow):
    for forbidden in (r"docker\s+(build|push|tag)\b", r"cosign\s+(sign|attest)(?:\s|$)", r"\bkubectl\b", r"terraform\s+apply"):
        assert not re.search(forbidden, script + workflow), "unexpected mutation"
    readonly_job = job_source(workflow, "verify")
    assert not re.search(r"cosign\s+(sign|attest)", script + readonly_job), "verification job must not sign"
    for required in ("--network none", "--read-only", "--cap-drop ALL", "--security-opt no-new-privileges",
                     "--pids-limit 64", "--memory 512m", "timeout 60 docker run",
                     "--platform linux/amd64", ".RepoDigests | index($subject) != null",
                     ".entrypoint == [$entrypoint]", '"registry:$subject"', '"sbom:$evidence/sbom.json"',
                     "jq -e '.status == \"passed\"'", "unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN",
                     "unset ACTIONS_ID_TOKEN_REQUEST_TOKEN ACTIONS_ID_TOKEN_REQUEST_URL"):
        assert required in script, required
    assert '"$evidence/applicability-decision.json"' in script
    assert '"$evidence/scan-summary.json" >/dev/null' not in script
    assert "collect-vault-runtime-applicability.sh" in script and "assess-vault-runtime-applicability.py" in script
    assert script.index("aws ecr describe-images") < script.index("unset AWS_ACCESS_KEY_ID") < script.index("docker pull")
    assert not re.search(r"^\s*environment:", readonly_job, re.M), "environment invalidates exact-ref OIDC subject"
    assert "workflow_dispatch:" in workflow and "if: github.ref == 'refs/heads/main'" in readonly_job
    assert not re.search(r"^\s*(push|pull_request|pull_request_target|workflow_run):", workflow, re.M)
    assert "persist-credentials: false" in workflow and "fail-fast: false" in workflow
    assert "trap cleanup EXIT" in workflow and 'export DOCKER_CONFIG="$scratch/docker"' in workflow
    assert "if: always()" in workflow and "vault-runtime-evidence/*.json" in workflow


script = (ROOT / "scripts/ci/verify-vault-runtime-candidate.sh").read_text()
workflow = (ROOT / ".github/workflows/operations-verification.yml").read_text()
workflow = runpy.run_path(str(ROOT / "scripts/ci/lib/workflow-source.py"))["expand_text"](workflow)
validate(script, workflow)
for bad_script, bad_workflow in (
    (script.replace("--network none", "--network host"), workflow),
    (script.replace("--read-only", ""), workflow),
    (script.replace("unset AWS_ACCESS_KEY_ID", "# missing AWS_ACCESS_KEY_ID"), workflow),
    (script.replace(".status == \"passed\"", "true"), workflow),
    (script.replace('"$evidence/applicability-decision.json"', '"$evidence/scan-summary.json"'), workflow),
    (script + "\ndocker push changed\n", workflow),
    (script, workflow.replace("    runs-on: ubuntu-24.04\n    timeout-minutes:", "    runs-on: ubuntu-24.04\n    environment: unsafe\n    timeout-minutes:", 1)),
    (script, workflow.replace("if: github.ref == 'refs/heads/main' && inputs.target == 'vault-runtime'", "if: true", 1)),
):
    try:
        validate(bad_script, bad_workflow)
    except AssertionError:
        continue
    raise AssertionError("unsafe verification mutation accepted")
allowlist = json.loads((ROOT / ".ci/vault-runtime-candidates.json").read_text())
assert set(allowlist["candidates"]) == {"server", "agent", "injector"}
for component, candidate in allowlist["candidates"].items():
    assert candidate["repository"] == f"node-operator-baseline-vault-runtime-{component}"
    assert re.fullmatch(r"sha256:[a-f0-9]{64}", candidate["digest"])


def validate_collector(collector):
    for required in ("test \"$subject\" = \"$expected\"", "--pull never", "--network none", "--read-only",
                     "--cap-drop ALL", "--security-opt no-new-privileges", "timeout 60 docker run",
                     "unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN",
                     "--connect-timeout 10 --max-time 30", "https://vuln.go.dev/ID/GO-2026-5932.json",
                     "agent-dependencies.txt", '"$evidence/binary.sha256"', '"$evidence/dependencies.txt"'):
        assert required in collector, required
    assert not re.search(r"docker\s+(build|push|tag)\b|--privileged|--mount|\s-v\s|\s-e\s", collector)


collector = (ROOT / "scripts/ci/collect-vault-runtime-applicability.sh").read_text()
validate_collector(collector)
for bad in (collector.replace("--network none", "--network host"),
            collector.replace("--pull never", "--pull always"),
            collector.replace('test "$subject" = "$expected"', "true")):
    try:
        validate_collector(bad)
    except AssertionError:
        continue
    raise AssertionError("unsafe collector mutation accepted")
print("PASS: frozen runtime wrapper/workflow contract and eight unsafe mutations rejected")
print("PASS: exact-subject metadata collector and three unsafe mutations rejected")
