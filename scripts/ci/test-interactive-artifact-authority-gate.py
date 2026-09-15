#!/usr/bin/env python3
# Check objective: Verify the interactive installer artifact-authority gate.
"""PTY regression tests for the interactive installer's artifact-authority gate.

The installer itself is the process under test. Each case executes a copied
release-bundle layout through a real pseudo-terminal; Python only assembles the
offline fixture and observes its boundary. This is not a source-text check and
cannot pass merely because a non-TTY invocation stopped before the gate.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import pty
import select
import shutil
import stat
import subprocess
import sys
import tempfile
import time


ROOT = Path(__file__).resolve().parents[2]
REVISION = "a" * 40
ACCOUNT = "123456789012"
REGION = "ap-northeast-2"
DEPLOYMENT = "node-op-gate"


def write_executable(path: Path, contents: str) -> None:
    path.write_text(contents, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


def make_bundle(work: Path, *, inventory: str = "actual") -> tuple[Path, Path, Path]:
    """Copy the executable and its real inventory inputs into a bundle fixture."""
    bundle = work / "bundle"
    source = bundle / "source"
    source.mkdir(parents=True)
    # The inventory imports sibling modules and consumes these catalogs. Copying
    # them prevents a missing local file from masquerading as installer coverage.
    for name in ("scripts", ".ci", "release"):
        shutil.copytree(ROOT / name, source / name)
    manifest = bundle / "bundle-manifest.json"
    manifest.write_text(json.dumps({"source_revision": REVISION}) + "\n", encoding="utf-8")

    release = source / "scripts/release/node-operator-release.sh"
    write_executable(
        release,
        "#!/usr/bin/env bash\n"
        "set -euo pipefail\n"
        "printf 'release %s\\n' \"$*\" >> \"$RELEASE_LOG\"\n"
        "if [ \"$1\" = verify ]; then exit 0; fi\n"
        "printf 'RELEASE_DEPLOY_BOUNDARY\\n' >&2\n"
        "exit 87\n",
    )
    # The authority gate verifies the node-operator release wrapper. Recovery
    # itself invokes the Hoodi release wrapper, which is a separate boundary.
    write_executable(
        source / "scripts/release/hoodi-validator-release.sh",
        "#!/usr/bin/env bash\n"
        "set -euo pipefail\n"
        "printf 'hoodi-release %s\\n' \"$*\" >> \"$RELEASE_LOG\"\n"
        "printf 'RELEASE_DEPLOY_BOUNDARY\\n' >&2\n"
        "exit 87\n",
    )
    fake_bin = work / "bin"
    fake_bin.mkdir()
    write_executable(
        fake_bin / "aws",
        "#!/usr/bin/env bash\n"
        "set -euo pipefail\n"
        "printf 'aws %s\\n' \"$*\" >> \"$CALLS\"\n"
        "if [ \"$1\" = sts ] && [ \"$2\" = get-caller-identity ]; then\n"
        "  printf '{\\\"Account\\\":\\\"123456789012\\\",\\\"Arn\\\":\\\"arn:aws:iam::123456789012:user/fixture\\\"}\\n'\n"
        "  exit 0\n"
        "fi\n"
        "printf 'AWS_READ_BOUNDARY %s\\n' \"$*\" >&2\n"
        "exit 88\n",
    )
    # Keep the real Python interpreter for the copied helpers, but log the
    # helper path so the negative case proves the real inventory was invoked.
    write_executable(
        fake_bin / "python3",
        "#!/usr/bin/env bash\n"
        "set -euo pipefail\n"
        "printf 'python %s\\n' \"$*\" >> \"$PYTHON_LOG\"\n"
        "exec \"$SYSTEM_PYTHON\" \"$@\"\n",
    )
    helper = source / "scripts/release/installer_artifact_inventory.py"
    if inventory == "success":
        write_executable(
            helper,
            "#!/usr/bin/env python3\n"
            "import json, os, sys\n"
            "with open(os.environ['INVENTORY_LOG'], 'a', encoding='utf-8') as out:\n"
            "    out.write(' '.join(sys.argv[1:]) + '\\n')\n"
            "args = dict(zip(sys.argv[1::2], sys.argv[2::2]))\n"
            "account = args['--aws-account-id']; region = args['--aws-region']; deployment = args['--deployment-name']\n"
            "registry = f'{account}.dkr.ecr.{region}.amazonaws.com'\n"
            "rows = []\n"
            "for component, repo, digest in [\n"
            " ('web3signer', 'baseline-validator-runtime-web3signer', '1'*64),\n"
            " ('postgres', 'baseline-validator-runtime-postgres', '2'*64),\n"
            " ('prysm-validator', 'baseline-validator-prysm', '3'*64),\n"
            " ('validator-signing-fence', 'baseline-validator-fence', '4'*64),\n"
            " ('argocd-bootstrap', 'baseline-gitops-argocd', '5'*64),\n"
            " ('vault-bootstrap', 'baseline-gitops-vault', '6'*64),\n"
            " ('node-operator-client-chart', 'baseline-gitops-client/node-operator-client', '7'*64),\n"
            "]:\n"
            "    value = {'component': component, 'required': True, 'destination': f'{registry}/{deployment}-{repo}@sha256:{digest}', 'source': f'example.invalid/{repo}@sha256:{digest}'}\n"
            "    if component == 'node-operator-client-chart': value['destination_tag'] = '0.1.37'\n"
            "    rows.append(value)\n"
            "print(json.dumps({'schema_version': 1, 'complete': True, 'artifacts': rows}))\n",
        )
    elif inventory != "actual":
        raise ValueError(f"unknown inventory fixture: {inventory}")
    return bundle, fake_bin, source / "scripts/release/interactive-hoodi-release.sh"


def run_tty(script: Path, fake_bin: Path, work: Path, input_text: str, **extra_env: str) -> tuple[int, str]:
    """Run the actual shell entrypoint with stdin and stdout attached to a PTY."""
    master, slave = pty.openpty()
    environment = {
        **os.environ,
        "PATH": f"{fake_bin}{os.pathsep}{os.environ['PATH']}",
        "CALLS": str(work / "aws-calls.log"),
        "RELEASE_LOG": str(work / "release.log"),
        "INVENTORY_LOG": str(work / "inventory.log"),
        "PYTHON_LOG": str(work / "python-calls.log"),
        "SYSTEM_PYTHON": sys.executable,
        **extra_env,
    }
    process = subprocess.Popen([str(script)], stdin=slave, stdout=slave, stderr=slave, text=False, env=environment)
    os.close(slave)
    os.write(master, input_text.encode())
    output = bytearray()
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        readable, _, _ = select.select([master], [], [], 0.1)
        if readable:
            try:
                chunk = os.read(master, 8192)
            except OSError:
                chunk = b""
            if chunk:
                output.extend(chunk)
        if process.poll() is not None:
            while True:
                try:
                    chunk = os.read(master, 8192)
                except OSError:
                    break
                if not chunk:
                    break
                output.extend(chunk)
            break
    else:
        process.kill()
        raise AssertionError("interactive installer did not complete within 15 seconds")
    os.close(master)
    return process.wait(), output.decode(errors="replace")


def calls(work: Path) -> list[str]:
    path = work / "aws-calls.log"
    return path.read_text(encoding="utf-8").splitlines() if path.exists() else []


def assert_no_aws_mutation(observed: list[str]) -> None:
    mutations = (" create-", " put-", " update-", " delete-", " attach-", " detach-")
    assert not any(token in line for line in observed for token in mutations), observed


def assert_release_verification(work: Path, bundle: Path) -> None:
    """Prove the shell executed the verification half of the authority gate."""
    assert (work / "release.log").read_text(encoding="utf-8") == (
        f"release verify --bundle-root {bundle.resolve()}\n"
    )


def fresh_answers() -> str:
    # An artifact-gate fixture must explicitly provide its synthetic withdrawal
    # address; the installer intentionally has no maintainer-wallet default.
    return f"DEPLOY\n\n\n{DEPLOYMENT}\n0x{'1' * 40}\nCONFIRM\n"


def write_resume_context(bundle: Path, work: Path) -> Path:
    resume = work / "resume"
    resume.mkdir(mode=0o700)
    inputs = resume / "inputs"
    inputs.mkdir()
    input_file = inputs / "hoodi-zero-release-inputs.json"
    input_file.write_text(json.dumps({"aws_account_id": ACCOUNT, "aws_region": REGION}), encoding="utf-8")
    input_file.chmod(0o600)
    manifest = bundle / "bundle-manifest.json"
    receipt = {
        "schema_version": 1,
        "bundle_manifest_sha256": hashlib.sha256(manifest.read_bytes()).hexdigest(),
        "inputs_sha256": hashlib.sha256(input_file.read_bytes()).hexdigest(),
        "aws_account_id": ACCOUNT,
        "aws_region": REGION,
        "deployment_name": DEPLOYMENT,
        "inputs_rel": "inputs/hoodi-zero-release-inputs.json",
        "work_rel": "deployment-work",
        "session_rel": "private-eks-session.json",
        "phase": "infrastructure",
    }
    receipt_file = resume / "interactive-resume.json"
    receipt_file.write_text(json.dumps(receipt), encoding="utf-8")
    receipt_file.chmod(0o600)
    return resume


def test_missing_withdrawal_stops_before_aws() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        work = Path(temporary)
        _, fake_bin, script = make_bundle(work)
        answers = f"DEPLOY\n\n\n{DEPLOYMENT}\n\n"
        code, output = run_tty(script, fake_bin, work, answers)
        assert code == 64 and "withdrawal address must be explicitly configured" in output, (code, output)
        assert calls(work) == [], calls(work)


def test_unresolved_actual_inventory_stops_at_gate() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        work = Path(temporary)
        bundle, fake_bin, script = make_bundle(work)
        code, output = run_tty(script, fake_bin, work, fresh_answers())
        observed = calls(work)
        assert code == 65, (code, output)
        assert "required installer artifact authority is unresolved; no resources changed" in output, output
        python_calls = (work / "python-calls.log").read_text(encoding="utf-8")
        assert "installer_artifact_inventory.py --bundle-root" in python_calls, python_calls
        assert_release_verification(work, bundle)
        assert observed == ["aws sts get-caller-identity --output json"], observed
        assert_no_aws_mutation(observed)


def test_successful_gate_reaches_only_next_iam_read_boundary() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        work = Path(temporary)
        bundle, fake_bin, script = make_bundle(work, inventory="success")
        code, output = run_tty(script, fake_bin, work, fresh_answers())
        observed = calls(work)
        # The shell intentionally normalizes a failed role lookup to its
        # fail-closed discovery error, so the externally visible exit is 69.
        # The AWS call log is the boundary evidence for the attempted IAM read.
        assert code == 69, (code, output)
        assert "cannot inspect backend role; discovery failure is not an absent role" in output, output
        inventory_args = (work / "inventory.log").read_text(encoding="utf-8")
        expected_args = (
            f"--bundle-root {bundle.resolve()} --release-sha {REVISION} --aws-account-id {ACCOUNT} "
            f"--aws-region {REGION} --deployment-name {DEPLOYMENT} --require-signer-probe\n"
        )
        assert inventory_args == expected_args, (inventory_args, expected_args)
        assert observed == [
            "aws sts get-caller-identity --output json",
            f"aws iam get-role --role-name {DEPLOYMENT}-{REGION}-tfstate --query Role.Arn --output text",
        ], observed
        assert_no_aws_mutation(observed)


def test_resume_context_passes_gate_before_recovery_boundary() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        work = Path(temporary)
        bundle, fake_bin, script = make_bundle(work, inventory="success")
        resume = write_resume_context(bundle, work)
        code, output = run_tty(script, fake_bin, work, "RESUME\n", WORK_DIR=str(resume))
        observed = calls(work)
        assert code == 87, (code, output)
        assert "RELEASE_DEPLOY_BOUNDARY" in output, output
        inventory_args = (work / "inventory.log").read_text(encoding="utf-8")
        expected_args = (
            f"--bundle-root {bundle.resolve()} --release-sha {REVISION} --aws-account-id {ACCOUNT} "
            f"--aws-region {REGION} --deployment-name {DEPLOYMENT} --require-signer-probe\n"
        )
        # Resume validates before prompting, then re-reads authority after confirmation.
        assert inventory_args == expected_args * 2, (inventory_args, expected_args * 2)
        assert observed == ["aws sts get-caller-identity --output json"], observed
        assert_no_aws_mutation(observed)


def test_resume_actual_inventory_failure_stops_before_recovery() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        work = Path(temporary)
        bundle, fake_bin, script = make_bundle(work)
        resume = write_resume_context(bundle, work)
        code, output = run_tty(script, fake_bin, work, "RESUME\n", WORK_DIR=str(resume))
        observed = calls(work)
        assert code == 65, (code, output)
        assert "required installer artifact authority is unresolved; no resources changed" in output, output
        python_calls = (work / "python-calls.log").read_text(encoding="utf-8")
        assert "installer_artifact_inventory.py --bundle-root" in python_calls, python_calls
        assert observed == ["aws sts get-caller-identity --output json"], observed
        assert_release_verification(work, bundle)
        assert_no_aws_mutation(observed)


def test_negative_assertion_detects_a_bypassed_gate_mutant() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        work = Path(temporary)
        _, fake_bin, script = make_bundle(work)
        original = script.read_text(encoding="utf-8")
        needle = 'artifact_authority_json="$(artifact_authority_gate "$account" "$region" "$deployment_name")" || return $?'
        assert needle in original
        rows = []
        for component, repository, digit in (
            ("web3signer", "baseline-validator-runtime-web3signer", "1"),
            ("postgres", "baseline-validator-runtime-postgres", "2"),
            ("prysm-validator", "baseline-validator-prysm", "3"),
            ("validator-signing-fence", "baseline-validator-fence", "4"),
            ("argocd-bootstrap", "baseline-gitops-argocd", "5"),
            ("vault-bootstrap", "baseline-gitops-vault", "6"),
            ("node-operator-client-chart", "baseline-gitops-client/node-operator-client", "7"),
        ):
            digest = "sha256:" + digit * 64
            item = {"component": component, "required": True,
                    "destination": f"{ACCOUNT}.dkr.ecr.{REGION}.amazonaws.com/{DEPLOYMENT}-{repository}@{digest}",
                    "source": f"example.invalid/{repository}@{digest}"}
            if component == "node-operator-client-chart":
                item["destination_tag"] = "0.1.37"
            rows.append(item)
        forged = json.dumps({"schema_version": 1, "complete": True, "artifacts": rows})
        script.write_text(original.replace(needle, f"artifact_authority_json='{forged}' # deliberately bypassed authority gate"), encoding="utf-8")
        code, output = run_tty(script, fake_bin, work, fresh_answers())
        observed = calls(work)
        # A correct negative assertion must reject this behavior: the real,
        # failing inventory was skipped and execution reached the next IAM read.
        detected = code == 65 and "required installer artifact authority is unresolved; no resources changed" in output
        assert not detected, (code, output)
        assert code == 69 and "cannot inspect backend role; discovery failure is not an absent role" in output, (code, output)
        assert any("aws iam get-role" in line for line in observed), observed
        assert_no_aws_mutation(observed)


test_missing_withdrawal_stops_before_aws()
test_unresolved_actual_inventory_stops_at_gate()
test_successful_gate_reaches_only_next_iam_read_boundary()
test_resume_context_passes_gate_before_recovery_boundary()
test_resume_actual_inventory_failure_stops_before_recovery()
test_negative_assertion_detects_a_bypassed_gate_mutant()
print("PASS: PTY artifact-authority gate boundaries and mutation sensitivity verified")
