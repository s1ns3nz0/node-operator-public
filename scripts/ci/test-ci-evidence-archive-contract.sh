#!/usr/bin/env bash
# Check objective: Ensure CI evidence is redacted, Cosign-signed, verified, and archived through the dedicated S3 role.
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
workflow="$root/.github/workflows/evidence-archive.yml"
iac="$root/infra/terraform/ci-evidence-archive.tf"
archive="$root/scripts/ci/archive-ci-evidence.sh"
assume="$root/scripts/ci/assume-ci-evidence-archive-role.sh"
resolver="$root/scripts/ci/resolve-ci-evidence-archive-subject.sh"
for file in "$workflow" "$iac" "$archive" "$assume" "$resolver"; do
  test -f "$file" || { printf 'missing archive contract file: %s\n' "$file" >&2; exit 1; }
done
grep -Fq 'workflow_run:' "$workflow"
grep -Fq 'workflows: [CI Evidence Gate]' "$workflow"
grep -Fq "github.event.workflow_run.conclusion == 'success'" "$workflow"
python3 - "$root/.github/workflows/evidence-gate.yml" <<'PY'
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

source = Path(sys.argv[1]).read_text()
step = source.split('- name: Failed Exact-SHA Evidence Check', 1)[1].split('\n  evidence-gate:', 1)[0]
match = re.search(r'        run: \|\n((?:          .*\n)+)', step)
assert match, 'upstream failure must have an explicit failing run block'
body = '\n'.join(line[10:] for line in match.group(1).splitlines())
with tempfile.TemporaryDirectory() as directory:
    stub = Path(directory) / 'scripts/ci/publish-pr-evidence-check.sh'
    stub.parent.mkdir(parents=True)
    stub.write_text('#!/bin/sh\nprintf "published-failure\\n"\nexit 0\n')
    stub.chmod(0o700)
    result = subprocess.run(['bash', '-e', '-c', body], cwd=directory,
        env={'PATH': os.environ['PATH'], 'SUBJECT_SHA': 'a' * 40,
             'DETAILS_URL': 'https://example.invalid'}, capture_output=True, text=True, timeout=5)
    assert result.stdout.strip() == 'published-failure', result.stderr
    assert result.returncode == 1, 'published failure must not trigger success-only archive'
PY
grep -Fq 'id-token: write' "$workflow"
grep -Fq 'actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093' "$workflow"
python3 - "$workflow" "$resolver" <<'PY'
from pathlib import Path
import sys

workflow = Path(sys.argv[1]).read_text()
resolver = Path(sys.argv[2]).read_text()
assert 'pattern: ci-evidence-gate-*' in workflow
assert 'pattern: ci-review-decision-${{ github.event.workflow_run.id }}' in workflow
assert '${{ runner.temp }}/ci-evidence/gate' in workflow
assert '${{ runner.temp }}/ci-evidence/review' in workflow
assert 'EXPECTED_GATE_RUN_ID: ${{ github.event.workflow_run.id }}' in workflow
assert 'run: scripts/ci/resolve-ci-evidence-archive-subject.sh' in workflow
assert 'evidence is not in its expected exact-run artifact directory' in resolver
assert 'cache context does not bind the exact evidence subject' in resolver
assert 'expected exactly one valid exact-run evidence artifact' in resolver
PY
python3 - "$resolver" <<'PY'
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

script = Path(sys.argv[1])
sha = 'a' * 40

def run(files, expected_gate_run=900):
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory) / 'evidence'
        output = Path(directory) / 'output'
        for source, name, value, context_subject, context_gate_run in files:
            target = root / source / name / 'evidence.json'
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(json.dumps({'subject': {'commit_sha': value}}))
            (target.parent / 'decision.json').write_text(json.dumps({'summary': {'block': 0, 'require_approval': 0}, 'violations': []}))
            (target.parent / 'cache-context.json').write_text(json.dumps({
                'schema_version': 1, 'subject_sha': context_subject, 'base_sha': 'b' * 40,
                'trusted_sha': 'c' * 40, 'source_run_id': 800, 'gate_run_id': context_gate_run,
            }))
        result = subprocess.run(['bash', str(script)], text=True, capture_output=True,
            env=os.environ | {'EVIDENCE_ROOT': str(root), 'EXPECTED_GATE_RUN_ID': str(expected_gate_run),
                              'GITHUB_OUTPUT': str(output)})
        return result, output.read_text() if output.exists() else ''

result, output = run([('gate', f'ci-evidence-gate-{sha}', sha, sha, 900)])
assert result.returncode == 0, result.stderr
lines = output.splitlines()
assert lines[0] == f'subject_sha={sha}'
assert len(lines) == 2 and lines[1].startswith('evidence_directory=')
assert lines[1].split('=', 1)[1].endswith(f'/gate/ci-evidence-gate-{sha}')
result, output = run([('review', 'ci-review-decision-900', sha, sha, 700)])
assert result.returncode == 0, result.stderr
for files in (
    [],
    [('gate', f'ci-evidence-gate-{sha}', sha, sha, 900), ('review', 'ci-review-decision-900', sha, sha, 700)],
    [('gate', f'ci-evidence-gate-{sha}', sha, sha, 700)],
    [('review', 'ci-review-decision-900', sha, 'b' * 40, 700)],
    [('gate', 'wrong-directory', sha, sha, 900)],
):
    result, output = run(files)
    assert result.returncode != 0, (files, output)
PY
grep -Fq 'cosign sign-blob --yes --bundle' "$archive"
grep -Fq 'cosign verify-blob --bundle' "$archive"
grep -Fq 'aws s3 cp' "$archive"
grep -Fq 'manifest.sigstore.json' "$archive"
grep -Fq 'object_lock_enabled = true' "$iac"
grep -Fq 'default_retention' "$iac"
grep -Fq 'sse_algorithm     = "aws:kms"' "$iac"
grep -Fq 'ci-evidence-archive' "$iac"
grep -Fq 'sts:AssumeRoleWithWebIdentity' "$iac"
python3 - "$iac" <<'PY'
from pathlib import Path
import re
import sys

text = Path(sys.argv[1]).read_text()
key = text.split('data "aws_iam_policy_document" "ci_evidence_archive_key" {', 1)[1].split('\ndata ', 1)[0]
context = re.search(r'variable\s*=\s*"kms:EncryptionContext:aws:s3:arn"\s*.*?values\s*=\s*\[(.*?)\n\s*\]', key, re.S)
assert context, 'archive KMS encryption context must be bounded'
values = re.sub(r'\s+', '', context.group(1))
assert values == 'aws_s3_bucket.ci_evidence_archive[0].arn,"${aws_s3_bucket.ci_evidence_archive[0].arn}/ci/*",', 'permit only the exact bucket key context and legacy ci/ object context'
assert 'variable = "kms:ViaService"' in key
assert 'values   = ["s3.${var.aws_region}.amazonaws.com"]' in key
assert 'bucket_key_enabled = true' in text
role = text.split('data "aws_iam_policy_document" "github_ci_evidence_archive" {', 1)[1].split('\nresource ', 1)[0]
assert '"s3:HeadObject"' not in role, 'HeadObject is authorized by s3:GetObject'
assert 'actions   = ["s3:GetObject"]' in role
assert 'resources = ["${aws_s3_bucket.ci_evidence_archive[0].arn}/ci/*"]' in role
PY
if grep -Eq 'secrets/|VAULT_TOKEN|recovery.key|private_key' "$archive"; then
  printf 'archive script contains a forbidden secret path or token reference\n' >&2
  exit 1
fi
bash -n "$archive" "$assume" "$resolver"
python3 "$root/scripts/ci/test-ci-evidence-archive-runtime.py"
printf 'PASS: CI evidence archive is Cosign-signed, verified, redacted, and OIDC-scoped.\n'
