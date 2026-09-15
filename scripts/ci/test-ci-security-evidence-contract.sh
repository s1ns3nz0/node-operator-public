#!/usr/bin/env bash
# Check objective: Preserve immutable scanner-image and evidence-gate contracts across security workflows.
# shellcheck disable=SC2016
set -euo pipefail
# shellcheck source=scripts/ci/lib/workflow-contract.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/workflow-contract.sh"

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
workflow="$script_dir/../../.github/workflows/continuous-integration.yml"
gate_workflow="$script_dir/../../.github/workflows/evidence-gate.yml"
review_workflow="$script_dir/../../.github/workflows/review-signal.yml"
review_handler="$gate_workflow"

check_scanner_images() {
  local scanner_workflow="$1"
  local scanner_gate_workflow="$2"
  local scanner_image
  local gate_scanner_image
  local immutable_scanner_image_pattern='^ghcr\.io/s1ns3nz0/node-operator/security-scanners@sha256:[0-9a-f]{64}$'

  scanner_image="$(sed -nE 's/^[[:space:]]*SCANNER_IMAGE:[[:space:]]*([^[:space:]#]+).*$/\1/p' "$scanner_workflow")"
  gate_scanner_image="$(sed -nE 's/^[[:space:]]*SCANNER_IMAGE:[[:space:]]*([^[:space:]#]+).*$/\1/p' "$scanner_gate_workflow")"

  if ! [[ "$scanner_image" =~ $immutable_scanner_image_pattern ]]; then
    printf 'ci-security scanner image must use one immutable lowercase SHA-256 reference\n' >&2
    return 1
  fi

  if ! [[ "$gate_scanner_image" =~ $immutable_scanner_image_pattern ]]; then
    printf 'opa-pr-gate scanner image must use one immutable lowercase SHA-256 reference\n' >&2
    return 1
  fi

  if [[ "$scanner_image" != "$gate_scanner_image" ]]; then
    printf 'scanner image references must match across security workflows\n' >&2
    return 1
  fi
}

run_scanner_image_guard_tests() {
  local test_dir
  local ci_fixture
  local gate_fixture
  local valid_image='ghcr.io/s1ns3nz0/node-operator/security-scanners@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'

  test_dir="$(mktemp -d)"
  ci_fixture="$test_dir/ci.yml"
  gate_fixture="$test_dir/evidence-gate.yml"
  trap 'rm -rf "$test_dir"' RETURN

  printf 'SCANNER_IMAGE: %s\n' "$valid_image" > "$ci_fixture"
  printf 'SCANNER_IMAGE: %s\n' "$valid_image" > "$gate_fixture"
  check_scanner_images "$ci_fixture" "$gate_fixture"

  printf 'SCANNER_IMAGE: ghcr.io/s1ns3nz0/node-operator/security-scanners@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n' > "$gate_fixture"
  if check_scanner_images "$ci_fixture" "$gate_fixture" 2>/dev/null; then
    printf 'scanner image guard accepted mismatched image references\n' >&2
    return 1
  fi

  printf 'SCANNER_IMAGE: ghcr.io/s1ns3nz0/node-operator/security-scanners:latest\n' > "$ci_fixture"
  printf 'SCANNER_IMAGE: ghcr.io/s1ns3nz0/node-operator/security-scanners:latest\n' > "$gate_fixture"
  if check_scanner_images "$ci_fixture" "$gate_fixture" 2>/dev/null; then
    printf 'scanner image guard accepted a floating tag\n' >&2
    return 1
  fi

  printf 'SCANNER_IMAGE: %s\nSCANNER_IMAGE: %s\n' "$valid_image" "$valid_image" > "$ci_fixture"
  printf 'SCANNER_IMAGE: %s\n' "$valid_image" > "$gate_fixture"
  if check_scanner_images "$ci_fixture" "$gate_fixture" 2>/dev/null; then
    printf 'scanner image guard accepted multiple SCANNER_IMAGE bindings\n' >&2
    return 1
  fi
}

if [[ "${1:-}" == '--self-test-scanner-images' ]]; then
  run_scanner_image_guard_tests
  printf 'PASS: scanner image guard rejects invalid bindings.\n'
  exit 0
fi

check_scanner_images "$workflow" "$gate_workflow"

# The scanner produces the sole uploadable evidence in a non-hidden directory,
# rather than a hidden checkout path. This preserves upload-artifact's safe
# default (hidden files excluded) and prevents an accidental workspace-wide
# upload. The scanner mounts the workspace read-only and /evidence separately.
grep -Fq 'EVIDENCE_ROOT: ${{ github.workspace }}/security-evidence' <(workflow_job_source "$workflow" security-scans)
grep -Fq 'path: ${{ env.EVIDENCE_ROOT }}' <(workflow_job_source "$workflow" security-scans)
grep -Fq -- '--volume "$GITHUB_WORKSPACE:/workspace:ro"' <(workflow_job_source "$workflow" security-scans)
grep -Fq -- '--volume "$EVIDENCE_ROOT:/evidence"' <(workflow_job_source "$workflow" security-scans)
if grep -Fq 'include-hidden-files: true' <(workflow_job_source "$workflow" security-scans); then
  printf 'security evidence upload must not include hidden files\n' >&2
  exit 1
fi

test "$(grep -Fc 'checks: write' <(workflow_source "$gate_workflow"))" -eq 3
grep -Fq 'resolve-pr-evidence-context.sh' <(workflow_source "$gate_workflow")
grep -Fq 'ref: ${{ steps.context.outputs.trusted_sha }}' <(workflow_source "$gate_workflow")
grep -Fq 'run: bash scripts/ci/workflows/collect-head-security.sh' "$gate_workflow"
grep -Fq -- '--volume "$GITHUB_WORKSPACE/.pr-source:/workspace:ro"' <(workflow_source "$gate_workflow")
grep -Fq -- '--volume "$RUNNER_TEMP/head-security-evidence:/evidence"' <(workflow_source "$gate_workflow")
grep -Fq -- '--env SEMGREP_RULES=/trusted-config/semgrep.yml' <(workflow_source "$gate_workflow")
grep -Fq -- '--env GITLEAKS_CONFIG=/trusted-config/gitleaks.toml' <(workflow_source "$gate_workflow")
grep -Fq -- '--volume "$GITHUB_WORKSPACE/.semgrep/ci.yml:/trusted-config/semgrep.yml:ro"' <(workflow_source "$gate_workflow")
grep -Fq -- '--volume "$GITHUB_WORKSPACE/scripts/ci/trusted-scanner/gitleaks.toml:/trusted-config/gitleaks.toml:ro"' <(workflow_source "$gate_workflow")
grep -Fq 'run: bash scripts/ci/workflows/reject-scanner-policy-replacement.sh' "$gate_workflow"
grep -Fq '*:osv-scanner.toml|*:.osv-scanner.toml' <(workflow_source "$gate_workflow")
grep -Fq 'git -C .pr-source diff --name-only -z' <(workflow_source "$gate_workflow")
grep -Fq 'read -r -d' <(workflow_source "$gate_workflow")
grep -Fq -- '--env CHECKOV_CONFIG_FILE=/trusted-config/checkov.yml' <(workflow_source "$gate_workflow")
grep -Fq -- '--env OSV_CONFIG_FILE=/trusted-config/osv-scanner.toml' <(workflow_source "$gate_workflow")
grep -Fq -- 'osv-scanner scan source --config="$OSV_CONFIG_FILE" --no-ignore' "$script_dir/collect-pr-evidence.sh"
grep -Fq -- '--disable-nosem --no-git-ignore' "$script_dir/collect-pr-evidence.sh"
grep -Fq -- 'zizmor --offline --no-config' "$script_dir/collect-pr-evidence.sh"
grep -Fq 'untrusted-zizmor-suppression' "$script_dir/collect-pr-evidence.sh"
if grep -Fq 'Download scanner evidence from the completed PR run' <(workflow_source "$gate_workflow"); then
  printf 'trusted decision must not consume a pull-request-controlled scanner artifact\n' >&2
  exit 1
fi
grep -Fq 'run: scripts/ci/publish-pr-evidence-check.sh "$SUBJECT_SHA" "$EVIDENCE_ROOT/published/decision.json"' "$gate_workflow"
# The failure producer uses a multiline block so publishing cannot turn failure
# into workflow success. Its executable exit behavior is tested by the archive contract.
grep -Fq 'scripts/ci/publish-pr-evidence-check.sh "$SUBJECT_SHA" - "$DETAILS_URL"' <(workflow_job_source "$gate_workflow" upstream-failure)
grep -Eq '^[[:space:]]+exit 1$' <(workflow_job_source "$gate_workflow" upstream-failure)
grep -Fq 'publish-pr-evidence-check.sh "$SUBJECT_SHA"' <(workflow_source "$gate_workflow")

printf 'PASS: scanner evidence is confined to a non-hidden dedicated directory.\n'

grep -Fq 'pull_request_review:' "$review_workflow"
grep -Fq 'permissions: {}' "$review_workflow"
if grep -Fq 'actions/checkout' "$review_workflow"; then
  printf 'review signal must not checkout pull-request context\n' >&2
  exit 1
fi
if grep -Eq '(actions|checks|contents|pull-requests): write|request-pr-evidence-refresh' "$review_workflow"; then
  printf 'review signal must not have write permissions or invoke repository code\n' >&2
  exit 1
fi
grep -Fq 'workflows: [CI, CI Evidence Review Signal]' "$review_handler"
grep -Fq 'refresh-review-evidence.py' <(workflow_job_source "$review_handler" review-refresh)
grep -Fq 'checks: write' <(workflow_job_source "$review_handler" review-refresh)
if workflow_job_source "$review_handler" review-refresh | grep -Eq 'actions: write|docker run|collect-head-security|collect-trusted-terraform|/rerun'; then
  printf 'review refresh must not rescan or request Actions write permission\n' >&2
  exit 1
fi
