#!/usr/bin/env bash
# Check objective: Collect baseline findings under trusted configuration and retain actionable policy evidence.
# Purpose: Scan the trusted base checkout and isolate findings newly introduced by the PR.
# Inputs: Pinned SCANNER_IMAGE, registry credentials, base/subject SHAs, trusted configs, and evidence paths.
# Outputs: Filtered baseline policy input beneath EVIDENCE_ROOT.
# Side effects: Pulls a scanner image and writes runner-local evidence; source mounts remain read-only.
set -euo pipefail

echo "$REGISTRY_TOKEN" | docker login ghcr.io -u "$REGISTRY_USERNAME" --password-stdin
docker pull "$SCANNER_IMAGE"
mkdir -p "$RUNNER_TEMP/base-security-evidence"
docker run --rm \
  --env SKIP_TERRAFORM=true \
  --env SEMGREP_RULES=/trusted-config/semgrep.yml \
  --env GITLEAKS_CONFIG=/trusted-config/gitleaks.toml \
  --env GITLEAKS_IGNORE_PATH=/trusted-config/gitleaksignore \
  --env CHECKOV_CONFIG_FILE=/trusted-config/checkov.yml \
  --env OSV_CONFIG_FILE=/trusted-config/osv-scanner.toml \
  --volume "$GITHUB_WORKSPACE/.semgrep/ci.yml:/trusted-config/semgrep.yml:ro" \
  --volume "$GITHUB_WORKSPACE/scripts/ci/trusted-scanner/gitleaks.toml:/trusted-config/gitleaks.toml:ro" \
  --volume "$GITHUB_WORKSPACE/scripts/ci/trusted-scanner/gitleaksignore:/trusted-config/gitleaksignore:ro" \
  --volume "$GITHUB_WORKSPACE/scripts/ci/trusted-scanner/checkov.yml:/trusted-config/checkov.yml:ro" \
  --volume "$GITHUB_WORKSPACE/scripts/ci/trusted-scanner/osv-scanner.toml:/trusted-config/osv-scanner.toml:ro" \
  --volume "$GITHUB_WORKSPACE/.base-source:/workspace:ro" \
  --volume "$RUNNER_TEMP/base-security-evidence:/evidence" \
  "$SCANNER_IMAGE" /evidence "$BASE_SHA" "$BASE_SHA"
scripts/ci/filter-pr-baseline-findings.sh \
  "$EVIDENCE_ROOT/raw" "$RUNNER_TEMP/base-security-evidence" \
  "$EVIDENCE_ROOT/policy-input" "$SUBJECT_SHA"
