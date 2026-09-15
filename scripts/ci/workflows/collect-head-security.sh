#!/usr/bin/env bash
# Check objective: Collect head findings with trusted policy mounted separately from untrusted PR source.
# Purpose: Scan the PR head using only trusted scanner configuration.
# Inputs: Pinned SCANNER_IMAGE, registry credentials, subject/base SHAs, and checked-out trusted configs.
# Outputs: Raw JSON scanner evidence beneath EVIDENCE_ROOT/raw.
# Side effects: Pulls a scanner image and writes runner-local evidence; the PR source is mounted read-only.
set -euo pipefail

echo "$REGISTRY_TOKEN" | docker login ghcr.io -u "$REGISTRY_USERNAME" --password-stdin
docker pull "$SCANNER_IMAGE"
mkdir -p "$RUNNER_TEMP/head-security-evidence"
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
  --volume "$GITHUB_WORKSPACE/.pr-source:/workspace:ro" \
  --volume "$RUNNER_TEMP/head-security-evidence:/evidence" \
  "$SCANNER_IMAGE" /evidence "$SUBJECT_SHA" "$BASE_SHA"
mkdir -p "$EVIDENCE_ROOT/raw"
cp "$RUNNER_TEMP/head-security-evidence"/*.json "$EVIDENCE_ROOT/raw/"
