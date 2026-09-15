#!/usr/bin/env bash
# Check objective: Download only this run's completed verification artifacts.
# Purpose: Retrieve this eligible run's three Vault runtime verification artifact sets for signing.
# Inputs: GITHUB_RUN_ID, GITHUB_REPOSITORY, GH_TOKEN, and release-eligibility provenance.
# Outputs: Verification artifacts beneath RUNNER_TEMP/vault-signed-evidence.
# Side effects: Read-only GitHub API and artifact-download calls; no release or registry mutation.
set -euo pipefail

bash scripts/ci/verify-release-source-eligibility.sh "$GITHUB_SHA"
for component in server agent injector; do
  gh run download "$GITHUB_RUN_ID" --repo "$GITHUB_REPOSITORY" \
    --name "vault-runtime-$component-verification" \
    --dir "$RUNNER_TEMP/vault-signed-evidence/vault-runtime-$component-verification"
done
