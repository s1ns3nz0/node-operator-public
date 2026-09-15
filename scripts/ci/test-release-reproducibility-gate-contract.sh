#!/usr/bin/env bash
# Check objective: Enforce the inlined release reproducibility gate and exact-SBOM SCA contracts.
# shellcheck disable=SC2016 # The workflow contract must match the literal GitHub runner variable.
set -euo pipefail
# shellcheck source=scripts/ci/lib/workflow-contract.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/workflow-contract.sh"

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
release="$root/.github/workflows/release-bundle.yml"
reproducibility="$(workflow_job_source "$release" reproducibility)"
# Both bundle passes must use the reviewed Python-capable executor, not the
# retired image that stopped at the first Python-based evidence validator.
expected_executor='ghcr.io/s1ns3nz0/node-operator/release-build@sha256:5221febd3278d7081ec6e5655b2d5036b4c22c5cca6755be036517d10eb05254'
[ "$(grep -Fc "RELEASE_BUILD_IMAGE: $expected_executor" "$release")" -eq 2 ]
grep -Fq 'environment: gitops-evidence-reader' <<<"$reproducibility"
grep -Fq 'actions/create-github-app-token@bcd2ba49218906704ab6c1aa796996da409d3eb1' <<<"$reproducibility"
grep -Fq 'client-id: ${{ vars.GITOPS_EVIDENCE_APP_CLIENT_ID }}' <<<"$reproducibility"
grep -Fq 'private-key: ${{ secrets.GITOPS_EVIDENCE_APP_PRIVATE_KEY }}' <<<"$reproducibility"
grep -Fq 'owner: s1ns3nz0' <<<"$reproducibility"
grep -Fq 'repositories: node-operator-public-gitops' <<<"$reproducibility"
grep -Fq 'permission-actions: read' <<<"$reproducibility"
grep -Fq 'skip-token-revoke: false' <<<"$reproducibility"
grep -Fq 'GITOPS_EVIDENCE_TOKEN: ${{ steps.gitops-reader.outputs.token }}' <<<"$reproducibility"
if grep -Fq 'uses: ./.github/workflows/ci-release-integrity.yml' "$release"; then
  printf 'release reproducibility must be inlined rather than call the retired reusable workflow\n' >&2
  exit 1
fi
grep -Fq 'needs: eligibility' <<<"$reproducibility"
grep -Fq 'verify-release-source-eligibility.sh "$GITHUB_SHA"' "$release"
grep -Fq 'needs: [eligibility, reproducibility]' "$release"
grep -Fq "inputs.mode == 'verify-only'" <<<"$reproducibility"
grep -Fq '!cancelled()' <<<"$reproducibility"
grep -Fq 'test-build-release-bundle.sh --publication-records-dir /publication-records' <<<"$reproducibility"
grep -Fq 'mkdir -p "$RUNNER_TEMP/current"' <<<"$reproducibility"
grep -Fq '"$RUNNER_TEMP/current:/output/current"' <<<"$reproducibility"
if grep -Fq '"$RUNNER_TEMP:/output"' <<<"$reproducibility"; then
  printf 'release reproducibility must not mount the runner temporary root as writable output\n' >&2
  exit 1
fi
grep -Fq 'name: prysm-publication-record-${{ github.sha }}' "$release"
grep -Fq 'path: ${{ runner.temp }}/prysm-publication-record/prysm-mtls-publication-record.json' "$release"
grep -Fq 'Download frozen Prysm publication record' "$release"
grep -Fq 'PRYSM_PUBLICATION_RECORD: ${{ runner.temp }}/prysm-publication-record/prysm-mtls-publication-record.json' "$release"
grep -Fq 'name: fence-publication-record-${{ github.sha }}' "$release"
grep -Fq 'path: ${{ runner.temp }}/fence-publication-record/fence-release-verification.json' "$release"
grep -Fq 'Download frozen Fence publication record' "$release"
grep -Fq "FENCE_PUBLICATION_RECORD: \${{ hashFiles('release/fence-publication-authorization.json') != '' && format('{0}/fence-publication-record/fence-release-verification.json', runner.temp) || '' }}" "$release"
grep -Fq -- '--fence-publication-record /fence-release-verification.json' <<<"$reproducibility"
grep -Fq 'name: client-chart-publication-records-${{ github.sha }}' "$release"
grep -Fq 'Download frozen client chart publication records' "$release"
grep -Fq 'CLIENT_CHART_PUBLICATION_RECORDS: ${{ hashFiles' "$release"
grep -Fq -- '--client-chart-publication-records /client-chart-publication-records' <<<"$reproducibility"
grep -Fq 'name: signer-probe-publication-record-${{ github.sha }}' "$release"
grep -Fq 'path: ${{ runner.temp }}/signer-probe-publication-record/signer-identity-probe-publication-record.json' "$release"
grep -Fq "SIGNER_PROBE_PUBLICATION_RECORD: \${{ hashFiles('release/signer-probe-publication-authorization.json') != '' && format('{0}/signer-probe-publication-record/signer-identity-probe-publication-record.json', runner.temp) || '' }}" "$release"
grep -Fq -- '--signer-probe-publication-record /signer-probe-publication-record.json' <<<"$reproducibility"
grep -Fq 'install-release-sca-tool.sh "$RUNNER_TEMP/release-sca-bin"' <<<"$reproducibility"
grep -Fq 'scan-release-sbom.sh' <<<"$reproducibility"
grep -Fq 'sbom.cyclonedx.json' <<<"$reproducibility"
grep -Fq '.findings.critical == 0 and .findings.high == 0 and .findings.unknown == 0' <<<"$reproducibility"
grep -Fq 'artifact_digest: ${{ steps.sca-binding.outputs.artifact_digest }}' <<<"$reproducibility"
grep -Fq 'APPROVED_ARTIFACT_DIGEST: ${{ needs.reproducibility.outputs.artifact_digest }}' "$release"
grep -Fq 'sha256sum "$RUNNER_TEMP/release/node-operator-release-bundle.tar"' <(workflow_source "$release")
grep -Fq "jq -er '.metadata.component.version'" <(workflow_source "$release")
printf '%s\n' 'PASS: release publication is blocked on the inlined reproducibility and exact-SBOM SCA gate.'
