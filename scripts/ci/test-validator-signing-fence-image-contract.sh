#!/usr/bin/env bash
# Check objective: Enforce the hardened signing-fence image build and release contract.
set -euo pipefail
# shellcheck source=scripts/ci/lib/workflow-contract.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/workflow-contract.sh"
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
dockerfile="$root/.ci/validator-signing-fence/Dockerfile"
workflow="$root/.github/workflows/image-publish.yml"
fail(){ printf 'FAIL signing fence image contract: %s\n' "$*" >&2; exit 1; }
grep -Eq '^FROM golang:1\.26\.6-alpine@sha256:[a-f0-9]{64} AS build$' "$dockerfile" || fail 'builder is not digest pinned'
grep -Fq 'FROM scratch' "$dockerfile" || fail 'runtime is not scratch'
grep -Fq 'USER 65532:65532' "$dockerfile" || fail 'runtime is not non-root'
grep -Fq 'COPY cmd/validator-signing-fence/main.go' "$dockerfile" || fail 'reviewed source is not explicit'
grep -Fq 'environment: validator-client-ecr-mirror' <(workflow_source "$workflow") || fail 'protected environment missing'
# Literal workflow source.
# shellcheck disable=SC2016
grep -Fq 'test "$GITHUB_REF" = refs/heads/main' <(workflow_source "$workflow") || fail 'main-only publish gate missing'
grep -Fq 'CGO_ENABLED=0 go test ./cmd/validator-signing-fence &&' "$dockerfile" || fail 'tests do not run before the build in the digest-pinned builder'
# shellcheck disable=SC2016 # Literal workflow source.
grep -Fq 'file://$token_file' <(workflow_source "$workflow") || fail 'OIDC token is passed in process argv instead of an indirection file'
# shellcheck disable=SC2016 # Literal workflow source.
if grep -Fq -- '--web-identity-token "$token"' <(workflow_source "$workflow"); then fail 'OIDC token appears directly in process argv'; fi
grep -Fq '::add-mask::' <(workflow_source "$workflow") || fail 'temporary credentials are not masked'
grep -Fq 'persist-credentials: false' <(workflow_source "$workflow") || fail 'checkout credentials persist'
# shellcheck disable=SC2016 # Literal workflow source.
grep -Fq "DEPLOYMENT_NAME: \${{ vars.DEPLOYMENT_NAME || 'node-operator' }}" "$workflow" || fail 'fence workflow does not supply the deployment context'
# shellcheck disable=SC2016 # Literal workflow source.
grep -Fq 'DEPLOYMENT_NAME="${DEPLOYMENT_NAME:-node-operator}"' <(workflow_source "$workflow") || fail 'fence publisher has no compatibility deployment default'
# shellcheck disable=SC2016 # Literal workflow source.
grep -Fq 'repository="${DEPLOYMENT_NAME}-baseline-validator-fence"' <(workflow_source "$workflow") || fail 'fence image is not deployment-scoped and type-separated'
grep -Fq 'install-validator-signing-fence-release-tools.sh' <(workflow_source "$workflow") || fail 'pinned release tools are not installed'
# shellcheck disable=SC2016 # Literal workflow source.
grep -Fq 'cosign sign --yes "$subject"' <(workflow_source "$workflow") || fail 'exact image digest is not signed'
for kind in slsaprovenance1 cyclonedx https://github.com/s1ns3nz0/node-operator/attestations/scan-summary/v1; do grep -Fq "cosign attest --yes --type $kind" <(workflow_source "$workflow") || fail "$kind attestation missing"; done
grep -Fq 'needs: [select, fence-security]' "$workflow" || fail 'fence publication does not depend on selection and fence security'
grep -Fq "needs.fence-security.result == 'success'" "$workflow" || fail 'fence publication does not require successful fence security'
grep -Fq 'uses: ./.github/workflows/fence-security.yml' <(workflow_source "$workflow") || fail 'release does not execute the security workflow'
ci_workflow="$root/.github/workflows/continuous-integration.yml"
grep -Fq 'needs: [fence-security, quality-tests]' <(workflow_job_source "$ci_workflow" quality) || fail 'required quality check does not depend on fence security'
grep -Fq 'if: always()' <(workflow_job_source "$ci_workflow" quality) || fail 'required quality check can be skipped after failed security'
# shellcheck disable=SC2016 # Literal workflow source.
grep -Fq 'run: test "$FENCE_SECURITY_RESULT" = success' <(workflow_job_source "$ci_workflow" quality) || fail 'required quality check does not fail on skipped/failed security'
# shellcheck disable=SC2016 # Literal workflow source.
grep -Fq 'FENCE_SECURITY_RESULT: ${{ needs.fence-security.result }}' <(workflow_job_source "$ci_workflow" quality) || fail 'quality result is not bound to the actual security dependency'
# shellcheck disable=SC2016 # Literal workflow source.
grep -Fq 'collect-validator-signing-fence-release-evidence.sh "$subject" "$GITHUB_SHA"' <(workflow_source "$workflow") || fail 'authenticated release collector is not executed'
grep -Fq 'actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02' <(workflow_source "$workflow") || fail 'sanitized release evidence is not retained through a pinned action'
grep -Fq 'aws_ecr_repository" "validator_signing_fence' "$root/infra/terraform/validator-client-ecr-mirror.tf" || fail 'dedicated immutable fence repository missing'
if grep -Eq 'ecr:(Delete|SetRepositoryPolicy)|docker build .*--push' <(workflow_source "$workflow"); then fail 'destructive or unreviewed publish path found'; fi
printf '%s\n' 'PASS signing fence image is review-built from pinned inputs through the protected OIDC environment.'
