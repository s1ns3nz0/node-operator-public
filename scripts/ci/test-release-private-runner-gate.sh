#!/usr/bin/env bash
# Check objective: Require protected private execution for release publication while allowing unprivileged eligibility checks on hosted runners.
set -euo pipefail
# shellcheck source=scripts/ci/lib/workflow-contract.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/workflow-contract.sh"

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$script_dir/lib/common.sh"
root="$(repo_root)"
fail() { printf 'FAIL %s\n' "$*" >&2; exit 1; }

workflow="$root/.github/workflows/release-bundle.yml"
contract="$root/docs/gitops/private-release-runner-contract.md"
operations_workflow="$root/.github/workflows/operations-verification.yml"

test -f "$workflow" || fail 'missing release workflow'
test -f "$contract" || fail 'missing private release-runner contract'
test -f "$operations_workflow" || fail 'missing operations workflow'

# shellcheck disable=SC2016 # The literal GitHub expression is part of the workflow contract.
grep -Fq "runs-on: codebuild-\${{ vars.PRIVATE_RELEASE_RUNNER_PROJECT || 'node-operator-baseline-private-release' }}-\${{ github.run_id }}-\${{ github.run_attempt }}" "$workflow" || fail 'release workflow is not bound to the selected dedicated CodeBuild runner and workflow-run identity'
grep -Eq '^    environment: release$' "$workflow" || fail 'release workflow does not require the protected release environment'

publication_job="$(sed -n '/^  build-and-publish:/,$p' "$workflow")"
if grep -Eq 'runs-on: (ubuntu-|windows-|macos-)' <<<"$publication_job"; then
  fail 'release publication permits a GitHub-hosted runner'
fi

# shellcheck disable=SC2016 # These are literal workflow fragments, not shell expressions.
for required in \
  'RELEASE_RUNNER_ROLE_ARN' \
  'RELEASE_ARTIFACT_BUCKET' \
  'PRIVATE_RELEASE_RUNNER_PROJECT' \
  'RELEASE_SIGNER_PROJECT' \
  'test -n "$AWS_ROLE_ARN"; test -n "$INPUT_BUCKET"' \
  'verify-release-signature.sh'; do
  grep -Fq "$required" <(workflow_source "$workflow") || fail "release workflow omits fail-closed prerequisite: $required"
done

if grep -Fq 'runs-on: ubuntu-' <<<"$publication_job"; then
  fail 'release publication permits a GitHub-hosted runner'
fi

# The manual smoke is the non-deployment proof that the private CodeBuild
# runner can obtain the reviewed build image and reach only required AWS APIs.
for required in \
  'packages: read' \
  'environment: private-runner-smoke' \
  "docker pull \"\$RELEASE_BUILD_IMAGE\"" \
  'aws eks describe-cluster --name node-operator' \
  'aws ecr get-authorization-token' \
  'aws logs describe-log-groups'; do
  grep -Fq "$required" <(workflow_job_source "$operations_workflow" smoke) || fail "private runner smoke omits required connectivity check: $required"
done
grep -Fq "inputs.target == 'private-runner'" <(workflow_job_source "$operations_workflow" smoke) || fail 'private runner smoke is not target-scoped'
grep -Fq "github.ref == 'refs/heads/main'" <(workflow_job_source "$operations_workflow" smoke) || fail 'private runner smoke is not main-only'

printf 'PASS release workflow requires the protected private-runner boundary.\n'
