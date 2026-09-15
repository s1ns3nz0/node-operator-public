#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
source "$root/scripts/ci/lib/workflow-contract.sh"
terraform_file="$root/infra/terraform/validator-client-ecr-mirror.tf"
workflow="$root/.github/workflows/private-ecr-mirror.yml"
allowlist="$root/.ci/validator/approved-client-images.json"
for required in 'enable_validator_client_ecr_mirror' 'default     = false' 'aws_ecr_repository" "validator_client' 'image_tag_mutability = "IMMUTABLE"' 'encryption_type = "KMS"' 'scan_on_push = true' 'local.github_destination_oidc_subject_prefix}:environment:validator-client-ecr-mirror' 'ecr:BatchGetImage' 'ecr:DescribeImages' 'ecr:PutImage'; do
  grep -Fq "$required" "$terraform_file" || { printf 'missing mirror contract: %s\n' "$required" >&2; exit 1; }
done
grep -Fq 'offchainlabs/prysm-validator@sha256:' <(workflow_job_source "$workflow" validator-client)
grep -Fq 'docker buildx imagetools create' <(workflow_job_source "$workflow" validator-client)
grep -Fq 'approved-client-images.json' <(workflow_job_source "$workflow" validator-client)
grep -Fq '.mirror_eligible == true and .release_channel == "upstream-mirror" and .provenance_status == "upstream-release-mirror"' <(workflow_job_source "$workflow" validator-client)
grep -Fq '::add-mask::' <(workflow_job_source "$workflow" validator-client)
grep -Fq 'persist-credentials: false' <(workflow_job_source "$workflow" validator-client)
grep -Fq "needs: [preflight]" <(workflow_job_source "$workflow" validator-client)
grep -Fq "inputs.target == 'validator-client'" <(workflow_job_source "$workflow" validator-client)
grep -Fq "github.ref == 'refs/heads/main'" <(workflow_job_source "$workflow" validator-client)
# This verifies literal workflow shell source.
# shellcheck disable=SC2016
grep -Fq 'test "$digest" = "${SOURCE_IMAGE#*@}"' <(workflow_job_source "$workflow" validator-client)
jq -e '
  .schema_version == 2 and (.images | length == 3) and
  ([.images[] | select(.release_channel == "upstream-mirror" and .mirror_eligible == true and .provenance_status == "upstream-release-mirror")] | length == 1) and
  ([.images[] | select(
    .release_channel == "manual-native-mtls" and
    .mirror_eligible == false and
    .provenance_status == "manual-reviewed-live-build" and
    .stage_approved == true and .activation_approved == true and
    (.approval_basis | type == "object") and
    (.approval_basis.source_commit | type == "string" and test("^[a-f0-9]{40}$")) and
    .approval_basis.source_lock == ".ci/prysm-mtls/source.lock.json" and
    (.approval_basis.mtls_patch_sha256 | type == "string" and test("^[a-f0-9]{64}$")) and
    (.approval_basis.security_patch_sha256 | type == "string" and test("^[a-f0-9]{64}$"))
  )] | length == 1) and
  ([.images[] | select(
    .private_image == "123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/node-operator-example-baseline-validator-prysm@sha256:2789e2433b907019958b6d558c6e19b27dc9af7fe10e38684a1a64fccb48263d" and
    .mirror_eligible == false and .stage_approved == true and .activation_approved == true and
    .activation_expires_at == "2026-09-21T00:00:00Z" and
    (.approval_basis.direct_activation_decision == "release/direct-hoodi-activation-approval.json") and
    (.approval_basis.publication_authorization == "release/prysm-publication-authorization.json") and
    .approval_basis.publication_authorization_activation_approved == false and
    .approval_basis.task_scoped_activation_approval == true and
    .approval_basis.fence_image == "123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/node-operator-example-baseline-validator-fence@sha256:951312f79c693eae0a9b3e54961701944e0e1339d997f0f3315a25112dcb7fb8"
  )] | length == 1) and
  all(.images[]; (.private_image == "123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/node-operator-example-baseline-validator-prysm@sha256:2789e2433b907019958b6d558c6e19b27dc9af7fe10e38684a1a64fccb48263d" or (.private_image | test("^123456789012\\.dkr\\.ecr\\.ap-northeast-2\\.amazonaws\\.com/node-operator-baseline-validator-prysm@sha256:[a-f0-9]{64}$"))))
' "$allowlist" >/dev/null
# The task-scoped approval must survive release packaging, not point to an
# ignored local plan that a downloaded installer cannot inspect.
jq -e --slurpfile approval "$root/release/direct-hoodi-activation-approval.json" '
  [.images[] | select((.approval_basis | type) == "object") | select(.approval_basis.task_scoped_activation_approval == true)] as $entries |
  ($entries | length == 1) and
  $entries[0].private_image == $approval[0].client_image and
  $entries[0].approval_basis.fence_image == $approval[0].fence_image and
  $entries[0].activation_expires_at == $approval[0].activation_expires_at and
  $approval[0].new_activation_approval == true
' "$allowlist" >/dev/null
if jq -e '[.images[] | select(.release_channel == "manual-native-mtls" and .mirror_eligible == true)] | length > 0' "$allowlist" >/dev/null; then
  printf '%s\n' 'manual native record is mirror-eligible' >&2; exit 1
fi
if grep -Eq 'ecr:(DeleteRepository|DeleteImage|SetRepositoryPolicy|\*)' "$terraform_file"; then printf '%s\n' 'validator mirror grants destructive ECR permission' >&2; exit 1; fi
printf '%s\n' 'PASS: Prysm validator mirror is private, immutable, OIDC-bound, repository-scoped, and non-destructive.'
