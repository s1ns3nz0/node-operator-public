#!/usr/bin/env bash
# Check objective: Verify the GitOps mirror's exact OIDC subject, approved digest input and restricted ECR publication contract.
# shellcheck disable=SC2016 # Literal Terraform and workflow fragments intentionally contain $ expressions.
set -euo pipefail
# shellcheck source=scripts/ci/lib/workflow-contract.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/workflow-contract.sh"

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$script_dir/lib/common.sh"
root="$(repo_root)"
fail() { printf 'FAIL GitOps OCI mirror contract: %s\n' "$*" >&2; exit 1; }

terraform_file="$root/infra/terraform/private-gitops.tf"
workflow="$root/.github/workflows/private-ecr-mirror.yml"
allowlist="$root/.ci/gitops/approved-oci-artifacts.json"
dockerfile="$root/.ci/toolchains/gitops-oci-mirror.Dockerfile"
for file in "$terraform_file" "$workflow" "$allowlist" "$dockerfile"; do
  test -f "$file" || fail "missing required file: $file"
done


jq -e '.version == 1 and (.artifacts | type == "array") and all(.artifacts[]; (.source | type == "string") and (.destination | type == "string") and (.ecrTag | type == "string"))' "$allowlist" >/dev/null || fail 'approved artifact allowlist has an invalid schema'
grep -Fqx 'ENTRYPOINT ["skopeo"]' "$dockerfile" || fail 'mirror toolchain must invoke skopeo'
grep -Fq 'apt-get install -y --no-install-recommends ca-certificates skopeo' "$dockerfile" || fail 'mirror toolchain must include skopeo'

for required in \
  'variable "enable_private_gitops_foundation"' \
  'default     = true' \
  'resource "aws_ecr_repository" "private_gitops"' \
  'image_tag_mutability = "IMMUTABLE"' \
  'scan_on_push = true' \
  'prevent_destroy = true' \
  'resource "aws_iam_role" "github_gitops_oci_mirror"' \
  'vault' \
  'cert_manager' \
  'nodes        = "${local.name_prefix}-gitops-nodes"' \
  'vault_chart = "${local.name_prefix}-gitops-vault/vault"' \
  'cert_manager_chart = "${local.name_prefix}-gitops-cert-manager/cert-manager"' \
  'token.actions.githubusercontent.com:repository' \
  '${local.github_destination_oidc_subject_prefix}:environment:gitops-oci-mirror' \
  '"ecr:BatchGetImage"' \
  '"ecr:DescribeImages"' \
  '"ecr:PutImage"' \
  'github_gitops_oci_mirror_role_arn'; do
  grep -Fq "$required" "$terraform_file" || fail "Terraform contract omits: $required"
done

kyverno_layer_read_policy="$(sed -n '/resource "aws_iam_role_policy" "github_kyverno_cli_layer_read" {/,/^}/p' "$terraform_file")"
test -n "$kyverno_layer_read_policy" || fail 'missing Kyverno CLI layer-read inline policy'
grep -Fqx '  count = var.enable_private_gitops_foundation ? 1 : 0' <<<"$kyverno_layer_read_policy" || fail 'Kyverno CLI layer-read policy is not foundation-gated'
grep -Fqx '  name  = "${local.name_prefix}-kyverno-cli-layer-read"' <<<"$kyverno_layer_read_policy" || fail 'Kyverno CLI layer-read policy name is not exact'
grep -Fqx '  role  = aws_iam_role.github_gitops_oci_mirror[0].id' <<<"$kyverno_layer_read_policy" || fail 'Kyverno CLI layer-read policy is not attached to the GitOps mirror role'
grep -Fqx '      Action   = ["ecr:GetDownloadUrlForLayer"]' <<<"$kyverno_layer_read_policy" || fail 'Kyverno CLI layer-read policy action is not exact'
grep -Fqx '      Resource = [aws_ecr_repository.private_gitops["nodes"].arn]' <<<"$kyverno_layer_read_policy" || fail 'Kyverno CLI layer-read policy resource is not exact'

if grep -Eq 'ecr:(DeleteRepository|DeleteImage|SetRepositoryPolicy|PutLifecyclePolicy|\*)' "$terraform_file"; then
  fail 'mirror role exceeds the required ECR read-and-push permission boundary'
fi

for required in \
  'environment: gitops-oci-mirror' \
  'id-token: write' \
  'source must be an OCI reference pinned to a 64-character sha256 digest' \
  'reviewed GitOps artifact allowlist' \
  '.ci/gitops/approved-oci-artifacts.json' \
  'ECR_TAG=$ecr_tag' \
  'aws sts assume-role-with-web-identity' \
  '::add-mask::' \
  'GITOPS_OCI_MIRROR_TOOL_IMAGE' \
  'copy --all "docker://$SOURCE" "docker://$destination_ref"' \
  'aws ecr describe-images' \
  'test "$destination_digest" = "$source_digest"' \
  'GITHUB_STEP_SUMMARY'; do
  grep -Fq "$required" <(workflow_job_source "$workflow" gitops) || fail "workflow contract omits: $required"
done

grep -Fq 'options: [none, argocd, charts, nodes, vault, cert-manager]' "$workflow" || fail 'workflow omits the approved GitOps destination choices'
grep -Fq "needs: [preflight]" <(workflow_job_source "$workflow" gitops) || fail 'GitOps job does not require input preflight'
grep -Fq "inputs.target == 'gitops'" <(workflow_job_source "$workflow" gitops) || fail 'GitOps job is not target-selected'
grep -Fq "github.ref == 'refs/heads/main'" <(workflow_job_source "$workflow" gitops) || fail 'GitOps job is not main-only'
if grep -Fq 'docker buildx imagetools create' <(workflow_job_source "$workflow" gitops); then
  fail 'workflow uses manifest-only imagetools instead of a blob-copying OCI client'
fi

grep -Fq 'actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1' "$workflow" || fail 'workflow must read the versioned artifact approval allowlist'

printf 'PASS private GitOps OCI mirror accepts only approved digests and records the ECR-verified digest.\n'
