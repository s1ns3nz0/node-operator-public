#!/usr/bin/env bash
# shellcheck disable=SC2016 # Literal workflow and Terraform fragments intentionally contain $ expressions.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "$root/scripts/ci/lib/workflow-contract.sh"
allowlist="$root/.ci/gitops/approved-oci-artifacts.json"
workflow="$root/.github/workflows/private-ecr-mirror.yml"
terraform_file="$root/infra/terraform/private-gitops.tf"

jq -e '
  .version == 1 and
  (.helm_archives | type == "array") and
  ([.helm_archives[] | select(.name == "vault")] | length == 1) and
  (.helm_archives[] | select(.name == "vault") |
    .version == "0.31.0" and
    .source == "https://helm.releases.hashicorp.com/vault-0.31.0.tgz" and
    (.sha256 | test("^[a-f0-9]{64}$")) and
    (.ecrManifestDigest | test("^sha256:[a-f0-9]{64}$")) and
    .destination == "vault" and .ecrTag == "0.31.0")
' "$allowlist" >/dev/null

for required in \
  '.helm_archives[] | select(.name == "vault")' \
  'chart_source' \
  'chart_sha256' \
  'chart_manifest_digest' \
  'chart_destination' \
  'test "$chart_destination" = vault' \
  'sha256sum --check --status' \
  'aws ecr describe-images' \
  'test "$ecr_manifest_digest" = "$chart_manifest_digest"' \
  'helm push "$RUNNER_TEMP/vault-$chart_version.tgz"'; do
  grep -Fq "$required" <(workflow_job_source "$workflow" vault-chart)
done

grep -Fq "needs: [preflight]" <(workflow_job_source "$workflow" vault-chart)
grep -Fq "inputs.target == 'vault-chart'" <(workflow_job_source "$workflow" vault-chart)
grep -Fq "github.ref == 'refs/heads/main'" <(workflow_job_source "$workflow" vault-chart)

grep -Fq 'vault_chart = "${local.name_prefix}-gitops-vault/vault"' "$terraform_file"

if grep -Fq "helm pull vault --repo" <(workflow_job_source "$workflow" vault-chart); then
  printf 'Vault chart mirror must not bypass the approved archive record.\n' >&2
  exit 1
fi

printf 'PASS Vault chart mirror is bound to the approved archive record.\n'
