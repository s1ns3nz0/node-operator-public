#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "$root/scripts/ci/lib/workflow-contract.sh"
allowlist="$root/.ci/gitops/approved-oci-artifacts.json"
workflow="$root/.github/workflows/private-ecr-mirror.yml"
terraform_file="$root/infra/terraform/private-gitops.tf"

jq -e '
  .version == 1 and
  (.helm_archives | type == "array") and
  ([.helm_archives[] | select(.name == "cert-manager")] | length == 1) and
  (.helm_archives[] | select(.name == "cert-manager") |
    .version == "v1.21.1" and
    .source == "https://charts.jetstack.io/charts/cert-manager-v1.21.1.tgz" and
    .sha256 == "c27101f3f3e2349fb4a9e704316105bf7b52ad73b8c8257d3498ef7f2f6a4adc" and
    .ecrManifestDigest == "sha256:62c4745561eccfd723678c6547500750ebef5a880d81ff670d33124ab335f877" and
    .destination == "cert-manager" and .ecrTag == "v1.21.1")
' "$allowlist" >/dev/null

for required in \
  '.helm_archives[] | select(.name == "cert-manager")' \
  'chart_source' \
  'chart_sha256' \
  'chart_manifest_digest' \
  "test \"\$chart_destination\" = cert-manager" \
  'cert-manager-keyring-2021-09-20-1020CF3C033D4F35BAE1C19E1226061C665DF13E.gpg' \
  'helm verify --keyring' \
  'sha256sum --check --status' \
  'aws ecr describe-images' \
  'existing_manifest_digest' \
  "test \"\$ecr_manifest_digest\" = \"\$chart_manifest_digest\"" \
  "helm push \"\$RUNNER_TEMP/cert-manager-\$chart_version.tgz\""; do
  grep -Fq "$required" <(workflow_job_source "$workflow" cert-manager-chart)
done

grep -Fq "needs: [preflight]" <(workflow_job_source "$workflow" cert-manager-chart)
grep -Fq "inputs.target == 'cert-manager-chart'" <(workflow_job_source "$workflow" cert-manager-chart)
grep -Fq "github.ref == 'refs/heads/main'" <(workflow_job_source "$workflow" cert-manager-chart)

grep -Fq "cert_manager_chart = \"\${local.name_prefix}-gitops-cert-manager/cert-manager\"" "$terraform_file"

if grep -Fq 'helm pull cert-manager --repo' <(workflow_job_source "$workflow" cert-manager-chart); then
  printf 'cert-manager chart mirror must not bypass the approved archive record.\n' >&2
  exit 1
fi

printf 'PASS cert-manager chart mirror is checksum- and signature-bound to the approved archive record.\n'
