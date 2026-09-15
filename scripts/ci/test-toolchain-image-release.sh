#!/usr/bin/env bash
# Check objective: Enforce pinned toolchain-image dependencies and restricted publication contracts.
# shellcheck disable=SC2016
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$script_dir/lib/workflow-contract.sh"
root="$(cd "$script_dir/../.." && pwd)"
temporary_directory="$(mktemp -d)"
trap 'rm -rf "$temporary_directory"' EXIT

for dockerfile in "$root/.ci/toolchains/terraform-validation.Dockerfile" "$root/.ci/toolchains/release-build.Dockerfile" "$root/.ci/toolchains/argocd-bootstrap.Dockerfile" "$root/.ci/toolchains/vault-bootstrap.Dockerfile"; do
  grep -Eqx 'FROM ubuntu@sha256:[0-9a-f]{64}' "$dockerfile"
  if grep -qE 'curl[^\n]*\|[[:space:]]*(tar|unzip|install)' "$dockerfile"; then
    printf 'toolchain image must verify downloads before extraction or installation\n' >&2
    exit 1
  fi
done
grep -Fq 'ripgrep' "$root/.ci/toolchains/release-build.Dockerfile"
grep -Fq 'python3' "$root/.ci/toolchains/release-build.Dockerfile"
workflow="$root/.github/workflows/image-publish.yml"
if ! ruby -ryaml -e '
  jobs = YAML.load_file(ARGV[0]).fetch("jobs")
  build = jobs.fetch("toolchain-build")
  publish = jobs.fetch("toolchain-publish")
  abort unless build.fetch("needs") == ["select"] && publish.fetch("needs") == ["select", "toolchain-build"]
  abort unless build.dig("permissions", "packages") == "read" && publish.dig("permissions", "packages") == "write"
  abort unless build.fetch("if") == "needs.select.outputs.toolchains == '\''true'\''"
  abort unless publish.fetch("if") == "github.ref == '\''refs/heads/main'\'' && needs.select.outputs.toolchains == '\''true'\'' && needs.toolchain-build.result == '\''success'\''"
  abort unless build.dig("strategy", "matrix") == "${{ fromJSON(needs.select.outputs.toolchain_matrix) }}"
  abort unless publish.dig("strategy", "matrix") == "${{ fromJSON(needs.select.outputs.toolchain_matrix) }}"
' "$workflow"; then
  printf 'toolchain jobs must retain their selected matrix, read-build and main-only successful publication boundary\n' >&2
  exit 1
fi
grep -Fq 'test-build-release-bundle.sh' <(workflow_source "$workflow")
grep -Fq 'DOCKERFILE: ${{ matrix.dockerfile }}' "$workflow"
grep -Fq 'IMAGE_NAME: ${{ matrix.image }}' "$workflow"
grep -Fq '"$DOCKERFILE"' <(workflow_source "$workflow")
grep -Fq '"$IMAGE_NAME" = release-build' <(workflow_source "$workflow")

for required in \
  'ARG CA_CERTIFICATES_VERSION=' \
  'ARG CURL_VERSION=' \
  'ARG TAR_VERSION=' \
  'ARG UNZIP_VERSION=' \
  'ca-certificates=${CA_CERTIFICATES_VERSION}' \
  'curl=${CURL_VERSION}' \
  'tar=${TAR_VERSION}' \
  'unzip=${UNZIP_VERSION}' \
  'jq=${JQ_VERSION}'; do
  grep -Fq "$required" "$root/.ci/toolchains/vault-bootstrap.Dockerfile"
done

expected_input_sha="$({ sha256sum "$root/.ci/toolchains/terraform-validation.Dockerfile"; } | awk '{print $1}' | sha256sum | awk '{print $1}')"
mkdir -p "$temporary_directory/bin"
printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' \
  'case "$1" in' \
  '  pull) exit 0 ;;' \
  '  image) [ "$2" = "inspect" ] && printf "%s\\n" "$EXPECTED_INPUT_SHA" ;;' \
  '  *) printf "unexpected docker command: %s\\n" "$*" >&2; exit 1 ;;' \
  'esac' > "$temporary_directory/bin/docker"
chmod +x "$temporary_directory/bin/docker"

output="$(cd "$root" && EXPECTED_INPUT_SHA="$expected_input_sha" GITHUB_REPOSITORY=s1ns3nz0/node-operator GITHUB_SHA=fixture PATH="$temporary_directory/bin:$PATH" .ci/toolchains/release-toolchain-image.sh terraform-validation .ci/toolchains/terraform-validation.Dockerfile)"
test "$output" = 'terraform-validation image inputs are unchanged; skipping build and push'

expected_bootstrap_input_sha="$({ sha256sum "$root/.ci/toolchains/argocd-bootstrap.Dockerfile" "$root/docs/gitops/argocd-private-values.example.yaml" "$root/docs/gitops/cert-manager-values.example.yaml" "$root/docs/gitops/vault-tls-internal-ca.example.yaml"; } | awk '{print $1}' | sha256sum | awk '{print $1}')"
output="$(cd "$root" && EXPECTED_INPUT_SHA="$expected_bootstrap_input_sha" GITHUB_REPOSITORY=s1ns3nz0/node-operator GITHUB_SHA=fixture PATH="$temporary_directory/bin:$PATH" .ci/toolchains/release-toolchain-image.sh argocd-bootstrap .ci/toolchains/argocd-bootstrap.Dockerfile docs/gitops/argocd-private-values.example.yaml docs/gitops/cert-manager-values.example.yaml docs/gitops/vault-tls-internal-ca.example.yaml)"
test "$output" = 'argocd-bootstrap image inputs are unchanged; skipping build and push'

expected_vault_bootstrap_input_sha="$({ sha256sum "$root/.ci/toolchains/vault-bootstrap.Dockerfile" "$root/docs/gitops/vault-values.example.yaml" "$root/scripts/ops/verify-hoodi-vault-readiness.sh" "$root/docs/gitops/vault-gp3-encrypted-storageclass.yaml" "$root/scripts/ops/ensure-vault-encrypted-storageclass.sh"; } | awk '{print $1}' | sha256sum | awk '{print $1}')"
output="$(cd "$root" && EXPECTED_INPUT_SHA="$expected_vault_bootstrap_input_sha" GITHUB_REPOSITORY=s1ns3nz0/node-operator GITHUB_SHA=fixture PATH="$temporary_directory/bin:$PATH" .ci/toolchains/release-toolchain-image.sh vault-bootstrap .ci/toolchains/vault-bootstrap.Dockerfile docs/gitops/vault-values.example.yaml scripts/ops/verify-hoodi-vault-readiness.sh docs/gitops/vault-gp3-encrypted-storageclass.yaml scripts/ops/ensure-vault-encrypted-storageclass.sh)"
test "$output" = 'vault-bootstrap image inputs are unchanged; skipping build and push'
