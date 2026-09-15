#!/usr/bin/env bash
# Check objective: Keep PR evidence Terraform validation bound to the deployable root module.
# shellcheck disable=SC2016
set -euo pipefail
# shellcheck source=scripts/ci/lib/workflow-contract.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/workflow-contract.sh"

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
collector="$script_dir/collect-pr-evidence.sh"

# The workflow gate must validate exactly the same deployable Terraform root
# as CI Terraform, never individual implementation fragments.
grep -Fq 'local root_module="$source_directory/infra/terraform"' "$collector"
grep -Fq '"$script_dir/validate-terraform-offline.sh" "$root_module" "$validation_directory"' "$collector"
grep -Fq '{"status":"passed","modules":[{"module":"infra/terraform","status":"passed"}]}' "$collector"
grep -Fq '{"status":"failed","modules":[{"module":"infra/terraform","status":"failed"}]}' "$collector"

# The trusted collector stages only the root module. Keep its public GitOps
# inputs local and identical to their operator-facing canonical examples.
for example in argocd-private-values.example.yaml cert-manager-values.example.yaml vault-tls-internal-ca.example.yaml; do
  cmp -s "$script_dir/../../infra/terraform/$example" "$script_dir/../../docs/gitops/$example"
done

printf 'PASS: evidence-gate Terraform validation uses the CI root-module contract.\n'
