#!/usr/bin/env bash
# Check objective: Validate the zero-resource release contract.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
entrypoint="$root/scripts/release/node-operator-release.sh"
baseline="$root/infra/terraform"
foundation="$root/infra/foundation-network"

for file in \
  "$root/release/zero-resource-bootstrap-state.tfvars.example" \
  "$root/release/zero-resource-foundation-network.tfvars.example" \
  "$root/release/zero-resource-baseline.tfvars.example"; do
  [ -f "$file" ] || { printf 'missing zero-resource example: %s\n' "$file" >&2; exit 1; }
done

rg -F 'network_source:"foundation"' "$entrypoint" >/dev/null
rg -F 'init -input=false -migrate-state' "$entrypoint" >/dev/null
rg -F 'node-operator/foundation-network/terraform.tfstate' "$entrypoint" >/dev/null
rg -F 'node-operator/baseline/terraform.tfstate' "$entrypoint" >/dev/null
# Publisher provisioning is explicit and cannot accidentally affect ordinary
# verification or infrastructure apply invocations.
for operation in 'verify' 'zero apply' 'bootstrap plan'; do
  read -r -a operation_args <<< "$operation"
  if rejection="$(bash "$entrypoint" "${operation_args[@]}" --include-publishers 2>&1)"; then
    printf 'publisher opt-in accepted outside the prerequisite phase\n' >&2
    exit 1
  fi
  [[ "$rejection" == *'--include-publishers requires zero prepare-artifacts'* ]] || {
    printf 'publisher opt-in was rejected for an unrelated reason\n' >&2
    exit 1
  }
done
rg -F 'include_publishers=false' "$entrypoint" >/dev/null
rg -F -- '-target=aws_iam_role_policy.github_validator_signer_identity_probe_mirror' "$entrypoint" >/dev/null
rg -F '"${publisher_validation_args[@]}"' "$entrypoint" >/dev/null
rg -F 'foundation-network.auto.tfvars.json' "$entrypoint" >/dev/null
rg -F '(.vpc_id | test("^vpc-[0-9a-f]+$"))' "$entrypoint" >/dev/null
rg -F 'vpc_id:.vpc_id' "$entrypoint" >/dev/null
if rg -F '.vpc_id.value' "$entrypoint" >/dev/null; then
  printf 'foundation output is already a direct Terraform output value and must not be dereferenced again\n' >&2
  exit 1
fi
if rg -F '$bootstrap[0].bucket.value' "$entrypoint" >/dev/null; then
  printf 'bootstrap output is already a direct Terraform output value and must not be dereferenced again\n' >&2
  exit 1
fi
rg -F 'gitops-publisher-handoff.json' "$entrypoint" >/dev/null
rg -F 'ops-access-handoff.json' "$entrypoint" >/dev/null
rg -F -- '--inputs cannot be combined with individual phase configs' "$entrypoint" >/dev/null
rg -F 'zero apply requires --inputs or all three phase configs' "$entrypoint" >/dev/null
rg -F 'nonempty work directory lacks a zero-resource checkpoint binding' "$entrypoint" >/dev/null
rg -F 'incomplete bootstrap checkpoint has an unsafe module path' "$entrypoint" >/dev/null
if rg -F 'incomplete foundation checkpoint; use a new work directory' "$entrypoint" >/dev/null; then
  printf 'foundation retry still rejects its existing checkpoint\n' >&2
  exit 1
fi
rg -F 'incomplete foundation checkpoint has an unsafe module path' "$entrypoint" >/dev/null
rg -F 'zero-resource inputs differ from the existing checkpoint' "$entrypoint" >/dev/null
rg -F 'ordinary resume plan contains a destructive action' "$entrypoint" >/dev/null
rg -F 'cp -R "$bundle_root/source/$relative/." "$destination"' "$entrypoint" >/dev/null
rg -F 'bootstrap-state.tfvars.json' "$entrypoint" >/dev/null
rg -F 'github_gitops_client_ecr_publisher_role_arn' "$entrypoint" >/dev/null
rg -F 'backend "s3" {}' "$baseline/backend.tf" >/dev/null
rg -F 'vpc_cidr' "$foundation/outputs.tf" >/dev/null
rg -F 'variable "network_source"' "$baseline/variables.tf" >/dev/null
rg -F 'variable "foundation_network"' "$baseline/variables.tf" >/dev/null
rg -F 'prevent_destroy = true' "$baseline/network.tf" >/dev/null
rg -F 'local.system_subnet_ids' "$baseline/eks.tf" "$baseline/endpoints.tf" >/dev/null
rg -F 'local.hoodi_subnet_ids' "$baseline/eks.tf" >/dev/null
if rg -n 'node-operator-tfstate-123456789012-apne2|23528ef1-681c-41c3-a565-d19d3ec98c37' "$baseline/backend.tf"; then
  printf 'baseline backend remains bound to historical state\n' >&2
  exit 1
fi
printf 'PASS zero-resource release contract preserves state and network ownership boundaries.\n'
