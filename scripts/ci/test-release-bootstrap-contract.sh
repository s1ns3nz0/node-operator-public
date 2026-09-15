#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$script_dir/lib/common.sh"
root="$(repo_root)"
contract="$root/release/hoodi-release-contract.json"
template="$root/release/hoodi.ap-northeast-2.tfvars.example"
entrypoint="$root/scripts/release/node-operator-release.sh"
ops_entrypoint="$root/scripts/release/node-operator-ops-access.sh"

for file in "$contract" "$template" "$entrypoint" "$ops_entrypoint" "$root/docs/operations/release-bootstrap.md" "$root/docs/operations/terraform-ssm-state-migration.md"; do
  [ -f "$file" ] || { printf 'missing release foundation file: %s\n' "$file" >&2; exit 1; }
done

jq -e '
  .schema_version == "v1" and .network == "hoodi" and .region == "ap-northeast-2" and
  .client_chart == {name:"node-operator-client",version_pattern:"^0\\.1\\.[0-9]+$",immutable_digest_required:true} and
  (.bootstrap.forbidden_inputs | index("validator private key or keystore"))
' "$contract" >/dev/null

grep -Fx 'enable_temporary_ssm_ops_host = false' "$template" >/dev/null
grep -Fx 'enable_argocd_bootstrap_cluster_admin = false' "$template" >/dev/null
grep -Fx 'enable_vault_bootstrap_cluster_admin  = false' "$template" >/dev/null
grep -F 'SSM operations access belongs to the isolated ops-access command' "$entrypoint" >/dev/null
grep -F 'temporary cluster-admin bootstrap requires its separately approved phase' "$entrypoint" >/dev/null
grep -F 'zero apply --bundle-root DIRECTORY' "$entrypoint" >/dev/null
grep -F 'zero apply derives foundation network inputs' "$entrypoint" >/dev/null
grep -F 'plan|apply|destroy' "$ops_entrypoint" >/dev/null
grep -F -- '--backend-config BACKEND_HCL' "$ops_entrypoint" >/dev/null
grep -F -- '--allow-create' "$ops_entrypoint" >/dev/null
grep -F 'backend "s3" {}' "$root/infra/ops-access/main.tf" >/dev/null
[ -f "$root/infra/ops-access/backend.hcl.example" ] || { printf 'ops-access backend example is missing\n' >&2; exit 1; }
[ -f "$root/infra/ops-access/terraform.tfvars.example" ] || { printf 'ops-access tfvars example is missing\n' >&2; exit 1; }
grep -F 'existing_ssm_endpoint_security_group_id' "$root/infra/ops-access/main.tf" "$root/infra/ops-access/variables.tf" >/dev/null
grep -F 'local.create_ssm_endpoints || var.manage_existing_endpoint_ingress_rule ? 1 : 0' "$root/infra/ops-access/main.tf" >/dev/null
grep -F 'variable "manage_existing_endpoint_ingress_rule"' "$root/infra/ops-access/variables.tf" >/dev/null
for rule in cluster endpoints; do
  grep -F "from = aws_vpc_security_group_ingress_rule.$rule" "$root/infra/ops-access/main.tf" >/dev/null
  grep -F "to   = aws_vpc_security_group_ingress_rule.${rule}[0]" "$root/infra/ops-access/main.tf" >/dev/null
done
if grep -n -E 'scheduler|vault' "$ops_entrypoint"; then
  printf 'ops-access command crosses its intended boundary\n' >&2
  exit 1
fi

if grep -n -E -i 'vault(_token)?[[:space:]]*=[[:space:]]*[^"[:space:]]+|private[_-]?key[[:space:]]*=[[:space:]]*[^"[:space:]]+|seed_phrase[[:space:]]*=[[:space:]]*[^"[:space:]]+|withdrawal_credential[[:space:]]*=[[:space:]]*[^"[:space:]]+' "$template" "$entrypoint"; then
  printf 'release foundation contains a prohibited credential literal\n' >&2
  exit 1
fi

printf 'PASS release bootstrap contract preserves the non-secret and separated-operations boundary.\n'
