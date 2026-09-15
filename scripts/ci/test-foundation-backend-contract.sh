#!/usr/bin/env bash
# Check objective: Enforce the reviewed remote-state backend and foundation Terraform boundary.
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
module="$root/infra/foundation-network"
example="$module/backend.hcl.example"
guide="$root/docs/operations/foundation-network-state-migration.md"
grep -Fq 'backend "s3" {}' "$module/versions.tf"
for setting in \
  'key            = "node-operator/foundation-network/terraform.tfstate"' \
  'encrypt        = true' \
  'kms_key_id     = "arn:aws:kms:ap-northeast-2:123456789012:key/00000000-0000-0000-0000-000000000000"'; do
  grep -Fq "$setting" "$example"
done
if grep -Eqi '(secret|access)_key[[:space:]]*=' "$example"; then printf 'backend example contains credentials\n' >&2; exit 1; fi
grep -Fq 'Never use force-copy.' "$guide"
grep -Fq 'It must have no create, destroy,' "$guide"
grep -Fq 'replacement, or routing change.' "$guide"
scratch="$(mktemp -d)"; trap 'rm -rf "$scratch"' EXIT
# A production S3 declaration without configuration must fail init. The local
# fixture then replaces that exact extracted declaration before real init/plan.
production="$scratch/production"; mkdir "$production"
{ printf 'terraform {\n'; sed -n '/backend "s3" {}/p' "$module/versions.tf"; printf '}\n'; } > "$production/backend.tf"
if terraform -chdir="$production" init -input=false >"$scratch/production-init.out" 2>&1; then
  printf 'unconfigured production S3 backend unexpectedly initialized\n' >&2; exit 1
fi
grep -Fq '"bucket": required field is not set' "$scratch/production-init.out"
fixture="$scratch/fixture"; mkdir "$fixture"
{ printf 'terraform {\n'; sed -n '/backend "s3" {}/p' "$module/versions.tf" | sed 's/backend "s3" {}/backend "local" { path = "state.tfstate" }/'; printf '}\n'; } > "$fixture/local_backend_override.tf"
cat > "$fixture/main.tf" <<'EOF'
resource "terraform_data" "offline_backend_fixture" { input = "local-backend" }
EOF
terraform -chdir="$fixture" init -input=false >/dev/null
terraform -chdir="$fixture" plan -refresh=false -input=false -out="$scratch/fresh.tfplan" >/dev/null
test -f "$scratch/fresh.tfplan"
printf 'PASS foundation S3 contract and local-backend init/plan fixture.\n'
