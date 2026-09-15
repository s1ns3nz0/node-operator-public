#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$script_dir/../.." && pwd -P)"
fixture="$root/scripts/ci/fixtures/terraform-empty-state"
workspace="$(mktemp -d)"
trap 'rm -rf "$workspace"' EXIT
fail() { printf 'FAIL bootstrap-state CLI: %s\n' "$*" >&2; exit 1; }

command -v terraform >/dev/null || fail 'terraform is unavailable'
command -v jq >/dev/null || fail 'jq is unavailable'
cp -R "$fixture" "$workspace/module"
terraform -chdir="$workspace/module" init -backend=false -input=false >/dev/null
terraform -chdir="$workspace/module" show -json > "$workspace/state.json"
jq -e 'type == "object" and (.format_version | type == "string") and (.values.root_module? == null)' "$workspace/state.json" >/dev/null || fail 'fresh Terraform show JSON did not have the expected empty-state shape'

# This is the exact extractor used by the release wrapper. Empty root state is
# valid and must yield no reconciliation identities rather than an error.
entries="$(jq -r '
  def resources: .resources[]?, (.child_modules[]? | resources);
  if .values.root_module? == null then empty
  else .values.root_module | resources | [.address, .values.id] | @tsv end
' "$workspace/state.json")"
[ -z "$entries" ] || fail 'fresh Terraform state unexpectedly produced resource identities'

printf 'PASS bootstrap-state CLI accepts Terraform fresh-state JSON.\n'
