#!/usr/bin/env bash
# Check objective: Validate standalone module formatting and configuration with a read-only provider lock and no remote backend.
set -euo pipefail

if [ "$#" -ne 2 ]; then
  printf 'usage: %s MODULE_DIRECTORY OUTPUT_DIRECTORY\n' "$0" >&2
  exit 64
fi
module_directory="$1"
output_directory="$2"
test -f "$module_directory/.terraform.lock.hcl" || { printf 'missing provider lockfile: %s\n' "$module_directory" >&2; exit 1; }
mkdir -p "$output_directory"
work_directory="$(mktemp -d "$output_directory/terraform-module.XXXXXX")"
trap 'rm -rf "$work_directory"' EXIT
cp -R "$module_directory/." "$work_directory/"
rm -f "$work_directory/backend.tf"

terraform -chdir="$work_directory" fmt -check -recursive
terraform -chdir="$work_directory" init -backend=false -get=false -lockfile=readonly -input=false
terraform -chdir="$work_directory" validate

if [ "$(basename "$module_directory")" = "foundation-network" ]; then
  "$(dirname "$0")/test-foundation-network-existing-mode.sh" "$work_directory"
fi
