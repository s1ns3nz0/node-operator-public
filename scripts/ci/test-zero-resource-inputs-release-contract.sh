#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
entrypoint="$root/scripts/release/node-operator-release.sh"
scratch="$(mktemp -d /private/tmp/node-operator-zero-release-inputs.XXXXXX)"
bundle="$scratch/bundle"; mkdir -p "$bundle/source/release"

# The invalid metadata must fail before Terraform is required. A minimal valid
# bundle shape lets this test exercise the zero-input parser without AWS.
jq -n '{schema_version:"v1",entries:[]}' > "$bundle/bundle-manifest.json"
cp "$root/release/hoodi-release-contract.json" "$bundle/source/release/hoodi-release-contract.json"
inputs="$scratch/inputs"; mkdir "$inputs"
jq -n --arg p "$inputs" '{schema_version:1,aws_account_id:"123456789012",bootstrap_config:($p+"/other.json"),foundation_config:($p+"/foundation-network.tfvars.json"),baseline_config:($p+"/baseline.tfvars.json")}' > "$inputs/zero-resource-inputs.json"
if "$entrypoint" zero apply --bundle-root "$bundle" --inputs "$inputs/zero-resource-inputs.json" --work-dir "$scratch/work" >/dev/null 2>&1; then
  printf '%s\n' 'unbounded zero-resource metadata unexpectedly accepted' >&2
  exit 1
fi
printf '%s\n' 'PASS: zero-resource release accepts only a bounded generated input contract.'
