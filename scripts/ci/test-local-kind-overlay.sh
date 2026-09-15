#!/usr/bin/env bash
set -euo pipefail

# Render the local-only composition without contacting a cluster. The checks
# assert the safety boundary (zero replicas) and that the original pod templates
# remain present for admission evaluation.
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$script_dir/lib/common.sh"
root="$(repo_root)"
require_command kubectl

temporary_directory="$(mktemp -d)"
trap 'rm -rf "$temporary_directory"' EXIT
rendered="$temporary_directory/local-kind.yaml"

kubectl kustomize "$root/deploy/local-kind" > "$rendered"

assert_scaled_down() {
  local expected_name="$1"
  awk -v expected_name="$expected_name" '
    /^kind: StatefulSet$/ { in_statefulset = 1; name = ""; replicas = ""; next }
    in_statefulset && /^---$/ {
      if (name == expected_name && replicas == "0") found = 1
      in_statefulset = 0
      next
    }
    in_statefulset && /^  name: / { name = $2 }
    in_statefulset && /^  replicas: / { replicas = $2 }
    END {
      if (in_statefulset && name == expected_name && replicas == "0") found = 1
      exit(found ? 0 : 1)
    }
  ' "$rendered" || {
    printf 'StatefulSet %s was not rendered with replicas: 0\n' "$expected_name" >&2
    exit 1
  }
}

assert_scaled_down prysm-beacon
assert_scaled_down nethermind-execution

# Pinned images demonstrate that the pod templates were retained, not replaced
# by a Kind-specific placeholder workload.
rg -q 'offchainlabs/prysm-beacon-chain@sha256:49f8454eb2a756402eb781025e370eef7d613668c2914bad4cca9c1aa11fafa4' "$rendered"
rg -q 'nethermind/nethermind@sha256:ec5f6c8158dbf82d4ddbd5500f895c930f52aa3b4c998148d9e1b452793d828e' "$rendered"

printf 'PASS local Kind overlay renders both blockchain StatefulSets at zero replicas.\n'
