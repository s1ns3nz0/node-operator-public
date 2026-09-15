#!/usr/bin/env bash
# Check objective: Require Conftest to admit secure fixtures and reject insecure workload and Nethermind fixtures.
set -euo pipefail
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$script_dir/lib/common.sh"
root="$(repo_root)"
require_command conftest
conftest test --all-namespaces --policy "$root/policy/runtime" "$root/policy/tests/fixtures/workload-secure.yaml"
if conftest test --all-namespaces --policy "$root/policy/runtime" "$root/policy/tests/fixtures/workload-insecure.yaml"; then printf 'insecure workload fixture unexpectedly passed Conftest\n' >&2; exit 1; fi
conftest test --all-namespaces --policy "$root/policy/nethermind" "$root/policy/nethermind/fixtures/secure.yaml"
if conftest test --all-namespaces --policy "$root/policy/nethermind" "$root/policy/nethermind/fixtures/insecure.yaml"; then printf 'insecure Nethermind fixture unexpectedly passed Conftest\n' >&2; exit 1; fi
