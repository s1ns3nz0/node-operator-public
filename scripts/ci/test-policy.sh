#!/usr/bin/env bash
# Check objective: Run the repository Rego policy suite against its reviewed fixtures.
set -euo pipefail
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$script_dir/lib/common.sh"
root="$(repo_root)"
require_command opa
opa test --fail-on-empty --ignore fixtures "$root/policy"
