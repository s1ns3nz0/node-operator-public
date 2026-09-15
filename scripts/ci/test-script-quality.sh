#!/usr/bin/env bash
# Check objective: Enforce ShellCheck static analysis of CI and release shell scripts.
set -euo pipefail
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$script_dir/lib/common.sh"
root="$(repo_root)"
require_command shellcheck
shellcheck_version="$(shellcheck --version | sed -n 's/^version: //p')"
[ "$shellcheck_version" = '0.11.0' ] || {
  printf 'ShellCheck 0.11.0 is required to match CI; run npm run harness:bootstrap-policy-tools and use .ci-tools/bin.\n' >&2
  exit 1
}
# CI blocks correctness errors while retaining ShellCheck output for advisory
# style/info findings that are not release-blocking by themselves.
find "$root/scripts/ci" "$root/scripts/release" -type f -name '*.sh' -exec shellcheck -S error -x -P "$root/scripts/ci" {} +
