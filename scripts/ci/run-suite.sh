#!/usr/bin/env bash
# Check objective: Execute the same named, ordered test suite locally and in CI, stopping at the first failed check.
# Purpose: Execute or list one allowlisted CI test-suite manifest in a deterministic order.
# Inputs: Suite name and optional --list mode, plus repository-local suite manifests and test scripts.
# Outputs: Listed members or CHECK/PASS status lines and the first failing exit code.
# Side effects: Runs local test scripts in run mode; it performs no direct cloud, registry, or publication action.
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
suite="${1:-}"; mode="${2:-run}"
[[ "$suite" =~ ^[a-z][a-z0-9-]*$ ]] || { printf 'usage: bash scripts/ci/run-suite.sh SUITE [--list]\n' >&2; exit 64; }
[[ "$mode" = run || "$mode" = --list ]] || exit 64
[ "$#" -le 2 ] || exit 64
manifest="$root/scripts/ci/suites/$suite.txt"
[ -f "$manifest" ] || { printf 'unknown CI suite: %s\n' "$suite" >&2; exit 64; }
cd "$root"
count=0
while IFS= read -r script || [ -n "$script" ]; do
  [[ -z "$script" || "$script" = \#* ]] && continue
  [[ "$script" =~ ^scripts/ci/test-[a-zA-Z0-9-]+\.(sh|py)$ ]] || { printf 'invalid suite member\n' >&2; exit 65; }
  [ -f "$script" ] || { printf 'missing suite member: %s\n' "$script" >&2; exit 66; }
  count=$((count + 1))
  if [ "$mode" = --list ]; then printf '%s\n' "$script"; continue; fi
  printf 'CHECK [%s] %s\n' "$suite" "$script"
  case "$script" in *.sh) bash "$script" ;; *.py) python3 -B "$script" ;; esac
done < "$manifest"
[ "$count" -gt 0 ] || { printf 'empty CI suite\n' >&2; exit 65; }
if [ "$mode" = run ]; then printf 'PASS suite %s (%s checks)\n' "$suite" "$count"; fi
