#!/usr/bin/env bash
# shellcheck disable=SC2016 # literal shell fragments are contract assertions
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
script="$root/scripts/release/publish-gitops-client-chart.sh"
grep -Fq 'promotion_id=' "$script"
grep -Fq 'gitops-chart-evidence-${promotion_id}' "$script"
grep -Fq 'github() { gh "$@"; }' "$script"
if grep -Fq 'env -u GITHUB_TOKEN' "$script"; then
  printf '%s\n' 'GitOps chart publisher must preserve GITHUB_TOKEN' >&2
  exit 1
fi
grep -Fq 'multiple workflow runs produced the same promotion evidence identifier' "$script"
grep -Fq 'github run view "$run_id"' "$script"
if grep -Eq -- '--limit[[:space:]]+1([[:space:]]|$)' "$script"; then
  printf '%s\n' 'publisher must not select the newest workflow run' >&2
  exit 1
fi
printf '%s\n' 'PASS: chart promotion binds a unique dispatch identifier to its verified evidence artifact.'
