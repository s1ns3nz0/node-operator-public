#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
script="$root/scripts/release/revoke-argocd-bootstrap.sh"
grep -Fq 'zero-apply result' "$script"
grep -Fq 'enable_argocd_bootstrap_cluster_admin    = false' "$script"
grep -Fq 'change.actions == ["delete"]' "$script"
grep -Fq 'outside the temporary Argo bootstrap boundary' "$script"
printf '%s\n' 'PASS: Argo bootstrap teardown requires a private reviewed deletion-only plan scoped to temporary resources.'
