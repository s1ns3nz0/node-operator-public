#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
script="$root/scripts/release/apply-argocd-bootstrap.sh"
grep -Fq 'zero-apply result' "$script"
grep -Fq 'gitops_client_chart_oci_digest' "$script"
grep -Fq 'all(.resource_changes[]?; (.change.actions | index("delete") | not))' "$script"
grep -Fq 'reviewed plan file is required for apply' "$script"
printf '%s\n' 'PASS: Argo bootstrap reuses zero-apply state and requires a reviewed additive digest-bound plan.'
