#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
module="$root/infra/ops-access"

terraform -chdir="$module" fmt -check -recursive
grep -E '^  monitoring[[:space:]]*=[[:space:]]*false$' "$module/main.tf" >/dev/null
grep -F 'ebs_optimized                        = var.ebs_optimized' "$module/main.tf" >/dev/null
grep -F 'condition     = var.ebs_optimized == !local.retain_existing_host' "$module/main.tf" >/dev/null
grep -F 'encrypted   = true' "$module/main.tf" >/dev/null
grep -F 'volume_type = "gp3"' "$module/main.tf" >/dev/null
grep -F 'http_endpoint               = "enabled"' "$module/main.tf" >/dev/null
grep -F 'http_tokens                 = "required"' "$module/main.tf" >/dev/null
grep -F 'http_put_response_hop_limit = 1' "$module/main.tf" >/dev/null
if grep -Eq 'ignore_changes|checkov:skip' "$module/main.tf"; then
  printf 'basic-monitoring change must not suppress drift or Checkov findings\n' >&2
  exit 1
fi

printf 'PASS ops-access basic monitoring preserves EBS, encrypted disk, and IMDSv2 controls.\n'
