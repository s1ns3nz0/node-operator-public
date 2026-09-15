#!/usr/bin/env bash
set -euo pipefail
umask 077

usage() { printf '%s\n' "usage: ${0##*/} plan|apply --baseline-work-dir /absolute/zero-work-dir --baseline-config /absolute/baseline.tfvars --plan-file /absolute/private.tfplan" >&2; exit 64; }
operation="${1:-}"; shift || true
[ "$operation" = plan ] || [ "$operation" = apply ] || usage
work_dir=''; config=''; plan_file=''
while [ "$#" -gt 0 ]; do case "$1" in --baseline-work-dir) work_dir="${2:-}"; shift 2;; --baseline-config) config="${2:-}"; shift 2;; --plan-file) plan_file="${2:-}"; shift 2;; *) usage;; esac; done
case "$work_dir:$config:$plan_file" in /*:/*:/*) ;; *) usage;; esac
for cmd in terraform jq dirname stat grep; do command -v "$cmd" >/dev/null 2>&1 || { printf 'missing command: %s\n' "$cmd" >&2; exit 69; }; done
[ -d "$work_dir/baseline" ] && [ -f "$work_dir/baseline.backend.hcl" ] && [ ! -L "$work_dir/baseline.backend.hcl" ] || { printf '%s\n' 'baseline work directory is not a zero-apply result' >&2; exit 65; }
[ -f "$config" ] && [ ! -L "$config" ] && [ ! -L "$plan_file" ] || { printf '%s\n' 'configuration or plan path is unsafe' >&2; exit 65; }
parent="$(dirname "$plan_file")"; [ -d "$parent" ] || { printf '%s\n' 'plan directory is missing' >&2; exit 65; }
mode="$(stat -f '%Lp' "$parent" 2>/dev/null || stat -c '%a' "$parent")"; [ $((8#$mode & 077)) -eq 0 ] || { printf '%s\n' 'plan directory must not be accessible by group or others' >&2; exit 65; }
# The original baseline must explicitly keep both bootstrap controls disabled.
grep -F -x 'enable_argocd_bootstrap_runner           = false' "$config" >/dev/null && grep -F -x 'enable_argocd_bootstrap_cluster_admin    = false' "$config" >/dev/null || { printf '%s\n' 'baseline config must explicitly disable the Argo bootstrap runner and cluster admin' >&2; exit 65; }
terraform -chdir="$work_dir/baseline" init -input=false -reconfigure -backend-config="$work_dir/baseline.backend.hcl" >/dev/null
validate_plan() {
  terraform -chdir="$work_dir/baseline" show -json "$plan_file" | jq -e '
    [.resource_changes[]? | select(.change.actions != ["no-op"])] as $changes |
    ($changes | length > 0) and
    all($changes[]; .change.actions == ["delete"] and (.address | test("^(aws_(codebuild_project|cloudwatch_log_group|eks_access_(entry|policy_association)|iam_(role|role_policy|role_policy_attachment)|security_group|vpc_security_group_(egress_rule|ingress_rule))\\.argocd_bootstrap|aws_vpc_endpoint\\.private|aws_vpc_security_group_egress_rule\\.endpoints_to_argocd_bootstrap)")))
  ' >/dev/null || { printf '%s\n' 'revocation plan changes resources outside the temporary Argo bootstrap boundary' >&2; exit 70; }
}
if [ "$operation" = plan ]; then
  [ ! -e "$plan_file" ] || { printf '%s\n' 'plan file already exists' >&2; exit 65; }
  terraform -chdir="$work_dir/baseline" plan -input=false -var-file="$config" -out="$plan_file"
  chmod 600 "$plan_file"; validate_plan
  printf 'PASS: temporary Argo bootstrap revocation plan saved to %s; review before apply.\n' "$plan_file"
else
  [ -f "$plan_file" ] || { printf '%s\n' 'reviewed revocation plan file is required for apply' >&2; exit 65; }
  validate_plan
  terraform -chdir="$work_dir/baseline" apply -input=false "$plan_file"
  printf '%s\n' 'PASS: temporary Argo bootstrap runner and cluster-admin access were revoked.'
fi
