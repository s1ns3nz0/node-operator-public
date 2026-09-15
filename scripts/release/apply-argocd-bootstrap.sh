#!/usr/bin/env bash
set -euo pipefail
umask 077

# The separately approved Argo step reuses only the backend and baseline copy
# produced by `zero apply`; it never discovers or creates another network.
usage() { printf '%s\n' "usage: ${0##*/} plan|apply --baseline-work-dir /absolute/zero-work-dir --baseline-config /absolute/baseline.tfvars --bootstrap-input /absolute/argocd.tfvars.json --plan-file /absolute/private.tfplan" >&2; exit 64; }
operation="${1:-}"; shift || true
[ "$operation" = plan ] || [ "$operation" = apply ] || usage
work_dir=''; baseline_config=''; bootstrap_input=''; plan_file=''
while [ "$#" -gt 0 ]; do case "$1" in
  --baseline-work-dir) work_dir="${2:-}"; shift 2 ;;
  --baseline-config) baseline_config="${2:-}"; shift 2 ;;
  --bootstrap-input) bootstrap_input="${2:-}"; shift 2 ;;
  --plan-file) plan_file="${2:-}"; shift 2 ;;
  *) usage ;;
esac; done
case "$work_dir:$baseline_config:$bootstrap_input:$plan_file" in /*:/*:/*:/*) ;; *) usage ;; esac
for command in terraform jq dirname stat; do command -v "$command" >/dev/null 2>&1 || { printf 'missing command: %s\n' "$command" >&2; exit 69; }; done
for file in "$baseline_config" "$bootstrap_input"; do [ -f "$file" ] && [ ! -L "$file" ] || { printf '%s\n' 'configuration input must be a regular file' >&2; exit 65; }; done
[ -d "$work_dir/baseline" ] && [ -f "$work_dir/baseline.backend.hcl" ] && [ ! -L "$work_dir/baseline.backend.hcl" ] || { printf '%s\n' 'baseline work directory is not a zero-apply result' >&2; exit 65; }
[ ! -L "$plan_file" ] || { printf '%s\n' 'plan file must not be a symlink' >&2; exit 65; }
parent="$(dirname "$plan_file")"; [ -d "$parent" ] || { printf '%s\n' 'plan directory is missing' >&2; exit 65; }
mode="$(stat -f '%Lp' "$parent" 2>/dev/null || stat -c '%a' "$parent")"; [ $((8#$mode & 077)) -eq 0 ] || { printf '%s\n' 'plan directory must not be accessible by group or others' >&2; exit 65; }
jq -e '
  .enable_argocd_bootstrap_runner == true and .enable_argocd_bootstrap_cluster_admin == true and
  (.argocd_bootstrap_image | test("^[0-9]{12}\\.dkr\\.ecr\\.[a-z]{2}-[a-z0-9-]+-[0-9]+\\.amazonaws\\.com/.+@sha256:[a-f0-9]{64}$")) and
  (.argocd_bootstrap_subnet_ids | type == "array" and length > 0 and all(.[]; test("^subnet-[a-z0-9]+$"))) and
  (.gitops_client_chart_version | test("^0\\.1\\.[0-9]+$")) and (.gitops_client_chart_oci_digest | test("^sha256:[a-f0-9]{64}$"))
' "$bootstrap_input" >/dev/null || { printf '%s\n' 'bootstrap input is not a digest-bound Argo handoff' >&2; exit 65; }
terraform -chdir="$work_dir/baseline" init -input=false -reconfigure -backend-config="$work_dir/baseline.backend.hcl" >/dev/null
validate_plan() {
  terraform -chdir="$work_dir/baseline" show -json "$plan_file" | jq -e '
    .variables.enable_argocd_bootstrap_runner.value == true and .variables.enable_argocd_bootstrap_cluster_admin.value == true and
    (.variables.gitops_client_chart_version.value | test("^0\\.1\\.[0-9]+$")) and
    (.variables.gitops_client_chart_oci_digest.value | test("^sha256:[a-f0-9]{64}$")) and
    all(.resource_changes[]?; (.change.actions | index("delete") | not))
  ' >/dev/null || { printf '%s\n' 'plan is not an additive digest-bound Argo bootstrap' >&2; exit 70; }
}
if [ "$operation" = plan ]; then
  [ ! -e "$plan_file" ] || { printf '%s\n' 'plan file already exists' >&2; exit 65; }
  terraform -chdir="$work_dir/baseline" plan -input=false -var-file="$baseline_config" -var-file="$bootstrap_input" -out="$plan_file"
  chmod 600 "$plan_file"; validate_plan
  printf 'PASS: digest-bound Argo bootstrap plan saved to %s; review before apply.\n' "$plan_file"
else
  [ -f "$plan_file" ] || { printf '%s\n' 'reviewed plan file is required for apply' >&2; exit 65; }
  validate_plan
  terraform -chdir="$work_dir/baseline" apply -input=false "$plan_file"
  printf '%s\n' 'PASS: reviewed digest-bound Argo bootstrap plan applied.'
fi
