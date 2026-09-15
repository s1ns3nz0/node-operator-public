#!/usr/bin/env bash
set -euo pipefail
umask 077

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
scratch="$(mktemp -d "${TMPDIR:-/tmp}/ops-ebs-binding.XXXXXX")"
trap 'rm -rf "$scratch"' EXIT
# Exercise the production condition in a provider-free Terraform plan. This
# proves the four mode/flag combinations, not a full AWS plan or live identity.
condition="$(sed -n 's/^[[:space:]]*condition[[:space:]]*=[[:space:]]*\(var.ebs_optimized\)$/\1/p' "$root/infra/ops-access/main.tf")"
test "$condition" = 'var.ebs_optimized'
cp "$root/infra/ops-access/variables.tf" "$scratch/variables.tf"
cat > "$scratch/main.tf" <<EOF
resource "terraform_data" "guard" {
  lifecycle {
    precondition {
      condition = $condition
      error_message = "EBS representation binding rejected."
    }
  }
}
EOF
terraform -chdir="$scratch" init -input=false -no-color > "$scratch/init.log"
for mode in fresh retained; do
  for enabled in true false; do
    retention=null
    [ "$mode" != retained ] || retention='"i-0123456789abcdef0"'
    printf 'retained_host_instance_id = %s\nebs_optimized = %s\nvpc_id = "vpc-fixture"\nsubnet_id = "subnet-fixture"\ncluster_security_group_id = "sg-fixture"\n' "$retention" "$enabled" > "$scratch/case.tfvars"
    set +e
    terraform -chdir="$scratch" plan -input=false -no-color -detailed-exitcode -var-file=case.tfvars > "$scratch/plan.log" 2>&1
    result=$?
    set -e
    if [ "$mode" = fresh ] && [ "$enabled" = true ]; then
      [ "$result" -eq 2 ] || { printf 'valid EBS binding unexpectedly failed\n' >&2; exit 1; }
    else
      if [ "$result" -ne 1 ]; then
        printf 'invalid EBS binding was not rejected\n' >&2
        exit 1
      fi
    fi
  done
done
printf 'PASS rendered Terraform EBS binding: managed host requires true; retired host adoption is rejected.\n'
