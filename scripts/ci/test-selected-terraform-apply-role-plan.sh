#!/usr/bin/env bash
# Check objective: Bind KMS lifecycle policy only to an explicit selected role.
set -euo pipefail
# These later Terraform invocations do not inherit exports made by the child
# offline validator. Use synthetic credentials, never the operator's profile.
export AWS_ACCESS_KEY_ID=offline AWS_SECRET_ACCESS_KEY=offline AWS_EC2_METADATA_DISABLED=true
unset AWS_SESSION_TOKEN AWS_SECURITY_TOKEN AWS_PROFILE AWS_DEFAULT_PROFILE

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$script_dir/lib/common.sh"
root="$(cd "$script_dir/../.." && pwd -P)"
temporary_directory="$(mktemp -d)"
trap 'rm -rf "$temporary_directory"' EXIT
fail() { printf 'FAIL selected Terraform apply role: %s\n' "$*" >&2; exit 1; }

module="$root/infra/terraform"
role='arn:aws:iam::123456789012:role/SelectedTerraformApply'

"$script_dir/validate-terraform-offline.sh" "$module" "$temporary_directory/selected" fixtures/offline-selected-terraform-apply-role.tfvars >/dev/null

# The real plan includes a newly-created KMS administrator role, so policy
# JSON is unknown. In the disposable copied module only, seed that unrelated
# ARN to render the actual data-policy JSON under -refresh=false.
workspace="$temporary_directory/selected/terraform-source"
export TF_DATA_DIR="$temporary_directory/selected/terraform-data"
administrator='arn:aws:iam::123456789012:role/node-operator-kms-administrator'
replication_role='arn:aws:iam::123456789012:role/node-operator-audit-replication'
for source in "$workspace/kms.tf" "$workspace/audit-replica.tf"; do
  sed -i.bak "s|aws_iam_role.kms_administrator.arn|\"$administrator\"|g" "$source"
  rm -f "$source.bak"
done
sed -i.bak "s|aws_iam_role.audit_replication.arn|\"$replication_role\"|g" "$workspace/audit-replica.tf"
rm -f "$workspace/audit-replica.tf.bak"
cp "$module/fixtures/offline-kms-policy-outputs.tf" "$workspace/offline-kms-policy-outputs.tf"

render_plan() {
  local name="$1"; shift
  terraform -chdir="$workspace" plan -refresh=false -input=false "$@" -out="$temporary_directory/$name.plan" >/dev/null
  terraform -chdir="$workspace" show -json "$temporary_directory/$name.plan" > "$temporary_directory/$name.json"
}
render_plan selected-rendered -var-file=fixtures/offline-selected-terraform-apply-role.tfvars
render_plan omitted-rendered -var-file=fixtures/offline-baseline.tfvars

for policy in offline_test_kms_key_administrator_policy offline_test_audit_replica_key_policy; do
  jq -e --arg policy "$policy" '.planned_values.outputs[$policy].value' "$temporary_directory/selected-rendered.json" >/dev/null || fail "rendered policy is unavailable for $policy"
  jq -e --arg policy "$policy" --arg role "$role" '
    .planned_values.outputs[$policy].value | fromjson |
    [.Statement[] | select(.Sid == "AllowSelectedTerraformApplyKeyLifecycleManagement")] |
    length == 1 and .[0].Principal == {"AWS":$role} and
    (.[0].Action | sort) == (["kms:CancelKeyDeletion","kms:CreateAlias","kms:DeleteAlias","kms:DescribeKey","kms:EnableKeyRotation","kms:GetKeyPolicy","kms:GetKeyRotationStatus","kms:ListAliases","kms:ListResourceTags","kms:PutKeyPolicy","kms:ScheduleKeyDeletion","kms:TagResource"] | sort)
  ' "$temporary_directory/selected-rendered.json" >/dev/null || fail "selected role is absent or widened in $policy"
  jq -e --arg policy "$policy" '
    .planned_values.outputs[$policy].value | fromjson |
    [.Statement[] | select(.Sid == "AllowSelectedTerraformApplyKeyLifecycleManagement")] | length == 0
  ' "$temporary_directory/omitted-rendered.json" >/dev/null || fail "omitted role fabricated a principal in $policy"
done

expect_invalid_plan() {
  local role_value="$1" expected="$2" output
  output="$temporary_directory/invalid-${expected}.out"
  if terraform -chdir="$workspace" plan -refresh=false -input=false -var-file=fixtures/offline-baseline.tfvars -var="terraform_apply_role_arn=$role_value" >"$output" 2>&1; then
    fail "invalid selected role unexpectedly planned: $expected"
  fi
  grep -F "$expected" "$output" >/dev/null || fail "invalid selected role did not report $expected"
}

expect_invalid_plan 'arn:aws:iam::123456789012:user/not-a-role' 'terraform_apply_role_arn'
expect_invalid_plan 'arn:aws:iam::999999999999:role/ForeignTerraformApply' 'terraform_apply_role_arn'

printf 'PASS selected Terraform apply role KMS policy is explicit, lifecycle-only, and same-account bound.\n'
