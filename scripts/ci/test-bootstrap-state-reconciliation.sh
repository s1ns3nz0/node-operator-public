#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$script_dir/lib/common.sh"
root="$(repo_root)"
module="$root/infra/bootstrap-state"
variables="$module/variables.tf"
main="$module/main.tf"
outputs="$module/outputs.tf"
versions="$module/versions.tf"
runbook="$root/docs/operations/bootstrap-state-reconciliation.md"
fail() { printf 'FAIL bootstrap-state reconciliation: %s\n' "$*" >&2; exit 1; }
workspace="$(mktemp -d)"
trap 'rm -rf "$workspace"' EXIT

for required in \
  'variable "state_bucket_name"' \
  'default     = null' \
  'variable "baseline_state_key"' \
  'default     = "node-operator/baseline/terraform.tfstate"' \
  'node-operator/[a-z0-9][a-z0-9-]{0,62}/terraform\\.tfstate' \
  'variable "backend_principal_arns"' \
  'Exact same-account IAM role ARNs'; do
  rg -F "$required" "$variables" >/dev/null || fail "missing validated reconciliation contract: $required"
done

for required in \
  'generated_state_bucket' \
  'coalesce(var.state_bucket_name, local.generated_state_bucket)'; do
  rg -F "$required" "$main" >/dev/null || fail "missing generated-name preservation contract: $required"
done

rg -F 'key            = var.baseline_state_key' "$outputs" >/dev/null || fail 'backend output does not expose the configured state key'
rg -F 'kms_key_id     = aws_kms_key.state.arn' "$outputs" >/dev/null || fail 'backend output must select the state CMK explicitly'
rg -F 'bucket_key_enabled = false' "$main" >/dev/null || fail 'S3 object-context KMS permission requires bucket keys disabled'
rg -F 'allowed_account_ids = [var.aws_account_id]' "$versions" >/dev/null || fail 'provider account guard is missing'
rg -F 'backend "s3" {}' "$versions" >/dev/null || fail 'bootstrap module must declare its remote S3 backend'
rg -F '^arn:aws:iam::[0-9]{12}:role/' "$variables" >/dev/null || fail 'backend role syntax validation is missing'
rg -F '^arn:aws:iam::${var.aws_account_id}:role/' "$main" >/dev/null || fail 'backend roles are not constrained to the configured account'
rg -F 'precondition {' "$main" >/dev/null || fail 'same-account backend role validation must be a resource precondition'

test "$(rg -F -c 'prevent_destroy = true' "$main")" -ge 3 || fail 'state bucket, access-log bucket, and lock table must be destruction-protected'
rg -F 'AllowNamedBackendRolesS3DataCrypto' "$main" >/dev/null || fail 'S3 CMK data-plane allowlist is missing'
rg -F 'AllowNamedBackendRolesDescribeStateKey' "$main" >/dev/null || fail 'S3 CMK describe allowlist is missing'
rg -F 'Action    = ["kms:Decrypt", "kms:GenerateDataKey"]' "$main" >/dev/null || fail 'S3 CMK data-plane permissions are not the exact required actions'
! rg -F 'kms:GenerateDataKey*' "$main" >/dev/null || fail 'S3 CMK data-plane permissions must not include GenerateDataKeyWithoutPlaintext'
rg -F '"kms:ViaService"    = "s3.${var.aws_region}.amazonaws.com"' "$main" >/dev/null || fail 'S3 CMK service restriction is missing'
rg -F '"kms:EncryptionContext:aws:s3:arn" = "${local.state_bucket_arn}/*"' "$main" >/dev/null || fail 'S3 CMK encryption-context restriction is missing'
! rg -F 'kms:CreateGrant' "$main" >/dev/null || fail 'Backend roles must not receive grant-management permissions'
rg -F 'depends_on = [aws_s3_bucket_policy.state]' "$main" >/dev/null || fail 'SSE-C denial must precede encryption default changes'

# Evaluate actual Terraform plans and variable validation in a disposable,
# backend-free copy. The test-only provider override has no AWS endpoint.
cp -R "$module/." "$workspace/module"
cp "$workspace/module/fixtures/offline-provider-override.tf" "$workspace/module/override.tf"
# The production module intentionally declares an S3 backend. Remove only
# that declaration in the disposable offline copy so no test contacts AWS.
sed -i '' '/backend "s3" {}/d' "$workspace/module/versions.tf"
terraform -chdir="$workspace/module" init -backend=false -get=false -lockfile=readonly -input=false >/dev/null

terraform -chdir="$workspace/module" plan -refresh=false -input=false \
  -var='aws_account_id=123456789012' \
  -out="$workspace/default.plan" >/dev/null
terraform -chdir="$workspace/module" show -json "$workspace/default.plan" > "$workspace/default.json"
jq -e 'any(.resource_changes[]?; .address == "aws_s3_bucket.state" and .change.after.bucket == "node-operator-tfstate-123456789012-apnortheast2")' "$workspace/default.json" >/dev/null || fail 'default bucket plan changed or nullable default did not validate'
jq -e '
  (.configuration.root_module.outputs.backend.expression.references | index("aws_kms_key.state.arn")) != null and
  any(.resource_changes[]; .address == "aws_s3_bucket_server_side_encryption_configuration.state" and .change.after.rule[0].bucket_key_enabled == false)
' "$workspace/default.json" >/dev/null || fail 'Rendered backend output and bucket encryption must preserve CMK/object-context selection'

terraform -chdir="$workspace/module" plan -refresh=false -input=false \
  -var='aws_account_id=123456789012' \
  -var='state_bucket_name=node-operator-tfstate-123456789012-apne2' \
  -var='baseline_state_key=node-operator/t2/terraform.tfstate' \
  -out="$workspace/legacy.plan" >/dev/null
terraform -chdir="$workspace/module" show -json "$workspace/legacy.plan" > "$workspace/legacy.json"
jq -e 'any(.resource_changes[]?; .address == "aws_s3_bucket.state" and .change.after.bucket == "node-operator-tfstate-123456789012-apne2")' "$workspace/legacy.json" >/dev/null || fail 'legacy bucket override did not evaluate'

terraform -chdir="$workspace/module" plan -refresh=false -input=false \
  -var='aws_account_id=123456789012' \
  -var='state_bucket_name=node-operator-tfstate-123456789012-apne2' \
  -var='backend_principal_arns=["arn:aws:iam::123456789012:role/NodeOperatorTerraformApply"]' \
  -out="$workspace/roles.plan" >/dev/null
terraform -chdir="$workspace/module" show -json "$workspace/roles.plan" > "$workspace/roles.json"
jq -e '
  [.resource_changes[] | select(.address == "aws_kms_key.state") | .change.after.policy | fromjson | .Statement[]] as $s |
  ($s | length == 4) and
  ([$s[] | select(.Sid == "AllowNamedBackendRolesDynamoDataCrypto")] | length == 1) and
  ($s[] | select(.Sid == "AllowNamedBackendRolesDynamoDataCrypto") |
    .Effect == "Allow" and .Resource == "*" and
    .Principal == {"AWS":["arn:aws:iam::123456789012:role/NodeOperatorTerraformApply"]} and
    (.Action | sort) == (["kms:Encrypt","kms:Decrypt","kms:ReEncryptFrom","kms:ReEncryptTo","kms:GenerateDataKey","kms:GenerateDataKeyWithoutPlaintext"] | sort) and
    .Condition == {"StringEquals":{
      "kms:CallerAccount":"123456789012",
      "kms:ViaService":"dynamodb.ap-northeast-2.amazonaws.com",
      "kms:EncryptionContext:aws:dynamodb:tableName":"node-operator-terraform-lock",
      "kms:EncryptionContext:aws:dynamodb:subscriberId":"123456789012"}}) and
  ($s[] | select(.Sid == "AllowNamedBackendRolesS3DataCrypto") |
    (.Action | sort) == (["kms:Decrypt","kms:GenerateDataKey"] | sort) and
    .Condition == {"StringEquals":{"kms:CallerAccount":"123456789012","kms:ViaService":"s3.ap-northeast-2.amazonaws.com"},
      "StringLike":{"kms:EncryptionContext:aws:s3:arn":"arn:aws:s3:::node-operator-tfstate-123456789012-apne2/*"}}) and
  ($s[] | select(.Sid == "AllowNamedBackendRolesDescribeStateKey") |
    .Action == ["kms:DescribeKey"] and .Condition == {"StringEquals":{"kms:CallerAccount":"123456789012"}})
' "$workspace/roles.json" >/dev/null || fail 'Rendered KMS policy widened or omitted exact backend data-plane permissions'
jq -e '
  .resource_changes[] | select(.address == "aws_s3_bucket_policy.state") | .change.after.policy | fromjson |
  .Statement == [
    {"Sid":"DenyInsecureTransport","Effect":"Deny","Principal":"*","Action":"s3:*",
     "Resource":["arn:aws:s3:::node-operator-tfstate-123456789012-apne2","arn:aws:s3:::node-operator-tfstate-123456789012-apne2/*"],
     "Condition":{"Bool":{"aws:SecureTransport":"false"}}},
    {"Sid":"DenyCustomerProvidedEncryptionKeys","Effect":"Deny","Principal":"*","Action":"s3:PutObject",
     "Resource":"arn:aws:s3:::node-operator-tfstate-123456789012-apne2/*",
     "Condition":{"Null":{"s3:x-amz-server-side-encryption-customer-algorithm":"false"}}}
  ]
' "$workspace/roles.json" >/dev/null || fail 'Rendered state policy must retain TLS denial and reject SSE-C new writes'
jq -e '.resource_changes[] | select(.address == "aws_kms_key.state") | .change.after.policy | fromjson | .Statement | length == 1' "$workspace/default.json" >/dev/null || fail 'Empty backend allowlist must grant no role permissions'

expect_invalid_plan() {
  local expected_message="$1"
  shift
  if terraform -chdir="$workspace/module" plan -refresh=false -input=false "$@" >"$workspace/invalid-plan.out" 2>&1; then
    fail "invalid input unexpectedly planned: $expected_message"
  fi
  rg -F "$expected_message" "$workspace/invalid-plan.out" >/dev/null || fail "invalid input did not report: $expected_message"
}

expect_invalid_plan 'state_bucket_name must be null or a 3-63 character lowercase S3 bucket name' \
  -var='aws_account_id=123456789012' \
  -var='state_bucket_name=INVALID_BUCKET'

expect_invalid_plan 'baseline_state_key must be node-operator/<environment>/terraform.tfstate' \
  -var='aws_account_id=123456789012' \
  -var='baseline_state_key=node-operator/T2/terraform.tfstate'

expect_invalid_plan 'backend_principal_arns must contain only exact IAM role ARNs' \
  -var='aws_account_id=123456789012' \
  -var='backend_principal_arns=["arn:aws:iam::123456789012:user/not-a-role"]'

expect_invalid_plan 'backend_principal_arns must contain only IAM roles in aws_account_id' \
  -var='aws_account_id=123456789012' \
  -var='backend_principal_arns=["arn:aws:iam::999999999999:role/not-this-account"]'

# The backticks are literal Markdown required by the operator runbook.
# shellcheck disable=SC2016
for required in \
  'node-operator-tfstate-123456789012-apne2' \
  'node-operator/t2/terraform.tfstate' \
  'It is not a fresh `terraform apply`' \
  'operator_root="$(mktemp -d' \
  'aws_s3_bucket_server_side_encryption_configuration.state' \
  'node-operator-terraform-lock' \
  'private backend configuration file'; do
  rg -F "$required" "$runbook" >/dev/null || fail "runbook omits required reconciliation guidance: $required"
done

! rg -F 'terraform -chdir=infra/bootstrap-state' "$runbook" >/dev/null || fail 'runbook must execute Terraform only from a private module copy'
! rg -F 'EXACT_STATE_CMK_ID' "$runbook" >/dev/null || fail 'runbook must not instruct importing an unobserved state CMK'
! rg -F 'aws_kms_key.state EXACT' "$runbook" >/dev/null || fail 'runbook must not include an unobserved state CMK import command'

printf 'PASS bootstrap-state reconciliation contract is bounded and import-only.\n'
