#!/usr/bin/env bash
# Check objective: Verify bootstrap state reconciliation using mock tools.
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$script_dir/../.." && pwd -P)"
helper="$root/scripts/release/reconcile-bootstrap-state.py"
python3 "$script_dir/test-bootstrap-kms-discovery.py"
release="$root/scripts/release/node-operator-release.sh"
workspace="$(mktemp -d)"
trap 'rm -rf "$workspace"' EXIT
fail() { printf 'FAIL bootstrap reconciliation mocks: %s\n' "$*" >&2; exit 1; }

grep -F 'terraform -chdir="$bootstrap_module" show -json > "$bootstrap_state_json"' "$release" >/dev/null || fail 'release must use supported terraform show -json state output'
! grep -F 'state show -json' "$release" >/dev/null || fail 'release must not use unsupported terraform state show -json'
! grep -F 'state list' "$release" >/dev/null || fail 'bootstrap must use show JSON because state list errors for a valid empty state'

printf '{not-json\n' > "$workspace/corrupt-local.tfstate"
if jq -e 'type == "object" and (.resources | type == "array")' "$workspace/corrupt-local.tfstate" >/dev/null 2>&1; then
  fail 'corrupt local checkpoint passed the local-state shape check'
fi
grep -F 'bootstrap checkpoint has invalid local Terraform state' "$release" >/dev/null || fail 'release does not fail closed for corrupt local checkpoint state'

destructive_plan='{"configuration":{"root_module":{"resources":[{"address":"aws_s3_bucket.state"}]}},"resource_changes":[{"address":"aws_s3_bucket.state","change":{"actions":["delete","create"]}}]}'
if jq -e '(.configuration.root_module.resources | type == "array") and ([.configuration.root_module.resources[]?.address] | unique) as $allowed | all(.resource_changes[]?; (.address as $address | ($allowed | index($address)) != null) and all(.change.actions[]?; . != "delete"))' <<<"$destructive_plan" >/dev/null; then
  fail 'destructive bootstrap plan passed the pre-apply gate'
fi
foreign_plan='{"configuration":{"root_module":{"resources":[{"address":"aws_s3_bucket.state"}]}},"resource_changes":[{"address":"aws_kms_key.foreign","change":{"actions":["create"]}}]}'
if jq -e '(.configuration.root_module.resources | type == "array") and ([.configuration.root_module.resources[]?.address] | unique) as $allowed | all(.resource_changes[]?; (.address as $address | ($allowed | index($address)) != null) and all(.change.actions[]?; . != "delete"))' <<<"$foreign_plan" >/dev/null; then
  fail 'foreign resource bootstrap plan passed the pre-apply gate'
fi

mkdir "$workspace/bin"
cat > "$workspace/bin/aws" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "$AWS_CALL_LOG"
service="$1"; operation="$2"
if [ "${AWS_DUPLICATE_KMS:-0}" = 1 ] && [ "$service:$operation" = 'resourcegroupstaggingapi:get-resources' ]; then
  printf '{"ResourceTagMappingList":[{"ResourceARN":"arn:aws:kms:ap-northeast-2:123456789012:key/key-123"},{"ResourceARN":"arn:aws:kms:ap-northeast-2:123456789012:key/key-123"}]}'
  exit 0
fi
if [ "${AWS_NO_KMS:-0}" = 1 ] && [ "$service:$operation" = 'resourcegroupstaggingapi:get-resources' ]; then
  printf '{"ResourceTagMappingList":[]}'
  exit 0
fi
if [ "${AWS_BUCKET_OBJECT:-0}" = 1 ] && [ "$service:$operation" = 's3api:list-objects-v2' ]; then
  printf '{"Contents":[{"Key":"node-operator/bootstrap-state/terraform.tfstate"}]}'
  exit 0
fi
case "$AWS_SCENARIO:$service:$operation" in
  existing:s3api:list-buckets) printf '{"Buckets":[{"Name":"node-operator-tfstate-123456789012-apnortheast2"},{"Name":"node-operator-tfstate-123456789012-apnortheast2-01234567-logs"}]}' ;;
  existing:s3api:get-bucket-tagging) printf '{"TagSet":[{"Key":"Project","Value":"node-operator"},{"Key":"Deployment","Value":"hoodi"},{"Key":"DeploymentRegion","Value":"ap-northeast-2"},{"Key":"ManagedBy","Value":"terraform"},{"Key":"Purpose","Value":"terraform-state-bootstrap"}]}' ;;
  existing:s3api:get-bucket-encryption) printf '{"ServerSideEncryptionConfiguration":{"Rules":[{"ApplyServerSideEncryptionByDefault":{"KMSMasterKeyID":"arn:aws:kms:ap-northeast-2:123456789012:key/key-123"}}]}}' ;;
  existing:s3api:list-objects-v2) printf '{"Contents":[]}' ;;
  existing:dynamodb:describe-table) printf '{"Table":{"TableArn":"arn:aws:dynamodb:ap-northeast-2:123456789012:table/hoodi-terraform-lock"}}' ;;
  existing:dynamodb:list-tags-of-resource) printf '{"Tags":[{"Key":"Project","Value":"node-operator"},{"Key":"Deployment","Value":"hoodi"},{"Key":"DeploymentRegion","Value":"ap-northeast-2"},{"Key":"ManagedBy","Value":"terraform"},{"Key":"Purpose","Value":"terraform-state-bootstrap"}]}' ;;
  existing:resourcegroupstaggingapi:get-resources) printf '{"ResourceTagMappingList":[{"ResourceARN":"arn:aws:kms:ap-northeast-2:123456789012:key/key-123"}]}' ;;
  existing:kms:describe-key) printf '{"KeyMetadata":{"Arn":"arn:aws:kms:ap-northeast-2:123456789012:key/key-123","KeyState":"Enabled","KeyManager":"CUSTOMER"}}' ;;
  existing:kms:list-resource-tags) printf '{"Tags":[{"TagKey":"Project","TagValue":"node-operator"},{"TagKey":"Deployment","TagValue":"hoodi"},{"TagKey":"DeploymentRegion","TagValue":"ap-northeast-2"},{"TagKey":"ManagedBy","TagValue":"terraform"},{"TagKey":"Purpose","TagValue":"terraform-state-bootstrap"}]}' ;;
  existing:kms:list-aliases) printf '{"Aliases":[{"AliasName":"alias/node-operator-hoodi-bootstrap-state","TargetKeyId":"arn:aws:kms:ap-northeast-2:123456789012:key/key-123"}]}' ;;
  none:s3api:list-buckets) printf '{"Buckets":[]}' ;;
  none:dynamodb:describe-table) printf 'An error occurred (ResourceNotFoundException)' >&2; exit 255 ;;
  none:resourcegroupstaggingapi:get-resources) printf '{"ResourceTagMappingList":[]}' ;;
  unowned:s3api:list-buckets) printf '{"Buckets":[{"Name":"node-operator-tfstate-123456789012-apnortheast2"}]}' ;;
  unowned:s3api:get-bucket-tagging) printf '{"TagSet":[{"Key":"Project","Value":"someone-else"}]}' ;;
  *) printf 'unexpected mock AWS call: %s\n' "$AWS_SCENARIO:$service:$operation" >&2; exit 64 ;;
esac
MOCK
chmod 700 "$workspace/bin/aws"

run_helper() {
  AWS_CALL_LOG="$workspace/calls" AWS_SCENARIO="$1" PATH="$workspace/bin:$PATH" \
    python3 "$helper" --region ap-northeast-2 --deployment hoodi \
      --account-id 123456789012 --bucket node-operator-tfstate-123456789012-apnortheast2 \
      --logs-bucket node-operator-tfstate-123456789012-apnortheast2-01234567-logs \
      --table hoodi-terraform-lock "${@:2}"
}

run_helper existing > "$workspace/existing.tsv"
if AWS_DUPLICATE_KMS=1 run_helper existing > "$workspace/duplicate.tsv" 2> "$workspace/duplicate.err"; then
  fail 'ambiguous KMS discovery was allowed to choose a key'
fi
grep -F 'refusing to choose between multiple owned bootstrap KMS keys' "$workspace/duplicate.err" >/dev/null || fail 'ambiguous key rejection was not explicit'
diff -u <(printf '%s\n' \
  $'aws_s3_bucket.state\tnode-operator-tfstate-123456789012-apnortheast2' \
  $'aws_s3_bucket.state_access_logs\tnode-operator-tfstate-123456789012-apnortheast2-01234567-logs' \
  $'aws_dynamodb_table.lock\thoodi-terraform-lock' \
  $'aws_kms_key.state\tkey-123' \
  $'aws_kms_alias.state\talias/node-operator-hoodi-bootstrap-state') "$workspace/existing.tsv" || fail 'owned existing resources were not exactly selected for import'

: > "$workspace/calls"
run_helper existing \
  --state-address aws_s3_bucket.state --state-id aws_s3_bucket.state=node-operator-tfstate-123456789012-apnortheast2 \
  --state-address aws_s3_bucket.state_access_logs --state-id aws_s3_bucket.state_access_logs=node-operator-tfstate-123456789012-apnortheast2-01234567-logs \
  --state-address aws_dynamodb_table.lock --state-id aws_dynamodb_table.lock=hoodi-terraform-lock \
  --state-address aws_kms_key.state --state-id aws_kms_key.state=key-123 \
  --state-address aws_kms_alias.state --state-id aws_kms_alias.state=alias/node-operator-hoodi-bootstrap-state > "$workspace/remote.tsv"
[ ! -s "$workspace/remote.tsv" ] || fail 'existing remote Terraform state must be reused without imports'
! grep -Eq '(^| )(create|put|tag-resource|untag-resource|delete|update)( |$)' "$workspace/calls" || fail 'existing remote Terraform state reconciliation used a write operation'

: > "$workspace/calls"
run_helper none > "$workspace/none.tsv"
[ ! -s "$workspace/none.tsv" ] || fail 'no-resource path must create rather than import'
! grep -Eq '(^| )(create|put|tag-resource|untag-resource|delete|update)( |$)' "$workspace/calls" || fail 'reconciliation mock used an AWS write operation'

if run_helper unowned > "$workspace/unowned.tsv" 2> "$workspace/unowned.err"; then
  fail 'unowned deterministic resource was adopted'
fi
grep -F 'refusing to adopt unowned S3 bucket' "$workspace/unowned.err" >/dev/null || fail 'unowned resource rejection was not explicit'
[ ! -s "$workspace/unowned.tsv" ] || fail 'unowned resource emitted an import mapping'

if run_helper unowned --state-address aws_s3_bucket.state > "$workspace/remote-unowned.tsv" 2> "$workspace/remote-unowned.err"; then
  fail 'foreign resource recorded in remote state was trusted'
fi
grep -F 'refusing to adopt unowned S3 bucket' "$workspace/remote-unowned.err" >/dev/null || fail 'foreign remote-state resource rejection was not explicit'

if run_helper existing --state-address aws_s3_bucket.state --state-id aws_s3_bucket.state=foreign-bucket > "$workspace/wrong-id.tsv" 2> "$workspace/wrong-id.err"; then
  fail 'mismatched Terraform state identity was trusted'
fi
grep -F 'Terraform state identity for aws_s3_bucket.state does not match' "$workspace/wrong-id.err" >/dev/null || fail 'mismatched state identity rejection was not explicit'

AWS_NO_KMS=1 run_helper existing > "$workspace/partial-empty.tsv" || fail 'empty interrupted state bucket was not allowed to complete its KMS setup'
! grep -F 'aws_kms_key.state' "$workspace/partial-empty.tsv" >/dev/null || fail 'empty interrupted bucket must not import an absent KMS key'
if AWS_NO_KMS=1 AWS_BUCKET_OBJECT=1 run_helper existing > "$workspace/missing-kms.tsv" 2> "$workspace/missing-kms.err"; then
  fail 'populated state bucket without its owned KMS key was allowed to change encryption'
fi
grep -F 'refusing to change encryption on existing state bucket' "$workspace/missing-kms.err" >/dev/null || fail 'populated bucket missing KMS rejection was not explicit'

printf 'PASS bootstrap reconciliation uses read-only AWS discovery and strict ownership imports.\n'
