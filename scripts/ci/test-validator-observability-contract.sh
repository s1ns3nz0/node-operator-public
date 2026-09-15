#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
schema="$root/deploy/observability/evidence-envelope.schema.json"
validator="$root/scripts/ops/validate-validator-evidence-envelope.sh"
contract="$root/docs/operations/validator-observability-contract.md"
terraform_config="$root/infra/terraform/validator-observability.tf"
for file in "$schema" "$validator" "$contract" "$terraform_config"; do test -f "$file" || { printf 'missing validator observability artifact: %s\n' "$file" >&2; exit 1; }; done
jq -e '.properties.network.const == "hoodi" and .properties.validator_public_key.pattern == "^0x[0-9a-fA-F]{96}$"' "$schema" >/dev/null
jq -e '.properties.source.enum | index("public-rpc") != null' "$schema" >/dev/null
grep -Fq '"public-rpc"' "$validator"
grep -Fq 'Etherscan and Beaconcha.in are asynchronous' "$contract"
grep -Fq 'forbidden field name' "$validator"
grep -Fq '!{firehose:error-output-type}' "$terraform_config"
# Prevent an activation race: the producer KMS policy must not depend on the
# stream whose encryption it permits. Inspect complete Terraform blocks.
node - "$terraform_config" "$root/infra/terraform/validator-firehose-buffer.tf" <<'NODE'
const fs = require('fs');
const assert = require('assert/strict');
const streamSource = fs.readFileSync(process.argv[2], 'utf8');
const keySource = fs.readFileSync(process.argv[3], 'utf8');
function block(source, declaration) {
  const start = source.indexOf(declaration);
  assert(start >= 0, `missing ${declaration}`);
  const rest = source.slice(start + declaration.length);
  return rest.slice(0, rest.search(/^}/m));
}
const stream = block(streamSource, 'resource "aws_kinesis_firehose_delivery_stream" "validator_audit" {');
assert.match(stream, /depends_on\s*=\s*\[[^\]]*aws_iam_role_policy\.validator_firehose_buffer/s);
const producer = block(keySource, 'data "aws_iam_policy_document" "validator_firehose_buffer_producer" {');
assert.match(producer, /actions\s*=\s*\["kms:GenerateDataKey", "kms:Decrypt"\]/);
assert.match(producer, /resources\s*=\s*\[aws_kms_key\.validator_firehose_buffer\.arn\]/);
assert.doesNotMatch(producer, /aws_kinesis_firehose_delivery_stream/);
const policy = block(keySource, 'resource "aws_iam_role_policy" "validator_firehose_buffer" {');
assert.match(policy, /role\s*=\s*aws_iam_role\.validator_cloudwatch_subscription\.id/);
assert.match(policy, /policy\s*=\s*data\.aws_iam_policy_document\.validator_firehose_buffer_producer\.json/);
const subscription = block(streamSource, 'data "aws_iam_policy_document" "validator_cloudwatch_subscription" {');
assert.doesNotMatch(subscription, /kms:/);
NODE
printf 'PASS validator observability contract preserves public-only evidence boundaries.\n'
