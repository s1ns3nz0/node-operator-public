#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
script="$root/scripts/release/prepare-hoodi-validator-deployment.sh"
tmp="$(mktemp -d /private/tmp/node-operator-prepare-validator.XXXXXX)"
output="$tmp/prepared"
key='0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
web3signer='123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/node-operator-baseline-validator-runtime-web3signer@sha256:9a20e02a5821ad72fd318fa2a3ec0158a9a5acd9db80aa9214e9cc991ad4dbc3'
postgres='123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/node-operator-baseline-validator-runtime-postgres@sha256:030da09481c3876b71a7e49738a932e1c18c398201a1e4ccfdbff1e5a541215b'
prysm='123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/node-operator-baseline-validator-prysm@sha256:7fe554adf0efd27c0e5c5a3f80a3bbbec3d3872626208cf0a003b0dee7761f89'
fence='123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/node-operator-baseline-validator-fence@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'
"$script" --validator-set hoodi-test-001 --validator-public-key "$key" --withdrawal-address 0x403ff64383b8ddf994d5563550c8040d89f025ac --aws-account-id 123456789012 --web3signer-image "$web3signer" --postgres-image "$postgres" --prysm-validator-image "$prysm" --signing-fence-image "$fence" --kubernetes-api-cidr 10.100.0.1/32 --output-dir "$output" >/dev/null
[ "$(stat -f '%Lp' "$output")" = 700 ]
[ "$(stat -f '%Lp' "$output/validator-deployment-handoff.json")" = 600 ]
jq -e --arg output "$output" --arg key "$key" '.schema_version == 1 and .network == "hoodi" and .validator_set == "hoodi-test-001" and .aws_account_id == "123456789012" and .aws_region == "ap-northeast-2" and .validator_public_key == $key and .runtime_manifest == ($output + "/runtime.yaml") and .client_manifest == ($output + "/client-and-fence.yaml") and .staged_client_replicas == 0 and .staged_fence_replicas == 0 and (.next_steps | type == "array" and length == 5)' "$output/validator-deployment-handoff.json" >/dev/null
grep -Fq 'replicas: 0' "$output/client-and-fence.yaml"
jq -e '[paths(scalars)] | all(.[]; map(tostring | ascii_downcase) | all(test("mnemonic|password|recovery|vault_token|keystore"; "i") | not))' "$output/validator-deployment-handoff.json" >/dev/null || {
  printf '%s\n' 'handoff contains a prohibited secret-bearing field' >&2; exit 1
}
if "$script" --validator-set hoodi-test-001 --validator-public-key "$key" --withdrawal-address 0x403ff64383b8ddf994d5563550c8040d89f025ac --aws-account-id 123456789012 --web3signer-image "$web3signer" --postgres-image "$postgres" --prysm-validator-image "$prysm" --signing-fence-image "$fence" --kubernetes-api-cidr 10.100.0.1/32 --output-dir "$output" >/dev/null 2>&1; then
  printf '%s\n' 'existing output directory unexpectedly accepted' >&2; exit 1
fi
printf '%s\n' 'PASS: deployment preparation renders non-secret zero-replica manifests and a bounded handoff.'
