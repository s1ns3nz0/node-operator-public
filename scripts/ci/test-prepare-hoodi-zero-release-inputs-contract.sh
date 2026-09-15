#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
scratch="$(mktemp -d /private/tmp/node-operator-zero-release-inputs.XXXXXX)"
cleanup() { rm -rf -- "$scratch"; }
trap cleanup EXIT INT TERM
fixture_root="$scratch/source"
# Build only the non-secret source files used by the real preparation path.
# In particular, do not inherit optional authorization inputs from a developer
# checkout or any sibling release bundle.
mkdir -p "$fixture_root/scripts/release" "$fixture_root/scripts/ops" "$fixture_root/deploy/validator" "$fixture_root/.ci/validator"
for file in \
  scripts/release/prepare-hoodi-zero-release-inputs.sh \
  scripts/release/prepare-zero-resource-inputs.sh \
  scripts/release/prepare-hoodi-validator-deployment.sh \
  scripts/release/validator_monitoring_dashboard.py \
  scripts/release/validator_monitoring_config.py \
  scripts/release/validator_monitoring_chain.py \
  scripts/ops/render-hoodi-validator-runtime.sh \
  scripts/ops/render-hoodi-validator-client.sh \
  deploy/validator/runtime-template.yaml \
  deploy/validator/client-template.yaml \
  deploy/validator/client-lease-fence-template.yaml \
  .ci/validator/approved-client-images.json; do
  cp "$root/$file" "$fixture_root/$file"
done
script="$fixture_root/scripts/release/prepare-hoodi-zero-release-inputs.sh"
output="$scratch/inputs"
key='0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
web3signer='123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/node-operator-baseline-validator-runtime-web3signer@sha256:9a20e02a5821ad72fd318fa2a3ec0158a9a5acd9db80aa9214e9cc991ad4dbc3'
postgres='123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/node-operator-baseline-validator-runtime-postgres@sha256:030da09481c3876b71a7e49738a932e1c18c398201a1e4ccfdbff1e5a541215b'
prysm='123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/node-operator-baseline-validator-prysm@sha256:7fe554adf0efd27c0e5c5a3f80a3bbbec3d3872626208cf0a003b0dee7761f89'
fence='123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/node-operator-baseline-validator-fence@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'

"$script" --aws-account-id 123456789012 --availability-zone ap-northeast-2a --availability-zone ap-northeast-2b --backend-principal-arn arn:aws:iam::123456789012:role/NodeOperatorTerraformApply --release-revision 1111111111111111111111111111111111111111 --validator-set hoodi-zero-001 --validator-public-key "$key" --withdrawal-address 0x403ff64383b8ddf994d5563550c8040d89f025ac --web3signer-image "$web3signer" --postgres-image "$postgres" --prysm-validator-image "$prysm" --signing-fence-image "$fence" --kubernetes-api-cidr 10.100.0.1/32 --output-dir "$output" >/dev/null
[ "$(stat -f '%Lp' "$output")" = 700 ]
for file in zero-resource/zero-resource-inputs.json validator-deployment/validator-deployment-handoff.json hoodi-zero-release-inputs.json; do
  [ -f "$output/$file" ] || { printf 'missing release input: %s\n' "$file" >&2; exit 1; }
  [ "$(stat -f '%Lp' "$output/$file")" = 600 ] || { printf 'unsafe release input mode: %s\n' "$file" >&2; exit 1; }
done
jq -e --arg output "$output" '.schema_version == 1 and .network == "hoodi" and .aws_account_id == "123456789012" and .validator_set == "hoodi-zero-001" and .zero_resource_inputs == ($output + "/zero-resource/zero-resource-inputs.json") and .validator_deployment_handoff == ($output + "/validator-deployment/validator-deployment-handoff.json") and (.required_checkpoints | length == 6)' "$output/hoodi-zero-release-inputs.json" >/dev/null
jq -e '.aws_account_id == "123456789012"' "$output/zero-resource/zero-resource-inputs.json" >/dev/null
jq -e --slurpfile dashboard "$output/zero-resource/validator-dashboard.json" \
  '(.validator_monitoring_dashboard_body | fromjson) == $dashboard[0]' \
  "$output/zero-resource/baseline.tfvars.json" >/dev/null
python3 - "$output/zero-resource/validator-dashboard.json" "$key" <<'PY'
import json, sys
body = json.load(open(sys.argv[1]))
assert body["widgets"]
assert sys.argv[2] not in json.dumps(body)
for widget in body["widgets"]:
    if widget["type"] in {"metric", "log"}:
        assert widget["properties"]["region"] == "ap-northeast-2"
PY
jq -e '.validator_set == "hoodi-zero-001" and .staged_client_replicas == 0 and .staged_fence_replicas == 0' "$output/validator-deployment/validator-deployment-handoff.json" >/dev/null
printf '%s\n' 'PASS: one bounded command prepares the complete non-secret zero-resource and validator input set.'
"$script" --aws-account-id 123456789012 --availability-zone ap-northeast-2a --availability-zone ap-northeast-2b --backend-principal-arn arn:aws:iam::123456789012:role/NodeOperatorTerraformApply --name node-operator --release-revision 1111111111111111111111111111111111111111 --validator-set hoodi-zero-001 --validator-public-key "$key" --withdrawal-address 0x403ff64383b8ddf994d5563550c8040d89f025ac --web3signer-image "$web3signer" --postgres-image "$postgres" --prysm-validator-image "$prysm" --signing-fence-image "$fence" --kubernetes-api-cidr 10.100.0.1/32 --output-dir "$scratch/identified" >/dev/null
ruby -ryaml -e 'count=0; ARGV.each{|f| YAML.load_stream(File.read(f)).each{|d| next unless d.is_a?(Hash) && ["Deployment","StatefulSet"].include?(d["kind"]); labels=d.dig("spec","template","metadata","labels"); abort "missing deployment identity" unless labels["node-operator.io/deployment-name"]=="node-operator"; abort "missing release identity" unless labels["node-operator.io/release-revision"]=="1"*40; count+=1}}; abort "missing workload" unless count==4' "$scratch/identified/validator-deployment/runtime.yaml" "$scratch/identified/validator-deployment/client-and-fence.yaml"
printf '%s\n' 'PASS: release identity reaches all four actual rendered workload Pod templates.'
