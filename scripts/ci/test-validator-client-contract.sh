#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
tmp="$(mktemp -d "${TMPDIR:-/tmp}/node-operator-client-render.XXXXXX")"
# Legacy catalog rendering must not inherit the checkout's release authorization.
# Bundle authorization is exercised by test-render-authorized-validator-client.py.
fixture="$tmp/source"
mkdir -p "$fixture/scripts/ops" "$fixture/deploy/validator" "$fixture/.ci/validator"
cp "$root/scripts/ops/render-hoodi-validator-client.sh" "$fixture/scripts/ops/"
cp "$root/deploy/validator/client-template.yaml" "$root/deploy/validator/client-lease-fence-template.yaml" "$fixture/deploy/validator/"
cp "$root/.ci/validator/approved-client-images.json" "$fixture/.ci/validator/"
renderer="$fixture/scripts/ops/render-hoodi-validator-client.sh"
image='123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/node-operator-baseline-validator-prysm@sha256:7fe554adf0efd27c0e5c5a3f80a3bbbec3d3872626208cf0a003b0dee7761f89'
native_image='123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/node-operator-baseline-validator-prysm@sha256:f35410bedf15c5a7b710769e1c67c5f77e74f75544fd51084f12d47082c457e3'
fence_image='123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/node-operator-baseline-validator-fence@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'
key='0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
allowlist="$root/.ci/validator/approved-client-images.json"
jq -e '.schema_version == 2 and all(.images[]; (.private_image == "123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/node-operator-example-baseline-validator-prysm@sha256:2789e2433b907019958b6d558c6e19b27dc9af7fe10e38684a1a64fccb48263d" or (.private_image | test("^123456789012\\.dkr\\.ecr\\.ap-northeast-2\\.amazonaws\\.com/node-operator-baseline-validator-prysm@sha256:[a-f0-9]{64}$"))) and (.release_channel == "upstream-mirror" or .release_channel == "manual-native-mtls") and (.stage_approved | type == "boolean") and (.activation_approved | type == "boolean"))' "$allowlist" >/dev/null
if jq 'del(.images[1].release_channel)' "$allowlist" | jq -e --arg image "$native_image" '.schema_version == 2 and any(.images[]; .private_image == $image and .stage_approved == true and (.release_channel == "upstream-mirror" or .release_channel == "manual-native-mtls"))' >/dev/null; then
  printf '%s\n' 'missing release channel unexpectedly passes stage contract' >&2; exit 1
fi
"$renderer" --validator-set hoodi-test-001 --validator-public-key "$key" --aws-account-id 123456789012 --prysm-validator-image "$image" --signing-fence-image "$fence_image" --kubernetes-api-cidr 10.100.0.1/32 --output "$tmp/client.yaml" >/dev/null
"$renderer" --validator-set hoodi-test-001 --validator-public-key "$key" --aws-account-id 123456789012 --prysm-validator-image "$image" --signing-fence-image "$fence_image" --kubernetes-api-cidr 10.100.0.1/32 --deployment-name node-operator --release-revision 1111111111111111111111111111111111111111 --output "$tmp/identified.yaml" >/dev/null
ruby -ryaml -e 'old=YAML.load_stream(File.read(ARGV[0])); identified=YAML.load_stream(File.read(ARGV[1])); count=0; identified.each{|d| next unless d.is_a?(Hash) && ["Deployment","StatefulSet"].include?(d["kind"]); labels=d.dig("spec","template","metadata","labels"); abort "deployment label mismatch" unless labels.delete("node-operator.io/deployment-name")=="node-operator"; abort "release label mismatch" unless labels.delete("node-operator.io/release-revision")=="1"*40; count+=1}; abort "labels changed more than Pod metadata" unless count==2 && identified==old' "$tmp/client.yaml" "$tmp/identified.yaml"
"$renderer" --validator-set hoodi-test-001 --validator-public-key "$key" --aws-account-id 123456789012 --prysm-validator-image "$native_image" --signing-fence-image "$fence_image" --kubernetes-api-cidr 10.100.0.1/32 --output "$tmp/native-client.yaml" >/dev/null
if "$renderer" --validator-set hoodi-test-001 --validator-public-key "$key" --aws-account-id 999999999999 --prysm-validator-image "$image" --signing-fence-image "$fence_image" --kubernetes-api-cidr 10.100.0.1/32 --output "$tmp/wrong-account.yaml" >/dev/null 2>&1; then
  printf '%s\n' 'client renderer accepted images from another AWS account' >&2
  exit 1
fi
for rejected in \
  "123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/other-repository@${native_image##*@}" \
  "123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/node-operator-baseline-validator-prysm@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"; do
  if "$renderer" --validator-set hoodi-test-001 --validator-public-key "$key" --aws-account-id 123456789012 --prysm-validator-image "$rejected" --signing-fence-image "$fence_image" --kubernetes-api-cidr 10.100.0.1/32 --output "$tmp/rejected-client.yaml" >/dev/null 2>&1; then
    printf 'unexpectedly rendered unapproved client image: %s\n' "$rejected" >&2; exit 1
  fi
done
grep -Fq 'replicas: 0' "$tmp/client.yaml"
grep -Fq -- '--validators-external-signer-url=https://' "$tmp/client.yaml"
grep -Fq -- '--datadir=/data' "$tmp/client.yaml"
if grep -Fq -- '--remote-signer-ca-crt-path=' "$tmp/client.yaml"; then printf '%s\n' 'gRPC-only CA flag must not stand in for Web3Signer HTTP trust' >&2; exit 1; fi
grep -Fq -- '--validators-external-signer-http-client-cert=/vault/secrets/tls.crt' "$tmp/client.yaml"
grep -Fq -- '--validators-external-signer-http-client-key=/vault/secrets/tls.key' "$tmp/client.yaml"
grep -Fq -- '--validators-external-signer-http-ca-cert=/vault/secrets/ca.crt' "$tmp/client.yaml"
grep -Fq 'automountServiceAccountToken: false' "$tmp/client.yaml"
grep -Fq 'vault.hashicorp.com/role: hoodi-hoodi-test-001-client-tls' "$tmp/client.yaml"
grep -Fq 'agent-inject-template-tls.key' "$tmp/client.yaml"
grep -Fq 'fsGroup: 1000' "$tmp/client.yaml"
if grep -Eq 'SSL_CERT_FILE|binaryData:|secretName: validator-hoodi-test-001-client-tls' "$tmp/client.yaml"; then printf '%s\n' 'client received ambient trust or Kubernetes TLS secret' >&2; exit 1; fi
grep -Fq 'name: validator-hoodi-test-001-signing-fence' "$tmp/client.yaml"
grep -Fq 'replicas: 0' "$tmp/client.yaml"
grep -Fq '10.100.0.1/32' "$tmp/client.yaml"
grep -Fq 'serviceAccountName: validator-hoodi-test-001-client-fence' "$tmp/client.yaml"
grep -Fq 'expirationSeconds: 600' "$tmp/client.yaml"
grep -Fq 'fsGroup: 65532' "$tmp/client.yaml"
grep -Fq 'defaultMode: 0440' "$tmp/client.yaml"
grep -Fq 'httpGet: {path: /healthz, port: health}' "$tmp/client.yaml"
ruby -ryaml -e 'documents=YAML.load_stream(File.read(ARGV[0])); client=documents.find{|d| d.is_a?(Hash) && d["kind"]=="StatefulSet" && d.dig("metadata","name")=="validator-hoodi-test-001-client"}; abort "client missing" unless client; abort "client identity is not stable" unless client.dig("spec","serviceName")=="validator-hoodi-test-001-client-headless"; mounts=client.dig("spec","template","spec","containers").flat_map{|c| c["volumeMounts"] || []}; abort "client received fence token" if mounts.any?{|m| m["name"]=="api-token"}' "$tmp/client.yaml"
grep -Fq 'resourceNames: ["validator-hoodi-test-001-client-0"]' "$tmp/client.yaml"
ruby -ryaml -e '
  docs=YAML.load_stream(File.read(ARGV[0]))
  policy=docs.find{|d| d.is_a?(Hash) && d["kind"]=="NetworkPolicy" && d.dig("metadata","name")=="validator-hoodi-test-001-beacon-ingress"}
  expected={"podSelector"=>{"matchLabels"=>{"app.kubernetes.io/name"=>"prysm-beacon"}},"policyTypes"=>["Ingress"],"ingress"=>[{"from"=>[{"namespaceSelector"=>{"matchLabels"=>{"kubernetes.io/metadata.name"=>"validator-operations"}},"podSelector"=>{"matchLabels"=>{"app.kubernetes.io/component"=>"validator-client","node-operator.io/validator-set"=>"hoodi-test-001"}}}],"ports"=>[{"protocol"=>"TCP","port"=>3500}]}]}
  valid=->(p){p && p.dig("metadata","namespace")=="node-operator" && p["spec"]==expected}
  abort "beacon ingress boundary mismatch" unless valid.call(policy)
  mutated=Marshal.load(Marshal.dump(policy)); mutated["spec"]["ingress"][0]["from"][0].delete("podSelector")
  abort "unrestricted namespace accepted" if valid.call(mutated)
  mutated=Marshal.load(Marshal.dump(policy)); mutated["spec"]["ingress"][0]["ports"][0]["port"]=443
  abort "wrong port accepted" if valid.call(mutated)
' "$tmp/client.yaml"
printf '%s\n' 'PASS: validator client uses set-scoped HTTP mTLS files and cannot start before activation.'
