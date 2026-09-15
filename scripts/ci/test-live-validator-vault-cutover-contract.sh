#!/usr/bin/env bash
# shellcheck disable=SC2016 # literal source-contract fragments
# Check objective: Enforce guarded validator runtime Vault cutover sequencing and evidence boundaries.
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
script="$root/scripts/ops/apply-live-validator-vault-cutover.sh"
policy="$root/deploy/validator/vault-runtime-egress-policy.yaml"
test -x "$script"; bash -n "$script"
test -f "$policy"
for required in \
  'signing-proxy-fence' \
  'client_and_fence_quiesced == true' \
  'direct_client_to_signer_denied == true' \
  'dry-run=server' \
  'Vault signer TLS injection' \
  'Vault client TLS injection' \
  'scale deployment "$signer" --replicas=1' \
  'signing_fence_replicas:0' \
  'activation_required:true' \
  'validator client must remain at zero' \
  'legacy_tls_secrets_retained:true'; do grep -Fq "$required" "$script" || { printf 'missing validator cutover control: %s\n' "$required" >&2; exit 1; }; done
if grep -Eq 'delete secret.*(signer|client)-tls|create secret generic' "$script"; then printf '%s\n' 'validator cutover must retain legacy TLS Secrets and never create replacements' >&2; exit 1; fi
if grep -Fq 'scale deployment "$fence_deployment" --replicas=1' "$script"; then
  printf '%s\n' 'staging must not start the identity-bound fence without its client' >&2; exit 1
fi
grep -Fq 'vault-runtime-egress-policy.yaml' "$script" || { printf '%s\n' 'cutover does not install the dedicated Vault egress policy' >&2; exit 1; }
grep -Fq 'field-manager=node-operator-vault-cutover-egress' "$script" || { printf '%s\n' 'cutover Vault egress policy lacks its dedicated field manager' >&2; exit 1; }
ruby -ryaml -e '
docs=YAML.load_stream(File.read(ARGV[0])).select{|d| d.is_a?(Hash)}
abort "expected exactly one policy" unless docs.length == 1
policy=docs.first
abort "wrong policy identity" unless policy["apiVersion"]=="networking.k8s.io/v1" && policy["kind"]=="NetworkPolicy" && policy.dig("metadata","name")=="allow-labelled-runtime-vault-clients" && policy.dig("metadata","namespace")=="validator-operations"
abort "wrong selector" unless policy.dig("spec","podSelector","matchLabels")=={"node-operator.io/vault-client"=>"true"}
abort "must be egress only" unless policy.dig("spec","policyTypes")==["Egress"] && !policy.dig("spec").key?("ingress")
expected=[{"to"=>[{"namespaceSelector"=>{"matchLabels"=>{"kubernetes.io/metadata.name"=>"vault"}},"podSelector"=>{"matchLabels"=>{"app.kubernetes.io/name"=>"vault"}}}],"ports"=>[{"protocol"=>"TCP","port"=>8200}]},{"to"=>[{"namespaceSelector"=>{"matchLabels"=>{"kubernetes.io/metadata.name"=>"kube-system"}}}],"ports"=>[{"protocol"=>"UDP","port"=>53},{"protocol"=>"TCP","port"=>53}]},{"to"=>[{"namespaceSelector"=>{"matchLabels"=>{"kubernetes.io/metadata.name"=>"node-operator"}},"podSelector"=>{"matchLabels"=>{"app.kubernetes.io/name"=>"prysm-beacon"}}}],"ports"=>[{"protocol"=>"TCP","port"=>3500}]},{"to"=>[{"podSelector"=>{"matchLabels"=>{"app.kubernetes.io/component"=>"validator-signing-fence"}}}],"ports"=>[{"protocol"=>"TCP","port"=>9001}]}]
abort "Vault egress is broader than the reviewed boundary" unless policy.dig("spec","egress")==expected
' "$policy"
printf '%s\n' 'PASS: validator cutover restores signer only; client and fence stay zero until activation.'
