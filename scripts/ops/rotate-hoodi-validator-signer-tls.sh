#!/usr/bin/env bash
set -euo pipefail
umask 077

# Rotates one complete transport-identity generation: signer PKCS#12, validator
# client certificate/key/CA, and the public known-clients ConfigMap. The client
# must be fenced at zero, so a partial attempt cannot create a double-signer.
dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
usage() { printf 'Usage: %s --validator-set <hoodi-id> --current-ca <absolute-pem> --previous-ca-output <absolute-pem> --new-ca-output <absolute-pem>\n' "${0##*/}" >&2; exit 64; }
validator_set=''; current_ca=''; previous_ca_output=''; new_ca_output=''
while [ "$#" -gt 0 ]; do case "$1" in
  --validator-set) validator_set="${2:-}"; shift 2 ;;
  --current-ca) current_ca="${2:-}"; shift 2 ;;
  --previous-ca-output) previous_ca_output="${2:-}"; shift 2 ;;
  --new-ca-output) new_ca_output="${2:-}"; shift 2 ;;
  *) usage ;;
esac; done
case "$validator_set" in hoodi-[a-z0-9][a-z0-9-]*) ;; *) usage ;; esac
case "$current_ca:$previous_ca_output:$new_ca_output" in /*:/*:/*) ;; *) usage ;; esac
[ "$current_ca" != "$previous_ca_output" ] && [ "$current_ca" != "$new_ca_output" ] && [ "$previous_ca_output" != "$new_ca_output" ] || usage
if [ "${PRIVATE_VAULT_SESSION:-}" != 1 ]; then exec "$dir/with-private-vault.sh" -- env PRIVATE_VAULT_SESSION=1 "$0" --validator-set "$validator_set" --current-ca "$current_ca" --previous-ca-output "$previous_ca_output" --new-ca-output "$new_ca_output"; fi
for command in vault kubectl jq openssl base64 install mktemp find seq tr python3 sed grep; do command -v "$command" >/dev/null 2>&1 || { printf 'missing command: %s\n' "$command" >&2; exit 69; }; done
[ -s "$current_ca" ] && openssl x509 -in "$current_ca" -noout >/dev/null 2>&1 || { printf '%s\n' 'current public CA is not a certificate' >&2; exit 65; }
for output in "$previous_ca_output" "$new_ca_output"; do [ ! -e "$output" ] && [ ! -L "$output" ] || { printf 'refusing existing output: %s\n' "$output" >&2; exit 65; }; install -d -m 700 "$(dirname "$output")"; done

namespace='validator-operations'; client_stateful="validator-${validator_set}-client"; signer="validator-${validator_set}-remote-signer"; known="validator-${validator_set}-known-clients"
deployments="$(kubectl -n "$namespace" get deployments -o json)" || { printf '%s\n' 'cannot prove validator client deployment state' >&2; exit 69; }
replicas="$(jq -er --arg name "$client_stateful" '[.items[] | select(.metadata.name == $name) | (.spec.replicas // 0)] | if length == 0 then 0 elif length == 1 then .[0] else error("duplicate") end' <<<"$deployments")"
[ "$replicas" = 0 ] || { printf '%s\n' 'validator client must be scaled to zero before TLS rotation' >&2; exit 65; }
stateful_replicas="$(kubectl -n "$namespace" get statefulset "$client_stateful" --ignore-not-found -o jsonpath='{.spec.replicas}')" || { printf '%s\n' 'cannot prove validator client StatefulSet state' >&2; exit 69; }
[ -z "$stateful_replicas" ] || [ "$stateful_replicas" = 0 ] || { printf '%s\n' 'validator client StatefulSet must be scaled to zero before TLS rotation' >&2; exit 65; }
pods="$(kubectl -n "$namespace" get pods -l "app.kubernetes.io/component=validator-client,node-operator.io/validator-set=${validator_set}" -o json)" || { printf '%s\n' 'cannot prove validator client Pod absence' >&2; exit 69; }
jq -e '.items | length == 0' <<<"$pods" >/dev/null || { printf '%s\n' 'validator client Pod remains; TLS rotation refused' >&2; exit 65; }

scratch="$(mktemp -d /private/tmp/node-operator-transport-tls-rotation.XXXXXX)"; chmod 700 "$scratch"
started=false; complete=false; root_token=''; child_token=''; child_accessor=''; policy_created=false
suffix="${scratch##*.}"; [[ "$suffix" =~ ^[A-Za-z0-9]+$ ]] || exit 70
policy="hoodi-${validator_set}-tls-rotation-${suffix}"
cleanup() {
  status=$?; trap - EXIT; set +e; failed=false
  [ -z "$child_accessor" ] || VAULT_TOKEN="$root_token" vault token revoke -accessor "$child_accessor" >/dev/null 2>&1 || failed=true
  [ "$policy_created" = false ] || VAULT_TOKEN="$root_token" vault policy delete "$policy" >/dev/null 2>&1 || failed=true
  [ -z "$root_token" ] || VAULT_TOKEN="$root_token" vault token revoke -self >/dev/null 2>&1 || failed=true
  [ "$started" = true ] && [ "$complete" != true ] && vault operator generate-root -cancel >/dev/null 2>&1 || true
  find "$scratch" -type f -exec sh -c 'chmod 600 "$1" 2>/dev/null; : > "$1"; rm -f "$1"' sh {} \; 2>/dev/null; rmdir "$scratch" 2>/dev/null || true
  unset VAULT_TOKEN root_token child_token child_accessor
  [ "$failed" = false ] || exit 70
  exit "$status"
}
trap cleanup EXIT INT TERM
# shellcheck source=scripts/ops/lib/vault-recovery-auth.sh
source "$dir/lib/vault-recovery-auth.sh"; vault_recovery_auth_preflight
status="$(vault operator generate-root -status -format=json)"; [ "$(jq -r .started <<<"$status")" = false ] || { printf '%s\n' 'root-token ceremony already in progress' >&2; exit 75; }
initial="$(vault operator generate-root -init -format=json)"; started=true
nonce="$(jq -er .nonce <<<"$initial")"; otp="$(jq -er .otp <<<"$initial")"; required="$(jq -er .required <<<"$initial")"
for number in $(seq 1 "$required"); do printf 'Recovery key share %s of %s: ' "$number" "$required" >&2; IFS= read -r -s share; printf '\n' >&2; reply="$(printf %s "$share" | vault operator generate-root -nonce="$nonce" -format=json -)"; unset share; if [ "$(jq -r .complete <<<"$reply")" = true ]; then complete=true; encoded="$(jq -er .encoded_token <<<"$reply")"; break; fi; done
[ "$complete" = true ] || { printf '%s\n' 'recovery quorum was not reached' >&2; exit 77; }
root_token="$(vault_recovery_decode_generated_root "$encoded" "$otp")"; unset encoded otp nonce initial reply status
VAULT_TOKEN="$root_token" "$dir/bootstrap-node-operator-vault-v2.sh" >/dev/null
template="$dir/../../deploy/validator/vault/tls-rotation.hcl"; sed "s/REPLACE_WITH_VALIDATOR_SET/${validator_set}/g" "$template" > "$scratch/policy.hcl"
VAULT_TOKEN="$root_token" vault policy write "$policy" "$scratch/policy.hcl" >/dev/null; policy_created=true
child="$(VAULT_TOKEN="$root_token" vault token create -orphan -no-default-policy -policy="$policy" -ttl=10m -format=json)"; child_token="$(jq -er .auth.client_token <<<"$child")"; child_accessor="$(jq -er .auth.accessor <<<"$child")"; unset child
base="node-operator-runtime/validators/hoodi/${validator_set}/runtime"
signer_version="$(VAULT_TOKEN="$child_token" vault kv metadata get -format=json "$base/signer-tls" | jq -er '.data.current_version | select(. > 0)')"
client_version="$(VAULT_TOKEN="$child_token" vault kv metadata get -format=json "$base/client-tls" | jq -er '.data.current_version | select(. > 0)')"

server_issue="$(VAULT_TOKEN="$root_token" vault write -format=json node-operator-pki/issue/validator-mtls common_name="$signer.$namespace.svc" alt_names="$signer.$namespace.svc,$signer.$namespace.svc.cluster.local" ttl=720h)"
client_issue="$(VAULT_TOKEN="$root_token" vault write -format=json node-operator-pki/issue/validator-mtls common_name="validator-${validator_set}-client.$namespace.svc" ttl=720h)"
jq -er '.data.private_key' <<<"$server_issue" > "$scratch/server.key"
jq -er '.data.certificate' <<<"$server_issue" > "$scratch/server.crt"
jq -er '(.data.ca_chain[0] // .data.issuing_ca)' <<<"$server_issue" > "$scratch/ca.crt"
jq -er '.data.private_key' <<<"$client_issue" > "$scratch/client.key"
jq -er '.data.certificate' <<<"$client_issue" > "$scratch/client.crt"
unset server_issue client_issue
openssl verify -CAfile "$scratch/ca.crt" -purpose sslserver -verify_hostname "$signer.$namespace.svc" "$scratch/server.crt" >/dev/null
openssl verify -CAfile "$scratch/ca.crt" -purpose sslclient "$scratch/client.crt" >/dev/null
openssl rand -base64 48 | tr -d '\n' > "$scratch/password"
openssl pkcs12 -export -inkey "$scratch/server.key" -in "$scratch/server.crt" -certfile "$scratch/ca.crt" -name "$signer" -out "$scratch/tls.p12" -passout "file:$scratch/password"
password="$(<"$scratch/password")"
{ printf '{"pkcs12_b64":"'; base64 < "$scratch/tls.p12" | tr -d '\n'; printf '","password":"%s"}\n' "$password"; } > "$scratch/signer.json"; unset password
{ printf '{"tls_crt_b64":"'; base64 < "$scratch/client.crt" | tr -d '\n'; printf '","tls_key_b64":"'; base64 < "$scratch/client.key" | tr -d '\n'; printf '","ca_crt_b64":"'; base64 < "$scratch/ca.crt" | tr -d '\n'; printf '"}\n'; } > "$scratch/client.json"
install -m 600 "$current_ca" "$previous_ca_output"; install -m 644 "$scratch/ca.crt" "$new_ca_output"
VAULT_TOKEN="$child_token" vault kv put -cas="$signer_version" "$base/signer-tls" @"$scratch/signer.json" >/dev/null
VAULT_TOKEN="$child_token" vault kv put -cas="$client_version" "$base/client-tls" @"$scratch/client.json" >/dev/null
fingerprint="$(openssl x509 -in "$scratch/client.crt" -noout -fingerprint -sha256 | cut -d= -f2)"
printf 'validator-%s-client.%s.svc %s\n' "$validator_set" "$namespace" "$fingerprint" > "$scratch/known-clients"
kubectl -n "$namespace" create configmap "$known" --from-file="known-clients=$scratch/known-clients" --dry-run=client -o yaml | kubectl -n "$namespace" apply -f - >/dev/null
printf 'PASS: Vault PKI-issued signer/client leaf certificates rotated with CAS versions %s/%s; client remains fenced at zero until both workloads are restarted and verified.\n' "$signer_version" "$client_version"
