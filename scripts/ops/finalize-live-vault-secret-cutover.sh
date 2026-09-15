#!/usr/bin/env bash
set -euo pipefail
umask 077

# Irreversible finalization, intentionally separate from the staged rollout.
# Delete only the three superseded credential Secrets after every consumer is
# demonstrated to use its narrowly scoped Vault Agent role.
dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
usage() { printf 'Usage: %s --validator-set <hoodi-id> --engine-evidence <absolute-json> --validator-evidence <absolute-json> --evidence-output <new-absolute-json> --execute\n' "${0##*/}" >&2; exit 64; }
validator_set=''; engine_evidence=''; validator_evidence=''; evidence=''; execute=false
while [ "$#" -gt 0 ]; do
  case "$1" in
    --validator-set) validator_set="${2:-}"; shift 2 ;;
    --engine-evidence) engine_evidence="${2:-}"; shift 2 ;;
    --validator-evidence) validator_evidence="${2:-}"; shift 2 ;;
    --evidence-output) evidence="${2:-}"; shift 2 ;;
    --execute) execute=true; shift ;;
    *) usage ;;
  esac
done
case "$validator_set" in hoodi-[a-z0-9][a-z0-9-]*) ;; *) usage ;; esac
case "$engine_evidence:$validator_evidence:$evidence" in /*:/*:/*) ;; *) usage ;; esac
[ "$execute" = true ] || usage
for file in "$engine_evidence" "$validator_evidence"; do [ -f "$file" ] && [ ! -L "$file" ] || { printf 'invalid evidence input: %s\n' "$file" >&2; exit 65; }; done
[ ! -e "$evidence" ] && [ ! -L "$evidence" ] || { printf '%s\n' 'evidence output must be a new regular path' >&2; exit 65; }
if [ "${PRIVATE_EKS_SESSION:-}" != 1 ]; then
  exec "$dir/with-private-eks.sh" -- env PRIVATE_EKS_SESSION=1 "$0" --validator-set "$validator_set" --engine-evidence "$engine_evidence" --validator-evidence "$validator_evidence" --evidence-output "$evidence" --execute
fi
for command in kubectl jq mkdir date; do command -v "$command" >/dev/null 2>&1 || { printf 'missing command: %s\n' "$command" >&2; exit 69; }; done
jq -e '.operation == "live-engine-vault-cutover" and .vault_agent_init_succeeded == true and .legacy_engine_jwt_secret_retained == true' "$engine_evidence" >/dev/null
jq -e --arg set "$validator_set" '.operation == "live-validator-vault-cutover" and .validator_set == $set and .signer_vault_init_succeeded == true and .legacy_tls_secrets_retained == true' "$validator_evidence" >/dev/null

require_vault_template() {
  local namespace="$1" kind="$2" name="$3" path="$4" legacy="$5" resource template pods
  resource="$(kubectl -n "$namespace" get "$kind" "$name" -o json)"
  jq -e --arg path "$path" '.spec.template.metadata.annotations["vault.hashicorp.com/agent-inject"] == "true" and ([.spec.template.metadata.annotations[]?] | any(. == $path))' <<<"$resource" >/dev/null || { printf 'Vault injection missing: %s/%s\n' "$kind" "$name" >&2; exit 65; }
  jq -e --arg legacy "$legacy" '[.spec.template.spec.volumes[]? | select(.secret.secretName == $legacy)] | length == 0' <<<"$resource" >/dev/null || { printf 'legacy Secret mount remains in template: %s/%s\n' "$kind" "$name" >&2; exit 65; }
  pods="$(kubectl -n "$namespace" get pods -l "node-operator.io/validator-set=${validator_set}" -o json 2>/dev/null || printf '{"items":[]}')"
  if [ "$namespace" = node-operator ]; then pods="$(kubectl -n "$namespace" get pods -l "app.kubernetes.io/name=${name}" -o json)"; fi
  jq -e --arg legacy "$legacy" 'all(.items[]?; [.spec.volumes[]? | .secret.secretName?] | index($legacy) | not)' <<<"$pods" >/dev/null || { printf 'legacy Secret mount remains in a live Pod: %s\n' "$legacy" >&2; exit 65; }
}

require_vault_template node-operator statefulset nethermind-execution 'node-operator-runtime/data/nodes/hoodi/engine-api-jwt' engine-api-jwt
require_vault_template node-operator statefulset prysm-beacon 'node-operator-runtime/data/nodes/hoodi/engine-api-jwt' engine-api-jwt
require_vault_template validator-operations deployment "validator-${validator_set}-remote-signer" "node-operator-runtime/data/validators/hoodi/${validator_set}/runtime/signer-tls" "validator-${validator_set}-signer-tls"
require_vault_template validator-operations statefulset "validator-${validator_set}-client" "node-operator-runtime/data/validators/hoodi/${validator_set}/runtime/client-tls" "validator-${validator_set}-client-tls"

# Never delete the public vault-agent-ca trust anchor or the public
# known-clients ConfigMap. Only the exact legacy credential objects are in scope.
kubectl -n node-operator delete secret engine-api-jwt --ignore-not-found >/dev/null
kubectl -n validator-operations delete secret "validator-${validator_set}-signer-tls" --ignore-not-found >/dev/null
kubectl -n validator-operations delete secret "validator-${validator_set}-client-tls" --ignore-not-found >/dev/null
for target in 'node-operator engine-api-jwt' "validator-operations validator-${validator_set}-signer-tls" "validator-operations validator-${validator_set}-client-tls"; do
  read -r namespace secret <<<"$target"
  test -z "$(kubectl -n "$namespace" get secret "$secret" --ignore-not-found -o name)" || { printf 'legacy Secret was not removed: %s/%s\n' "$namespace" "$secret" >&2; exit 70; }
done

mkdir -p "$(dirname "$evidence")"
jq -n --arg at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --arg set "$validator_set" \
  '{schema_version:1,operation:"live-vault-legacy-secret-finalization",completed_at_utc:$at,validator_set:$set,deleted_legacy_secrets:["node-operator/engine-api-jwt",("validator-operations/validator-"+$set+"-signer-tls"),("validator-operations/validator-"+$set+"-client-tls")],vault_agent_ca_retained:true,known_clients_configmap_retained:true,secret_values_emitted:false}' > "$evidence"
chmod 600 "$evidence"
printf 'PASS: legacy JWT and validator TLS Secrets were deleted only after all workloads proved Vault-injected templates. Evidence: %s\n' "$evidence"
