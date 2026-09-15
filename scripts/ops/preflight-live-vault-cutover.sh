#!/usr/bin/env bash
set -euo pipefail
umask 077

# Read-only cutover gate. It deliberately inventories names, keys, versions,
# health, and policy selectors only; it never fetches Secret data values.
dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
usage() { printf 'Usage: %s --validator-set <hoodi-id> --evidence-output <new-absolute-json> [--phase baseline|ready|finalized]\n' "${0##*/}" >&2; exit 64; }
validator_set=''; evidence=''; phase='baseline'
while [ "$#" -gt 0 ]; do case "$1" in --validator-set) validator_set="${2:-}"; shift 2;; --evidence-output) evidence="${2:-}"; shift 2;; --phase) phase="${2:-}"; shift 2;; *) usage;; esac; done
case "$validator_set:$evidence" in hoodi-[a-z0-9][a-z0-9-]*:/*) ;; *) usage;; esac
case "$phase" in baseline|ready|finalized) ;; *) usage;; esac
[ ! -e "$evidence" ] && [ ! -L "$evidence" ] || { printf '%s\n' 'evidence output must be new' >&2; exit 65; }
if [ "${PRIVATE_EKS_SESSION:-}" != 1 ]; then exec "$dir/with-private-eks.sh" -- env PRIVATE_EKS_SESSION=1 "$0" --validator-set "$validator_set" --evidence-output "$evidence"; fi
for command in kubectl jq mkdir date; do command -v "$command" >/dev/null 2>&1 || { printf 'missing command: %s\n' "$command" >&2; exit 69; }; done

require_ready() {
  local namespace="$1" kind="$2" name="$3" object ready
  object="$(kubectl -n "$namespace" get "$kind" "$name" -o json)"
  ready="$(jq -r 'if .kind == "Deployment" then ((.status.readyReplicas // 0) == (.spec.replicas // 1)) elif .kind == "StatefulSet" then ((.status.readyReplicas // 0) == (.spec.replicas // 1)) else false end' <<<"$object")"
  [ "$ready" = true ] || { printf 'not ready: %s/%s\n' "$kind" "$name" >&2; exit 65; }
}
require_ready vault StatefulSet vault
require_ready vault Deployment vault-agent-injector
require_ready node-operator StatefulSet nethermind-execution
require_ready node-operator StatefulSet prysm-beacon
require_ready validator-operations Deployment "validator-${validator_set}-remote-signer"
require_ready validator-operations StatefulSet "validator-${validator_set}-client"

for target in \
  'node-operator|engine-api-jwt|jwt|legacy' \
  "validator-operations|validator-${validator_set}-signer-tls|tls-password.txt,tls.p12|legacy" \
  "validator-operations|validator-${validator_set}-client-tls|ca.crt,tls.crt,tls.key|legacy" \
  'validator-operations|vault-agent-ca|ca.crt|public'; do
  IFS='|' read -r namespace name expected classification <<<"$target"
  if [ "$phase" = finalized ] && [ "$classification" = legacy ]; then
    test -z "$(kubectl -n "$namespace" get secret "$name" --ignore-not-found -o name)" || { printf 'legacy credential Secret still exists after finalization: %s/%s\n' "$namespace" "$name" >&2; exit 65; }
  else
    observed="$(kubectl -n "$namespace" get secret "$name" -o json | jq -r '[.data | keys[]] | sort | join(",")')"
    [ "$observed" = "$expected" ] || { printf 'unexpected Secret key inventory: %s/%s\n' "$namespace" "$name" >&2; exit 65; }
  fi
done

app="$(kubectl -n argocd get application node-operator-client -o json)"
jq -e '.status.sync.status == "Synced" and .status.health.status == "Healthy" and .spec.source.chart == "node-operator-client" and (.spec.source.targetRevision | test("^0\\.1\\.[0-9]+$"))' <<<"$app" >/dev/null
network="$(kubectl -n node-operator get networkpolicy allow-client-egress -o json)"
vault_egress=false
if jq -e '[.spec.egress[]?.to[]? | select(.namespaceSelector.matchLabels["kubernetes.io/metadata.name"] == "vault") | .podSelector.matchLabels["app.kubernetes.io/name"] == "vault"] | any' <<<"$network" >/dev/null; then vault_egress=true; fi
[ "$phase" = baseline ] || [ "$vault_egress" = true ] || { printf '%s\n' 'Engine client Vault egress policy is absent' >&2; exit 65; }

mkdir -p "$(dirname "$evidence")"
  jq -n --arg set "$validator_set" --arg phase "$phase" --arg revision "$(jq -r '.spec.source.targetRevision' <<<"$app")" --arg collected "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --argjson vault_egress "$vault_egress" \
  '{schema_version:1,operation:"live-vault-cutover-preflight",phase:$phase,validator_set:$set,collected_at_utc:$collected,argocd_revision:$revision,vault_active:true,vault_injector_ready:true,engine_pair_ready:true,validator_signer_ready:true,validator_client_ready:true,engine_vault_egress_ready:$vault_egress,source_secret_key_inventory_only:true,legacy_credential_secrets_absent:($phase == "finalized"),secret_values_emitted:false}' > "$evidence"
chmod 600 "$evidence"
printf 'PASS: live Vault cutover preflight passed without reading Secret values. Evidence: %s\n' "$evidence"
