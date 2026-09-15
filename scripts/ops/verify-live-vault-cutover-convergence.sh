#!/usr/bin/env bash
set -euo pipefail
umask 077

# Read-only final convergence gate.  It consumes only non-secret evidence and
# invokes the finalized metadata preflight; it never reopens Vault or reads a
# Kubernetes Secret value.
dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
usage() { printf 'Usage: %s --validator-set <hoodi-id> --engine-evidence <absolute-json> --validator-evidence <absolute-json> --finalization-evidence <absolute-json> --evidence-output <new-absolute-json>\n' "${0##*/}" >&2; exit 64; }
validator_set=''; engine=''; validator=''; finalization=''; evidence=''
while [ "$#" -gt 0 ]; do case "$1" in
  --validator-set) validator_set="${2:-}"; shift 2 ;;
  --engine-evidence) engine="${2:-}"; shift 2 ;;
  --validator-evidence) validator="${2:-}"; shift 2 ;;
  --finalization-evidence) finalization="${2:-}"; shift 2 ;;
  --evidence-output) evidence="${2:-}"; shift 2 ;;
  *) usage ;;
esac; done
case "$validator_set" in hoodi-[a-z0-9][a-z0-9-]*) ;; *) usage ;; esac
case "$engine:$validator:$finalization:$evidence" in /*:/*:/*:/*) ;; *) usage ;; esac
for file in "$engine" "$validator" "$finalization"; do [ -f "$file" ] && [ ! -L "$file" ] || { printf 'invalid evidence input: %s\n' "$file" >&2; exit 65; }; done
[ ! -e "$evidence" ] && [ ! -L "$evidence" ] || { printf '%s\n' 'evidence output must be new' >&2; exit 65; }
if [ "${PRIVATE_EKS_SESSION:-}" != 1 ]; then
  exec "$dir/with-private-eks.sh" -- env PRIVATE_EKS_SESSION=1 "$0" --validator-set "$validator_set" --engine-evidence "$engine" --validator-evidence "$validator" --finalization-evidence "$finalization" --evidence-output "$evidence"
fi
for command in jq mktemp rm date; do command -v "$command" >/dev/null 2>&1 || { printf 'missing command: %s\n' "$command" >&2; exit 69; }; done
jq -e '.operation == "live-engine-vault-cutover" and .vault_agent_init_succeeded == true and .secret_values_emitted == false' "$engine" >/dev/null
jq -e --arg set "$validator_set" '.operation == "live-validator-vault-cutover" and .validator_set == $set and .signer_vault_init_succeeded == true and .secret_values_emitted == false' "$validator" >/dev/null
jq -e --arg set "$validator_set" '.operation == "live-vault-legacy-secret-finalization" and .validator_set == $set and .vault_agent_ca_retained == true and .known_clients_configmap_retained == true and .secret_values_emitted == false' "$finalization" >/dev/null
preflight="$(mktemp /private/tmp/node-operator-finalized-preflight.XXXXXX)"; rm -f "$preflight"
trap 'rm -f "$preflight"' EXIT INT TERM
PRIVATE_EKS_SESSION=1 "$dir/preflight-live-vault-cutover.sh" --validator-set "$validator_set" --phase finalized --evidence-output "$preflight" >/dev/null
jq -e --arg set "$validator_set" '.operation == "live-vault-cutover-preflight" and .phase == "finalized" and .validator_set == $set and .engine_vault_egress_ready == true and .legacy_credential_secrets_absent == true and .secret_values_emitted == false' "$preflight" >/dev/null
mkdir -p "$(dirname "$evidence")"
jq -n --arg at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --arg set "$validator_set" \
  '{schema_version:1,operation:"live-vault-cutover-convergence",completed_at_utc:$at,validator_set:$set,engine_vault_injected:true,validator_vault_injected:true,legacy_credential_secrets_absent:true,public_trust_material_retained:true,engine_vault_egress_ready:true,secret_values_emitted:false}' > "$evidence"
chmod 600 "$evidence"
printf 'PASS: final convergence verified Engine and validator Vault injection, policy egress, and removal of superseded credential Secrets. Evidence: %s\n' "$evidence"
