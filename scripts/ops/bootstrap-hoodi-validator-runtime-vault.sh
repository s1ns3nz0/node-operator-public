#!/usr/bin/env bash
set -euo pipefail

# Admin-only authorization bootstrap. This never accepts or reads custody
# values. Use a short-lived admin token from the private Vault session only.
usage() { printf '%s\n' "Usage: ${0##*/} --validator-set <hoodi-id>" >&2; exit 64; }
validator_set=''
while [ "$#" -gt 0 ]; do case "$1" in --validator-set) validator_set="${2:-}"; shift 2 ;; *) usage ;; esac; done
case "$validator_set" in hoodi-[a-z0-9][a-z0-9-]*) ;; *) usage ;; esac
for command in vault sed mktemp unlink rmdir; do command -v "$command" >/dev/null 2>&1 || { printf 'missing command: %s\n' "$command" >&2; exit 69; }; done
: "${VAULT_ADDR:?VAULT_ADDR must name the private Vault endpoint}"
: "${VAULT_TOKEN:?Supply a short-lived Vault administrator token through the secure environment}"

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
template_dir="$root/deploy/validator/vault"
tmp="$(mktemp -d /private/tmp/node-operator-validator-vault.XXXXXX)"
cleanup() { set +e; unset VAULT_TOKEN; unlink "$tmp/onboarding.hcl" "$tmp/runtime.hcl" "$tmp/slashing-db.hcl" "$tmp/client-tls.hcl" "$tmp/role.json" "$tmp/slashing-db-role.json" "$tmp/client-tls-role.json" 2>/dev/null || true; rmdir "$tmp" 2>/dev/null || true; }
trap cleanup EXIT INT TERM
onboarding_policy="hoodi-${validator_set}-onboarding"
runtime_policy="hoodi-${validator_set}-runtime"
runtime_role="hoodi-${validator_set}-runtime"
slashing_db_policy="hoodi-${validator_set}-slashing-db"
slashing_db_role="hoodi-${validator_set}-slashing-db"
client_tls_policy="hoodi-${validator_set}-client-tls"
client_tls_role="hoodi-${validator_set}-client-tls"
sed "s/REPLACE_WITH_VALIDATOR_SET/${validator_set}/g" "$template_dir/onboarding-write.hcl" > "$tmp/onboarding.hcl"
sed "s/REPLACE_WITH_VALIDATOR_SET/${validator_set}/g" "$template_dir/runtime-read.hcl" > "$tmp/runtime.hcl"
sed "s/REPLACE_WITH_VALIDATOR_SET/${validator_set}/g" "$template_dir/slashing-db-read.hcl" > "$tmp/slashing-db.hcl"
sed "s/REPLACE_WITH_VALIDATOR_SET/${validator_set}/g" "$template_dir/client-tls-read.hcl" > "$tmp/client-tls.hcl"
sed "s/REPLACE_WITH_RUNTIME_POLICY/${runtime_policy}/g" "$template_dir/runtime-kubernetes-auth-role.json" > "$tmp/role.json"
sed "s/REPLACE_WITH_SLASHING_DB_POLICY/${slashing_db_policy}/g" "$template_dir/slashing-db-kubernetes-auth-role.json" > "$tmp/slashing-db-role.json"
sed "s/REPLACE_WITH_CLIENT_TLS_POLICY/${client_tls_policy}/g" "$template_dir/client-tls-kubernetes-auth-role.json" > "$tmp/client-tls-role.json"

vault read -format=json auth/kubernetes/config >/dev/null
"$root/scripts/ops/ensure-node-operator-runtime-kv-v2.sh" >/dev/null
vault policy write "$onboarding_policy" "$tmp/onboarding.hcl" >/dev/null
vault policy write "$runtime_policy" "$tmp/runtime.hcl" >/dev/null
vault policy write "$slashing_db_policy" "$tmp/slashing-db.hcl" >/dev/null
vault policy write "$client_tls_policy" "$tmp/client-tls.hcl" >/dev/null
vault write "auth/kubernetes/role/${runtime_role}" @"$tmp/role.json" >/dev/null
vault write "auth/kubernetes/role/${slashing_db_role}" @"$tmp/slashing-db-role.json" >/dev/null
vault write "auth/kubernetes/role/${client_tls_role}" @"$tmp/client-tls-role.json" >/dev/null
printf 'PASS: runtime-only Vault policy and Kubernetes auth role created for %s.\n' "$validator_set"
printf '%s\n' 'Issue the one-time custody credential outside this script; never place it in shell history, Git, CI, or Kubernetes.'
