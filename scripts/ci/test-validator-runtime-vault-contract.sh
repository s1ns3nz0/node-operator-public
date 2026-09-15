#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
vault_dir="$root/deploy/validator/vault"
grep -Fq 'runtime/keystore' "$vault_dir/runtime-read.hcl"
grep -Fq 'runtime/signer-tls' "$vault_dir/runtime-read.hcl"
grep -Fq 'capabilities = ["read"]' "$vault_dir/slashing-db-read.hcl"
if grep -Eq '^path .*?(keystore|runtime/password|signer-tls)' "$vault_dir/slashing-db-read.hcl"; then printf '%s\n' 'slashing DB policy may read signer material' >&2; exit 1; fi
grep -Fq 'validator-slashing-db' "$vault_dir/slashing-db-kubernetes-auth-role.json"
grep -Fq 'validator-remote-signer' "$vault_dir/runtime-kubernetes-auth-role.json"
# shellcheck disable=SC2016 # Literal source-contract assertion.
grep -Fq 'vault policy write "$slashing_db_policy"' "$root/scripts/ops/bootstrap-hoodi-validator-runtime-vault.sh"
printf '%s\n' 'PASS: signer and slashing database have separate least-privilege Vault roles.'
