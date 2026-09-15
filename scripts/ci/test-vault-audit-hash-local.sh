#!/usr/bin/env bash
# Check objective: prove local Vault audit-hash emits a request HMAC record.
set -euo pipefail
command -v vault >/dev/null; command -v jq >/dev/null
t="$(mktemp -d)"; trap 'kill "${pid:-}" 2>/dev/null || true; rm -rf "$t"' EXIT
port=$((19000 + RANDOM % 500)); token="local-test-$(openssl rand -hex 16)"; log="$t/vault.log"; audit="$t/audit.json"
VAULT_ADDR= VAULT_TOKEN= vault server -dev -dev-root-token-id="$token" -dev-listen-address="127.0.0.1:$port" >"$log" 2>&1 & pid=$!
for _ in $(seq 1 40); do VAULT_ADDR="http://127.0.0.1:$port" VAULT_TOKEN="$token" vault status >/dev/null 2>&1 && break; sleep .25; done
VAULT_ADDR="http://127.0.0.1:$port" VAULT_TOKEN="$token" vault status >/dev/null
VAULT_ADDR="http://127.0.0.1:$port" VAULT_TOKEN="$token" vault audit enable -path=validator-file file file_path="$audit" log_raw=false >/dev/null
marker="$(openssl rand -hex 32)"; hmac="$(VAULT_ADDR="http://127.0.0.1:$port" VAULT_TOKEN="$token" vault write -format=json sys/audit-hash/validator-file input="$marker" | jq -er '.data.hash')"
jq -e --arg h "$hmac" 'select(.type=="request") | .request | (.id|test("^[0-9a-f-]{36}$")) and .operation=="update" and .path=="sys/audit-hash/validator-file" and .data.input==$h' "$audit" >/dev/null
printf 'PASS local Vault audit-hash emitted an HMAC-bound request record.\n'
