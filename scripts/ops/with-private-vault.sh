#!/usr/bin/env bash
set -euo pipefail

# Extends with-private-eks.sh with a CA-validated, short-lived Vault port
# forward. The Vault CA is public; no token, private key, or Secret data is
# read or printed by this wrapper.
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
usage() {
  printf 'Usage: %s -- <command> [arguments...]\n' "${0##*/}" >&2
  exit 64
}
[ "${1:-}" = -- ] || usage
shift
[ "$#" -gt 0 ] || usage

exec "$root/scripts/ops/with-private-eks.sh" -- env PRIVATE_EKS_SESSION=1 \
  bash -c '
    set -euo pipefail
    for command in kubectl nc mktemp unlink; do
      command -v "$command" >/dev/null 2>&1 || { printf "missing command: %s\\n" "$command" >&2; exit 69; }
    done
    vault_port="${PRIVATE_VAULT_LOCAL_PORT:-18200}"
    vault_target="${PRIVATE_VAULT_TARGET:-service/vault-active}"
    port_log="$(mktemp /private/tmp/node-operator-vault-port.XXXXXX)"
    ca_file="$(mktemp /private/tmp/node-operator-vault-ca.XXXXXX)"
    port_pid=""
    cleanup() {
      set +e
      if [ -n "$port_pid" ]; then kill -TERM "$port_pid" 2>/dev/null || true; wait "$port_pid" 2>/dev/null || true; fi
      unlink "$port_log" "$ca_file" 2>/dev/null || true
    }
    trap cleanup EXIT
    kubectl -n vault exec vault-0 -- sh -c "dd if=/vault/userconfig/vault-tls/ca.crt 2>/dev/null" > "$ca_file"
    chmod 600 "$ca_file"
    kubectl -n vault port-forward "$vault_target" "${vault_port}:8200" >"$port_log" 2>&1 &
    port_pid=$!
    for attempt in $(seq 1 20); do nc -z 127.0.0.1 "$vault_port" 2>/dev/null && break; sleep 1; done
    nc -z 127.0.0.1 "$vault_port" >/dev/null
    VAULT_ADDR="https://127.0.0.1:${vault_port}" VAULT_CACERT="$ca_file" VAULT_TLS_SERVER_NAME="vault.vault.svc" "$@"
  ' -- "$@"
