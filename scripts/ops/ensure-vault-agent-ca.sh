#!/usr/bin/env bash
set -euo pipefail
umask 077
dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"

# Copy only Vault's public CA certificate into workload namespaces.  Private
# server keys and runtime secret values never leave the Vault namespace.
usage() {
  printf 'Usage: %s --namespace <namespace> [--namespace <namespace> ...]\n' "${0##*/}" >&2
  exit 64
}

namespaces=()
original_args=("$@")
while [ "$#" -gt 0 ]; do
  case "$1" in
    --namespace) namespaces+=("${2:-}"); shift 2 ;;
    *) usage ;;
  esac
done
[ "${#namespaces[@]}" -gt 0 ] || usage
for namespace in "${namespaces[@]}"; do
  [[ "$namespace" =~ ^[a-z0-9]([-a-z0-9]*[a-z0-9])?$ ]] || usage
done

# The EKS API is private.  When called from a laptop, establish the same
# short-lived SSM tunnel used by the other operational helpers.
if [ "${PRIVATE_EKS_SESSION:-}" != 1 ]; then
  exec "$dir/with-private-eks.sh" -- env PRIVATE_EKS_SESSION=1 "$0" "${original_args[@]}"
fi

for command in kubectl jq base64 mktemp; do
  command -v "$command" >/dev/null 2>&1 || { printf 'missing command: %s\n' "$command" >&2; exit 69; }
done

ca_b64="$(kubectl -n vault get secret vault-tls -o json | jq -er '.data["ca.crt"]')"
# macOS uses `-D`, while GNU coreutils uses `--decode`.
if ! printf '%s' "$ca_b64" | base64 -D >/dev/null 2>&1; then
  printf '%s' "$ca_b64" | base64 --decode >/dev/null
fi
for namespace in "${namespaces[@]}"; do
  jq -n --arg namespace "$namespace" --arg ca "$ca_b64" \
    '{apiVersion:"v1",kind:"Secret",metadata:{name:"vault-agent-ca",namespace:$namespace},type:"Opaque",data:{"ca.crt":$ca}}' |
    kubectl apply -f - >/dev/null
done
printf 'PASS: Vault public CA trust anchor synchronized to %s namespace(s); no private material was copied.\n' "${#namespaces[@]}"
