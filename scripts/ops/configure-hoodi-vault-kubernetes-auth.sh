#!/usr/bin/env bash
set +x
set -euo pipefail
umask 077

# Configure the Kubernetes auth backend only for the Vault server's own pod.
# No reviewer JWT or CA value is accepted: with disable_local_ca_jwt=false the
# Kubernetes auth plugin uses the server pod's projected service-account token
# and CA bundle instead of persisting an expiring reviewer credential.
usage() { printf 'Usage: %s\n' "${0##*/}" >&2; exit 64; }
[ "$#" -eq 0 ] || usage
for command in vault jq mktemp rm chmod; do
  command -v "$command" >/dev/null 2>&1 || { printf 'missing command: %s\n' "$command" >&2; exit 69; }
done
: "${VAULT_ADDR:?VAULT_ADDR must name the private Vault endpoint}"
: "${VAULT_TOKEN:?VAULT_TOKEN must contain an authenticated Vault administrator token}"

fail() { printf '%s\n' "$1" >&2; exit 65; }
expected_host='https://kubernetes.default.svc:443'
error_file="$(mktemp "${TMPDIR:-/tmp}/node-operator-vault-kubernetes-auth.XXXXXX")"
chmod 600 "$error_file"
cleanup() { local rc=$?; rm -f "$error_file" || rc=70; unset VAULT_TOKEN; return "$rc"; }
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

mounts="$(vault auth list -format=json 2>/dev/null)" || fail 'cannot list Vault auth mounts'
jq -e 'type == "object"' <<<"$mounts" >/dev/null || fail 'Vault auth mount list is malformed'
if jq -e 'has("kubernetes/")' <<<"$mounts" >/dev/null; then
  jq -e '."kubernetes/" | type == "object" and .type == "kubernetes"' <<<"$mounts" >/dev/null ||
    fail 'existing kubernetes auth mount has an incompatible type; refusing to repoint it'
else
  vault auth enable -path=kubernetes kubernetes >/dev/null 2>&1 || fail 'failed to create Kubernetes auth mount'
fi

config=''
config_missing=false
if config="$(vault read -format=json auth/kubernetes/config 2>"$error_file")"; then
  :
else
  # Vault CLI reports an unconfigured, otherwise healthy backend with this
  # exact 404 diagnostic.  Transport, permission, and CLI errors remain
  # failures; they must never be mistaken for an absent configuration.
  read_error="$(<"$error_file")"
  if [ "$read_error" = 'No value found at auth/kubernetes/config' ]; then
    config_missing=true
  else
    fail 'cannot read Kubernetes auth configuration; refusing to overwrite an unknown backend state'
  fi
fi

if [ "$config_missing" = false ]; then
  jq -e --arg host "$expected_host" '
    .data | type == "object" and
    .kubernetes_host == $host and
    .disable_local_ca_jwt == false and
    .token_reviewer_jwt_set == false and
    ((.kubernetes_ca_cert // "") == "")
  ' <<<"$config" >/dev/null ||
    fail 'Kubernetes auth configuration is incompatible with server-local service-account review; refusing to repoint it'
else
  vault write auth/kubernetes/config \
    kubernetes_host="$expected_host" \
    disable_local_ca_jwt=false >/dev/null 2>&1 ||
    fail 'failed to configure Kubernetes auth with the Vault server local service account'
  config="$(vault read -format=json auth/kubernetes/config 2>"$error_file")" ||
    fail 'cannot read back Kubernetes auth configuration after setup'
  jq -e --arg host "$expected_host" '
    .data | type == "object" and
    .kubernetes_host == $host and
    .disable_local_ca_jwt == false and
    .token_reviewer_jwt_set == false and
    ((.kubernetes_ca_cert // "") == "")
  ' <<<"$config" >/dev/null ||
    fail 'Kubernetes auth readback differs from the required server-local configuration'
fi

# Re-list after an enable/write so success is not inferred from a stale list.
mounts="$(vault auth list -format=json 2>/dev/null)" || fail 'cannot verify Kubernetes auth mount after configuration'
jq -e '."kubernetes/" | type == "object" and .type == "kubernetes"' <<<"$mounts" >/dev/null ||
  fail 'Kubernetes auth mount is absent or changed after configuration'
printf '%s\n' 'PASS: Vault Kubernetes auth uses the server-local service account and CA; no reviewer token is stored.'
