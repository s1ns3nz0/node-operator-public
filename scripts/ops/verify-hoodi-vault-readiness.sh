#!/usr/bin/env bash
set +x
set -euo pipefail

usage() { printf 'Usage: %s --mode sealed-deployment|post-init-ready\n' "${0##*/}" >&2; exit 64; }
[ "$#" -eq 2 ] && [ "$1" = --mode ] || usage
mode="$2"
case "$mode" in sealed-deployment|post-init-ready) ;; *) usage ;; esac
for command in kubectl jq mktemp rm sleep seq; do command -v "$command" >/dev/null 2>&1 || { printf 'missing command: %s\n' "$command" >&2; exit 69; }; done

attempts="${VAULT_READINESS_ATTEMPTS:-30}"; [[ "$attempts" =~ ^[1-9][0-9]?$ ]] || usage
pods=''
for attempt in $(seq 1 "$attempts"); do
  pods="$(kubectl --request-timeout=10s -n vault get pods -l app.kubernetes.io/name=vault,component=server -o json 2>/dev/null || :)"
  if jq -e '.items | type == "array" and length == 3 and all(.[]; .status.phase == "Running")' <<<"$pods" >/dev/null 2>&1; then
    if [ "$mode" = sealed-deployment ] || jq -e '.items | all(.[]; any(.status.conditions[]?; .type == "Ready" and .status == "True"))' <<<"$pods" >/dev/null 2>&1; then break; fi
  fi
  if [ "$attempt" -lt "$attempts" ]; then sleep 10; fi
done
jq -e '.items | type == "array" and length == 3 and all(.[]; .status.phase == "Running")' <<<"$pods" >/dev/null || { printf '%s\n' 'Vault server Pods did not become Running; reconcile the Helm release before retrying' >&2; exit 70; }
if [ "$mode" = post-init-ready ]; then jq -e '.items | all(.[]; any(.status.conditions[]?; .type == "Ready" and .status == "True"))' <<<"$pods" >/dev/null || { printf '%s\n' 'Vault server Pods did not become Ready after initialization; reconcile before custody' >&2; exit 70; }; fi

status_file="$(mktemp "${TMPDIR:-/tmp}/vault-status.XXXXXX")"
cleanup() { local rc=$?; rm -f "$status_file"; return "$rc"; }
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP
set +e
kubectl --request-timeout=10s -n vault exec vault-0 -c vault -- env VAULT_ADDR=https://127.0.0.1:8200 VAULT_CACERT=/vault/userconfig/vault-tls/ca.crt VAULT_TLS_SERVER_NAME=vault.vault.svc VAULT_CLIENT_TIMEOUT=10s vault status -format=json >"$status_file" 2>/dev/null
status_rc=$?
set -e
jq -e '.initialized | type == "boolean"' "$status_file" >/dev/null || { printf '%s\n' 'Vault TLS status response is malformed or unavailable' >&2; exit 70; }
if [ "$mode" = sealed-deployment ]; then
  if [ "$status_rc" -eq 2 ] && jq -e '.initialized == false and .sealed == true' "$status_file" >/dev/null; then
    printf '%s\n' 'PASS: Vault server Pods are Running and TLS status confirms sealed/uninitialized first-install state.'
  elif [ "$status_rc" -eq 0 ] && jq -e '.initialized == true and .sealed == false' "$status_file" >/dev/null; then
    printf '%s\n' 'PASS: Vault server Pods are Running and TLS status confirms an existing initialized/unsealed release.'
  else
    printf '%s\n' 'Vault status is neither a valid sealed first install nor an initialized/unsealed existing release' >&2; exit 70
  fi
else
  [ "$status_rc" -eq 0 ] && jq -e '.initialized == true and .sealed == false' "$status_file" >/dev/null || { printf '%s\n' 'Vault is not initialized and unsealed after the ceremony; custody remains blocked' >&2; exit 70; }
  printf '%s\n' 'PASS: all Vault server Pods are Ready and TLS status confirms initialized/unsealed state.'
fi
