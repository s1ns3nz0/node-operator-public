#!/usr/bin/env bash
set -euo pipefail
umask 077

# Purpose: prepare cert-manager-managed Vault listener TLS before the first
# Vault StatefulSet is installed. This helper is intentionally narrow: it
# never initializes Vault, reads certificate bytes, or mutates an existing
# Vault installation.
usage() {
  printf '%s\n' "usage: ${0##*/} --manifest ABSOLUTE_FILE" >&2
  exit 64
}

manifest=''
while [ "$#" -gt 0 ]; do
  case "$1" in
    --manifest) [ -z "$manifest" ] || usage; manifest="${2:-}"; shift 2 ;;
    *) usage ;;
  esac
done
[[ "$manifest" = /* ]] && [ -f "$manifest" ] && [ ! -L "$manifest" ] || usage
command -v kubectl >/dev/null 2>&1 || { printf '%s\n' 'missing command: kubectl' >&2; exit 69; }

for deployment in cert-manager cert-manager-webhook cert-manager-cainjector; do
  kubectl -n cert-manager rollout status "deployment/$deployment" --timeout=10m
done
for crd in certificates.cert-manager.io issuers.cert-manager.io; do
  kubectl wait --for=condition=Established "crd/$crd" --timeout=5m
done

namespace="$(kubectl get namespace vault --ignore-not-found -o name)"
if [ -n "$namespace" ] && [ -n "$(kubectl -n vault get statefulset vault --ignore-not-found -o name)" ]; then
  # An existing Vault may be OnDelete, sealed, or uninitialized. Those are
  # post-install lifecycle states; this TLS-only phase checks certificates only.
  kubectl -n vault wait --for=condition=Ready certificate/vault-internal-ca --timeout=10m
  kubectl -n vault wait --for=condition=Ready certificate/vault-server-tls --timeout=10m
  kubectl -n vault get secret vault-tls -o name | grep -qx 'secret/vault-tls'
  printf '%s\n' 'PASS: existing Vault TLS prerequisites are ready; no bootstrap mutation was performed.'
  exit 0
fi

if [ -z "$namespace" ]; then
  kubectl create namespace vault
fi
kubectl label namespace vault --overwrite \
  pod-security.kubernetes.io/enforce=restricted \
  pod-security.kubernetes.io/enforce-version=latest \
  pod-security.kubernetes.io/audit=restricted \
  pod-security.kubernetes.io/audit-version=latest \
  pod-security.kubernetes.io/warn=restricted \
  pod-security.kubernetes.io/warn-version=latest

kubectl apply -f "$manifest"
for certificate in vault-internal-ca vault-server-tls; do
  kubectl -n vault wait --for=condition=Ready "certificate/$certificate" --timeout=10m
done
kubectl -n vault get secret vault-tls -o name | grep -qx 'secret/vault-tls'
printf '%s\n' 'PASS: cert-manager prepared Vault TLS prerequisites; Vault installation and initialization remain the next integrated phase.'
