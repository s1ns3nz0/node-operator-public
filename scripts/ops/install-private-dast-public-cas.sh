#!/usr/bin/env bash
set -euo pipefail

usage() { printf 'Usage: %s --signer-ca <absolute-public-pem>\n' "${0##*/}" >&2; exit 64; }
signer_ca=''
while [ "$#" -gt 0 ]; do
  case "$1" in
    --signer-ca) signer_ca="${2:-}"; shift 2 ;;
    *) usage ;;
  esac
done
[[ "$signer_ca" = /* && -f "$signer_ca" ]] || usage

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
if [ "${PRIVATE_EKS_SESSION:-}" != 1 ]; then
  exec "$root/scripts/ops/with-private-eks.sh" -- env PRIVATE_EKS_SESSION=1 "$0" --signer-ca "$signer_ca"
fi

for command in kubectl openssl mktemp; do command -v "$command" >/dev/null 2>&1 || { printf 'missing command: %s\n' "$command" >&2; exit 69; }; done
signer_certificate="$(mktemp "${TMPDIR:-/tmp}/node-operator-signer-public-ca.XXXXXX")"
cleanup() { rm -f "$signer_certificate"; }
trap cleanup EXIT

if grep -Eq -- '-----BEGIN ([A-Z ]* )?PRIVATE KEY-----' "$signer_ca"; then
  printf 'refusing PEM that contains a private key\n' >&2
  exit 1
fi
# Canonicalize only a parsed signer X.509 certificate. This prevents trailing
# non-certificate material from entering validator-operations.
openssl x509 -in "$signer_ca" -out "$signer_certificate"
# Compatibility filename retained after DAST retirement: this installer now
# supplies only the GET-only signer proxy beside the signer.
kubectl -n validator-operations create configmap validator-hoodi-example-signer-ca --from-file=ca.crt="$signer_certificate" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
printf 'PASS: installed only the signer public CA for the upcheck proxy.\n'
