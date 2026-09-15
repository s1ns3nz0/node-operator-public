#!/usr/bin/env bash
# Verify already-read Vault transport records before publishing their public trust outputs.
set +x
set -euo pipefail
umask 077

usage() {
  printf 'Usage: %s --validator-set <hoodi-id> --signer-record <absolute-file> --client-record <absolute-file> --scratch-dir <absolute-directory> --output-dir <new-absolute-directory>\n' "${0##*/}" >&2
  exit 64
}

validator_set=''; signer_record=''; client_record=''; scratch=''; output=''
while [ "$#" -gt 0 ]; do
  case "$1" in
    --validator-set) validator_set="${2:-}"; shift 2 ;;
    --signer-record) signer_record="${2:-}"; shift 2 ;;
    --client-record) client_record="${2:-}"; shift 2 ;;
    --scratch-dir) scratch="${2:-}"; shift 2 ;;
    --output-dir) output="${2:-}"; shift 2 ;;
    *) usage ;;
  esac
done

[[ "$validator_set" =~ ^hoodi-[a-z0-9][a-z0-9-]{0,35}$ ]] || usage
for path in "$signer_record" "$client_record"; do
  [[ "$path" = /* ]] && [ -f "$path" ] && [ ! -L "$path" ] || usage
done
[[ "$scratch" = /* ]] && [ -d "$scratch" ] && [ ! -L "$scratch" ] || usage
[[ "$output" = /* ]] && [ ! -e "$output" ] && [ ! -L "$output" ] || usage
for command in jq openssl cmp install mkdir; do command -v "$command" >/dev/null 2>&1 || exit 69; done
if ! openssl version | grep -q '^OpenSSL 3\.'; then
  if [ -x /opt/homebrew/opt/openssl@3/bin/openssl ]; then
    PATH="/opt/homebrew/opt/openssl@3/bin:$PATH"
  elif [ -x /usr/local/opt/openssl@3/bin/openssl ]; then
    PATH="/usr/local/opt/openssl@3/bin:$PATH"
  fi
fi
openssl version | grep -q '^OpenSSL 3\.' || {
  printf '%s\n' 'OpenSSL 3 is required; install openssl@3 before starting this ceremony.' >&2
  exit 69
}

server="validator-$validator_set-remote-signer.validator-operations.svc"
client="validator-$validator_set-client.validator-operations.svc"

strict_b64_decode() {
  local json_file="$1" field="$2" encoded_file="$3" decoded_file="$4"
  jq -er --arg field "$field" '
    .[$field] | select(type == "string" and length > 0 and test("^[A-Za-z0-9+/]+={0,2}$"))
  ' "$json_file" > "$encoded_file" || return 1
  if ! openssl base64 -d -A -in "$encoded_file" -out "$decoded_file"; then return 1; fi
  [ "$(openssl base64 -e -A -in "$decoded_file")" = "$(<"$encoded_file")" ]
}

jq -e 'type == "object" and (keys | sort == ["password", "pkcs12_b64"]) and (.password | type == "string" and length > 0)' "$signer_record" >/dev/null || { printf '%s\n' 'stored signer TLS record is malformed' >&2; exit 65; }
jq -e 'type == "object" and (keys | sort == ["ca_crt_b64", "tls_crt_b64", "tls_key_b64"])' "$client_record" >/dev/null || { printf '%s\n' 'stored client TLS record is malformed' >&2; exit 65; }
strict_b64_decode "$signer_record" pkcs12_b64 "$scratch/signer-pkcs12.b64" "$scratch/server.p12" || { printf '%s\n' 'stored signer TLS PKCS#12 is not strict base64' >&2; exit 65; }
jq -er '.password | select(type == "string" and length > 0)' "$signer_record" > "$scratch/password"
openssl pkcs12 -in "$scratch/server.p12" -passin "file:$scratch/password" -clcerts -nokeys -out "$scratch/server.crt" >/dev/null 2>&1
openssl pkcs12 -in "$scratch/server.p12" -passin "file:$scratch/password" -nocerts -noenc -out "$scratch/server.key" >/dev/null 2>&1
strict_b64_decode "$client_record" tls_crt_b64 "$scratch/client-crt.b64" "$scratch/client.crt" || { printf '%s\n' 'stored client certificate is not strict base64' >&2; exit 65; }
strict_b64_decode "$client_record" tls_key_b64 "$scratch/client-key.b64" "$scratch/client.key" || { printf '%s\n' 'stored client key is not strict base64' >&2; exit 65; }
strict_b64_decode "$client_record" ca_crt_b64 "$scratch/client-ca.b64" "$scratch/ca.crt" || { printf '%s\n' 'stored client CA is not strict base64' >&2; exit 65; }
openssl verify -CAfile "$scratch/ca.crt" -purpose sslserver -verify_hostname "$server" "$scratch/server.crt" >/dev/null
openssl verify -CAfile "$scratch/ca.crt" -purpose sslclient "$scratch/client.crt" >/dev/null
[ "$(openssl x509 -in "$scratch/client.crt" -noout -subject -nameopt RFC2253)" = "subject=CN=$client" ] || { printf '%s\n' 'stored client certificate does not have the exact expected identity' >&2; exit 65; }
for identity in server client; do openssl x509 -in "$scratch/$identity.crt" -checkend 86400 -noout >/dev/null; done
for identity in server client; do
  openssl x509 -in "$scratch/$identity.crt" -pubkey -noout > "$scratch/cert-public"
  openssl pkey -in "$scratch/$identity.key" -pubout > "$scratch/key-public"
  cmp "$scratch/cert-public" "$scratch/key-public" >/dev/null
done
fingerprint="$(openssl x509 -in "$scratch/client.crt" -noout -fingerprint -sha256)"
fingerprint="${fingerprint#*=}"
mkdir -m 700 "$output"
install -m 644 "$scratch/ca.crt" "$output/signer-ca.crt"
printf '%s %s\n' "$client" "$fingerprint" > "$output/known-clients.txt"
