#!/usr/bin/env bash

# Read-only compatibility preflight for recovery wrappers. This library is
# sourced by a caller that owns any later ceremony lifecycle and cancellation.
vault_recovery_auth_preflight() {
  # Never allow xtrace to expose a supplied or tty-entered token.
  set +x

  if ! command -v vault >/dev/null 2>&1 || ! command -v jq >/dev/null 2>&1; then
    printf '%s\n' 'Vault recovery preflight requires vault and jq' >&2
    return 69
  fi

  local status status_rc version major
  if status="$(vault status -format=json 2>/dev/null)"; then
    status_rc=0
  else
    status_rc=$?
  fi
  if [ "$status_rc" -ne 0 ]; then
    printf '%s\n' 'Vault status check failed; recovery preflight cannot continue' >&2
    return 1
  fi
  if ! jq -e '.initialized == true and .sealed == false and (.version | type == "string")' \
      <<<"$status" >/dev/null 2>&1; then
    printf '%s\n' 'Vault must be initialized, unsealed, and return a valid status document' >&2
    return 1
  fi
  version="$(jq -er '.version' <<<"$status" 2>/dev/null)" || {
    printf '%s\n' 'Vault status version is invalid' >&2
    return 1
  }
  if [[ ! "$version" =~ ^([12])\.[0-9]+\.[0-9]+([+-][0-9A-Za-z.-]+)?$ ]]; then
    printf '%s\n' 'Unsupported or malformed Vault version; recovery preflight fails closed' >&2
    return 1
  fi
  major="${BASH_REMATCH[1]}"

  if [ "$major" = 2 ] && [ -z "${VAULT_TOKEN:-}" ]; then
    # Device permissions alone do not prove a controlling terminal exists.
    # Open the actual device on a private descriptor and suppress its OS error.
    if ! { exec 9<>/dev/tty; } 2>/dev/null; then
      printf '%s\n' 'Vault 2 recovery preflight requires VAULT_TOKEN or an interactive /dev/tty ceremony token' >&2
      return 1
    fi
    printf '%s' 'Vault 2 ceremony token: ' >&9
    if ! IFS= read -r -s VAULT_TOKEN <&9 || [ -z "$VAULT_TOKEN" ]; then
      printf '\n%s\n' 'Vault 2 recovery preflight requires a non-empty ceremony token' >&9
      exec 9>&-
      unset VAULT_TOKEN
      return 1
    fi
    printf '\n' >&9
    exec 9>&-
    export VAULT_TOKEN
  fi

  # This is deliberately the only Vault endpoint called here. It is read-only
  # and validates the supplied v2 ceremony token without starting a ceremony.
  if ! vault operator generate-root -status -format=json >/dev/null 2>&1; then
    printf '%s\n' 'Vault generate-root status authorization check failed' >&2
    return 1
  fi
}

# Vault's CLI decoder accepts both secrets as flags, which places them in the
# local process argument list. Vault encodes *only* the XOR result with raw
# standard base64: its OTP is a base62 string and must be used as literal UTF-8
# bytes. Keep the equivalent operation on stdin and expose neither value to
# process inspection. Callers must already have completed the ceremony.
vault_recovery_decode_generated_root() {
  if ! command -v python3 >/dev/null 2>&1; then
    printf '%s\n' 'Vault recovery decode requires python3' >&2
    return 69
  fi
  [ "$#" -eq 2 ] || return 64
  printf '%s\n%s\n' "$1" "$2" | python3 -c '
import base64, re, sys
encoded, otp = sys.stdin.read().splitlines()

def decode_encoded_token(value):
    # HashiCorp Vault roottoken.EncodeToken uses base64.RawStdEncoding, not
    # URL-safe base64. Accept optional canonical padding solely for transport
    # compatibility, then strictly decode the raw-standard alphabet.
    if not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", value):
        raise SystemExit("invalid generated-root response")
    unpadded = value.rstrip("=")
    padding_length = len(value) - len(unpadded)
    required_padding = -len(unpadded) % 4
    if len(unpadded) % 4 == 1:
        raise SystemExit("invalid generated-root response")
    if padding_length and (len(value) % 4 or padding_length != required_padding):
        raise SystemExit("invalid generated-root response")
    return base64.b64decode(unpadded + "=" * required_padding, validate=True)

encoded_bytes = decode_encoded_token(encoded)
# GenerateRoot automatically creates a base62 OTP. It is intentionally not
# base64-decoded: EncodeToken XORs the literal OTP bytes with the root token.
if not re.fullmatch(r"[A-Za-z0-9]+", otp):
    raise SystemExit("invalid generated-root response")
otp_bytes = otp.encode("ascii")
if len(encoded_bytes) != len(otp_bytes):
    raise SystemExit("invalid generated-root response")
root_token = bytes(a ^ b for a, b in zip(encoded_bytes, otp_bytes))
try:
    print(root_token.decode("utf-8"))
except UnicodeDecodeError:
    raise SystemExit("invalid generated-root response")
'
}
