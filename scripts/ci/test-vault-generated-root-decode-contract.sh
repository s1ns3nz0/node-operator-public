#!/usr/bin/env bash
# Check objective: Verify generated-root decoding accepts only canonical recovery material.
# shellcheck disable=SC2016 # literal source-contract fragments
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
library="$root/scripts/ops/lib/vault-recovery-auth.sh"
grep -Fq 'vault_recovery_decode_generated_root' "$library"
grep -Fq 'bytes(a ^ b for a, b in zip(encoded_bytes, otp_bytes))' "$library"
test "$(bash -c 'source "$1"; vault_recovery_decode_generated_root AA a' bash "$library")" = a
if bash -c 'source "$1"; vault_recovery_decode_generated_root -w a' bash "$library" >/dev/null 2>&1; then
  printf '%s\n' 'generated-root decoder must reject URL-safe encoded data' >&2
  exit 1
fi
if rg -n 'generate-root -decode=.*(encoded|otp)' "$root/scripts/ops"; then
  printf '%s\n' 'recovery wrappers must not pass generated-root decode inputs as process arguments' >&2
  exit 1
fi
for script in "$root"/scripts/ops/recover*.sh; do
  if grep -Fq 'operator generate-root -init' "$script" && ! grep -Fq 'vault_recovery_decode_generated_root' "$script"; then
    printf 'recovery wrapper lacks stdin-safe decode: %s\n' "$script" >&2
    exit 1
  fi
done
printf '%s\n' 'PASS: all generated-root recovery wrappers use the shared stdin-safe decoder.'
