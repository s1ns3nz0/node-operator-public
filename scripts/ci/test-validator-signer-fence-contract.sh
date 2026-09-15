#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
script="$root/scripts/ops/start-hoodi-validator-signer.sh"
grep -Fq 'with-private-eks.sh' "$script"
grep -Fq 'PRIVATE_EKS_SESSION' "$script"
grep -Fq 'Leave the empty Lease' "$script"
if grep -Eq 'patch lease|holderIdentity.*replace' "$script"; then
  printf '%s\n' 'signer start must not preclaim the proxy Lease' >&2
  exit 1
fi
# shellcheck disable=SC2016 # Literal source-contract assertions.
grep -Fq 'scale deployment "$signer" --replicas=1' "$script"
# shellcheck disable=SC2016 # Literal source-contract assertion.
grep -Fq '[ "$replicas" = 0 ]' "$script"
printf '%s\n' 'PASS: isolated signer start leaves the empty set-specific Lease for the signing proxy.'
