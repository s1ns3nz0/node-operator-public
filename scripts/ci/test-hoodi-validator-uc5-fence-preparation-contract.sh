#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
script="$root/scripts/ops/prepare-hoodi-validator-uc5-fence.sh"
fail() { printf 'FAIL UC-5 fence preparation: %s\n' "$*" >&2; exit 1; }
test -x "$script" || fail 'preparation script is not executable'
bash -n "$script"
# shellcheck disable=SC2016 # Literal source-contract assertions below.
for required in \
  'scale deployment "$fence" --replicas=0' \
  'scale statefulset "$client" --replicas=0' \
  'render-signer-network-probe.py' \
  'direct_client_to_signer_denied:true' \
  'client_and_fence_quiesced:true' \
  'GET-only public-key endpoint' \
  'delete pod "$direct_probe" "$control_probe" --ignore-not-found --wait=true'; do
  grep -Fq -- "$required" "$script" || fail "missing contract: $required"
done
if grep -Eiq 'signing[-_ ]?root|attestation[-_ ]?signature|keystore.*cat|vault.*read' "$script"; then
  fail 'preparation script has an unsafe signing or secret-read path'
fi
printf '%s\n' 'PASS UC-5 preparation fences the live path first, tests only the public-key endpoint, and cleans disposable probes.'
