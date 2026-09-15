#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
script="$root/scripts/ops/migrate-hoodi-validator-slashing-db.sh"
grep -Fq 'with-private-eks.sh' "$script"
# shellcheck disable=SC2016 # Literal source-contract assertion.
grep -Fq 'scale deployment "$signer" --replicas=0' "$script"
grep -Fq 'V00011__bigint_indexes.sql' "$script"
grep -Fq 'V00012__add_highwatermark_metadata.sql' "$script"
# shellcheck disable=SC2016 # Literal source-contract assertion.
grep -Fq '[ "$version_after" = 12 ]' "$script"
# shellcheck disable=SC2016 # Literal source-contract assertion.
grep -Fq 'data-${database}-0' "$script"
grep -Fq 'holderIdentity",value:""' "$script"
printf '%s\n' 'PASS: slashing DB migration preserves its PVC, fences signing, and verifies version 12.'
