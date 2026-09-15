#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
base="$root/deploy/validator"
readiness="$root/scripts/ops/verify-use-case-readiness.sh"

[ ! -e "$base/remote-signer-service.yaml" ] || { printf '%s\n' 'unscoped remote signer Service must not be part of the base' >&2; exit 1; }
[ ! -e "$base/fencing.yaml" ] || { printf '%s\n' 'unscoped validator fence must not be part of the base' >&2; exit 1; }
if grep -Eq 'hoodi-validator-remote-signer|hoodi-validator-set-primary' "$base/kustomization.yaml"; then
  printf '%s\n' 'kustomization retains an unscoped signer boundary' >&2
  exit 1
fi
grep -Fq 'node-operator.io/validator-set: REPLACE_WITH_VALIDATOR_SET' "$base/runtime-template.yaml"
grep -Fq 'legacy unscoped' "$readiness"
grep -Fq 'unscoped remote-signer Service(s) remain' "$readiness"
printf '%s\n' 'PASS: signer Services and fence Leases are validator-set scoped; readiness rejects legacy boundaries.'
