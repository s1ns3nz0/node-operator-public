#!/usr/bin/env bash
set -euo pipefail

dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
if [ "${PRIVATE_EKS_SESSION:-}" != 1 ]; then
  exec "$dir/with-private-eks.sh" -- env PRIVATE_EKS_SESSION=1 "$0" "$@"
fi

usage() { printf '%s\n' "Usage: ${0##*/} --validator-set <hoodi-id> [--dry-run]" >&2; exit 64; }
validator_set=''; dry_run=false
while [ "$#" -gt 0 ]; do case "$1" in --validator-set) validator_set="${2:-}"; shift 2 ;; --dry-run) dry_run=true; shift ;; *) usage ;; esac; done
case "$validator_set" in hoodi-[a-z0-9][a-z0-9-]*) ;; *) usage ;; esac
for command in kubectl date jq; do command -v "$command" >/dev/null 2>&1 || { printf 'missing command: %s\n' "$command" >&2; exit 69; }; done
namespace=validator-operations
signer="validator-${validator_set}-remote-signer"
lease="validator-${validator_set}-primary"
replicas="$(kubectl -n "$namespace" get deployment "$signer" -o jsonpath='{.spec.replicas}')"
[ "$replicas" = 0 ] || { printf '%s\n' 'signer is not at zero replicas; refuse concurrent ownership' >&2; exit 65; }
holder="$(kubectl -n "$namespace" get lease "$lease" -o jsonpath='{.spec.holderIdentity}')"
[ -z "$holder" ] || { printf '%s\n' 'fence lease already has a holder; refuse signer start' >&2; exit 65; }
if [ "$dry_run" = true ]; then printf '%s\n' 'PASS: signer start gate passed; no lease or workload changed.'; exit 0; fi
# The signer has no direct client ingress. Leave the empty Lease for the
# dedicated signing fence to acquire atomically after it binds the fixed Pod.
kubectl -n "$namespace" scale deployment "$signer" --replicas=1
printf '%s\n' 'PASS: isolated signer scale request submitted with an empty Lease. Start the client only through activate-hoodi-validator-client.sh.'
