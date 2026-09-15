#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
helper="$root/scripts/ops/provision-hoodi-transport-tls.sh"
test -x "$helper"
bash -n "$helper"
set +e
output="$($helper 2>&1)"
status=$?
set -e
[ "$status" -eq 65 ]
printf '%s' "$output" | grep -Fq 'TLS Kubernetes Secret provisioning is retired'
if grep -Eq 'kubectl.*create secret|create secret generic' "$helper"; then
  printf '%s\n' 'retired transport helper must not create Kubernetes Secrets' >&2
  exit 1
fi
printf '%s\n' 'PASS: legacy transport TLS provisioning fails closed before any Kubernetes mutation.'
