#!/usr/bin/env bash
# Check objective: Verify Kyverno baseline policies enforce hardened workload requirements.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
policy="$root/deploy/kyverno/policies/node-operator-workload-baseline.yaml"
fixtures="$root/deploy/kyverno/policies/fixtures/workload-baseline"
kyverno_bin="${KYVERNO_BIN:-kyverno}"

command -v "$kyverno_bin" >/dev/null 2>&1 || {
  printf 'Kyverno CLI is required for real-engine workload-baseline tests.\n' >&2
  exit 127
}

for fixture in no-volumes empty-volumes emptydir privileged-omitted; do
  "$kyverno_bin" apply "$policy" --resource "$fixtures/$fixture.yaml" >/dev/null || {
    printf 'Kyverno rejected allowed fixture: %s\n' "$fixture" >&2
    exit 1
  }
done

if hostpath_output="$("$kyverno_bin" apply "$policy" --resource "$fixtures/hostpath.yaml" 2>&1)"; then
  printf 'Kyverno accepted hostPath fixture\n' >&2
  exit 1
fi
printf '%s\n' "$hostpath_output" | grep -Fq 'deny-host-namespaces-and-host-paths'
printf '%s\n' "$hostpath_output" | grep -Fq 'Host namespaces and hostPath volumes are prohibited.'
printf '%s\n' "$hostpath_output" | grep -Eq 'fail: [1-9][0-9]*,'
printf '%s\n' "$hostpath_output" | grep -Fq 'error: 0'
if privileged_output="$("$kyverno_bin" apply "$policy" --resource "$fixtures/privileged-true.yaml" 2>&1)"; then
  printf 'Kyverno accepted privileged=true\n' >&2; exit 1
fi
printf '%s\n' "$privileged_output" | grep -Fq 'require-restricted-container-security-context'
printf '%s\n' "$privileged_output" | grep -Fq 'error: 0'

printf 'PASS Kyverno workload-baseline admits no-volume/emptyDir Pods and denies hostPath.\n'
