#!/usr/bin/env bash
# Check objective: Verify Kyverno workload coverage rejects project policy bypasses.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
policy="$root/deploy/kyverno/policies/node-operator-project-workload-baseline.yaml"
fixtures="$root/deploy/kyverno/policies/fixtures/project-coverage"
kyverno_bin="${KYVERNO_BIN:-kyverno}"

command -v "$kyverno_bin" >/dev/null 2>&1 || {
  printf 'Kyverno CLI is required for real-engine project-coverage tests.\n' >&2
  exit 127
}

# The project scope is explicit: control-plane namespaces are intentionally
# absent and separately governed (see the policy annotation).
for namespace in validator-operations vault argocd cert-manager validator-observability; do
  grep -Fq "$namespace" "$policy"
done
grep -Fq 'separately governed control-plane namespaces' "$policy"
grep -Fq 'background: true' "$policy"
if grep -Fq 'node-operator-dast' "$policy"; then
  printf 'retired DAST namespace must not be in policy scope\n' >&2
  exit 1
fi

for fixture in allowed-validator-operations allowed-vault-inherited allowed-collector; do
  "$kyverno_bin" apply "$policy" --resource "$fixtures/$fixture.yaml" >/dev/null || {
    printf 'Kyverno rejected allowed project-coverage fixture: %s\n' "$fixture" >&2
    exit 1
  }
done

assert_denied() {
  local fixture="$1" rule="$2"
  local output
  if output="$("$kyverno_bin" apply "$policy" --resource "$fixtures/$fixture.yaml" 2>&1)"; then
    printf 'Kyverno accepted rejected project-coverage fixture: %s\n' "$fixture" >&2
    exit 1
  fi
  printf '%s\n' "$output" | grep -Fq "$rule"
  printf '%s\n' "$output" | grep -Eq 'fail: [1-9][0-9]*,'
  printf '%s\n' "$output" | grep -Fq 'error: 0'
}

assert_denied denied-tag require-private-ecr-image-digest
assert_denied denied-hostpath deny-unapproved-hostpaths
assert_denied denied-collector-root-spoof require-effective-restricted-runtime-security-context
assert_denied denied-collector-init-varlog-readonly restrict-validator-log-collector-hostpath
assert_denied denied-collector-init-varlog-readwrite restrict-validator-log-collector-hostpath
assert_denied denied-collector-extra-hostpath restrict-validator-log-collector-hostpath

printf 'PASS Kyverno project coverage enforces scoped workload controls and the narrow collector exception.\n'
