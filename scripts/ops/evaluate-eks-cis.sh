#!/usr/bin/env bash
# Objective: Redact an actual kube-bench EKS node report and enforce its OPA prerequisite.
# Inputs: Raw kube-bench JSON, independently identified node name, new output directory.
# Side effects: Local evidence only; does not launch privileged Pods or contact AWS.
set -euo pipefail
umask 077
if [ "$#" -ne 3 ]; then
  printf 'usage: %s KUBE_BENCH_JSON NODE NEW_OUTPUT_DIR\n' "$0" >&2
  exit 64
fi
for tool in python3 opa; do command -v "$tool" >/dev/null || { printf 'missing command: %s\n' "$tool" >&2; exit 69; }; done
raw="$1"; node="$2"; output="$3"
[ ! -e "$output" ] && [ ! -L "$output" ] || exit 65
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
mkdir -m 700 "$output"
python3 "$root/scripts/ci/normalize-eks-cis.py" --input "$raw" \
  --profile "$root/policy/data/cis_eks.json" --node "$node" --output "$output/assessment.json"
# Unification makes a denied decision undefined; --fail alone accepts defined false.
if ! opa eval --fail --format json \
  --data "data:$root/policy/data/cis_eks.json" --data "$root/policy/cis_eks.rego" \
  --input "$output/assessment.json" 'true = data.nodeoperator.cis_eks.worker_node_pass' \
  > "$output/opa-decision.json"; then
  printf '%s\n' 'BLOCKED: EKS node assessment has failed or unresolved checks; see the redacted assessment.' >&2
  exit 1
fi
printf '%s\n' 'PASS: EKS worker-node prerequisite only; this is not full-cluster CIS compliance.'
