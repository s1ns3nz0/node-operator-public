#!/usr/bin/env bash
# Check objective: Exercise Kyverno project coverage installation and reject incomplete applied policy evidence.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
installer="$root/scripts/ops/apply-kyverno-project-coverage.sh"
kyverno_bin="${KYVERNO_BIN:-kyverno}"
command -v "$kyverno_bin" >/dev/null 2>&1 || { printf 'Kyverno CLI is required.\n' >&2; exit 127; }

scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT
mkdir -p "$scratch/bin" "$scratch/evidence"

cat > "$scratch/bin/kubectl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
case " $* " in
  *' rollout status '*) exit 0 ;;
  *' kustomize '*) cat "$TEST_ROOT/deploy/kyverno/policies/node-operator-workload-baseline.yaml"; printf '%s\n' '---'; cat "$TEST_ROOT/deploy/kyverno/policies/node-operator-project-workload-baseline.yaml" ;;
  *' get pods -A -o json '*) cat "$TEST_PODS" ;;
  *' create '* ) printf '%s\n' '{"kind":"List","items":[{"metadata":{"name":"node-operator-workload-baseline"},"spec":{"validationFailureAction":"Enforce"}},{"metadata":{"name":"node-operator-project-workload-baseline"},"spec":{"validationFailureAction":"Enforce"}}]}' ;;
  *' apply '* ) printf '%s\n' "$*" >> "$TEST_KUBECTL_CALLS" ;;
  *' wait '* ) exit 0 ;;
  *' get clusterpolicies -o json '*) printf '%s\n' '{"items":[{"metadata":{"name":"node-operator-workload-baseline"},"spec":{"validationFailureAction":"Enforce","background":true},"status":{"conditions":[]}},{"metadata":{"name":"node-operator-project-workload-baseline"},"spec":{"validationFailureAction":"Enforce","background":true},"status":{"conditions":[]}}]}' ;;
  *) printf 'unexpected kubectl invocation: %s\n' "$*" >&2; exit 70 ;;
esac
EOF
chmod 0755 "$scratch/bin/kubectl"

allowed_pods="$scratch/allowed-pods.json"
ruby -ryaml -rjson -e '
  pod = YAML.load_file(ARGV.fetch(0))
  pod["status"] = {"phase" => "Running"}
  puts({"items" => [pod]}.to_json)
' "$root/deploy/kyverno/policies/fixtures/project-coverage/allowed-vault-inherited.yaml" > "$allowed_pods"

run_enforce() {
  local pods="$1" evidence="$2" calls="$3"
  TEST_ROOT="$root" TEST_PODS="$pods" TEST_KUBECTL_CALLS="$calls" PRIVATE_EKS_SESSION=1 KYVERNO_BIN="$kyverno_bin" PATH="$scratch/bin:$PATH" \
    "$installer" --phase enforce --evidence-output "$evidence" --execute
}

run_enforce "$allowed_pods" "$scratch/evidence/allowed.json" "$scratch/allowed.calls" >/dev/null
test -s "$scratch/evidence/allowed.json"
grep -Fq 'apply --dry-run=server' "$scratch/allowed.calls"

assert_rejected_before_apply() {
  local name="$1" pods="$2" expected_message="${3:-}" output calls
  output="$scratch/$name.out"
  calls="$scratch/$name.calls"
  : > "$calls"
  if run_enforce "$pods" "$scratch/evidence/$name.json" "$calls" >"$output" 2>&1; then
    printf 'preflight accepted invalid pod-list shape: %s\n' "$name" >&2
    exit 1
  fi
  if [ -n "$expected_message" ]; then
    grep -Fq "$expected_message" "$output"
  fi
  test ! -e "$scratch/evidence/$name.json"
  test ! -s "$calls"
}

empty_pods="$scratch/empty-pods.json"
wrong_shape_pods="$scratch/wrong-shape-pods.json"
printf '%s\n' '{"items":[]}' > "$empty_pods"
printf '%s\n' '{"items":{"not":"an-array"}}' > "$wrong_shape_pods"
assert_rejected_before_apply empty "$empty_pods" 'No valid project Pods were observed; refusing an empty or malformed preflight'
assert_rejected_before_apply wrong-shape "$wrong_shape_pods"

denied_pods="$scratch/denied-pods.json"
ruby -ryaml -rjson -e '
  pod = YAML.load_file(ARGV.fetch(0))
  pod["status"] = {"phase" => "Running"}
  puts({"items" => [pod]}.to_json)
' "$root/deploy/kyverno/policies/fixtures/project-coverage/denied-tag.yaml" > "$denied_pods"
assert_rejected_before_apply denied-tag "$denied_pods" 'Live workload preflight failed; no policy was changed.'

printf 'PASS Enforce preflight evaluates list items and rejects denied, empty, or malformed pod lists before mutation.\n'
