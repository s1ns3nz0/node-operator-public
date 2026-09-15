#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
script="$root/scripts/ops/hoodi-session.sh"
runbook="$root/docs/operations/cost-optimized-hoodi.md"

fail() { printf 'FAIL Hoodi suspend/resume contract: %s\n' "$*" >&2; exit 1; }

test -f "$script" || fail 'missing Hoodi session operator script'
test -f "$runbook" || fail 'missing Hoodi session runbook'
bash -n "$script"

for required in \
  'Usage: %s {status|start|stop} [--yes]' \
  'requires --yes because it changes runtime capacity' \
  'Vault Engine API JWT injection is absent' \
  'vault\.hashicorp\.com/agent-inject-secret-engine\.jwt' \
  'desiredSize=1' \
  'desiredSize=0' \
  'wait --for=condition=Ready pod -l app.kubernetes.io/name=nethermind' \
  'wait --for=condition=Ready pod -l app.kubernetes.io/name=prysm-beacon' \
  'scale statefulset nethermind-execution prysm-beacon --replicas=0'; do
  grep -Fq "$required" "$script" || fail "missing safety invariant: $required"
done

if grep -Eqi 'jsonpath=.*\.data|base64|kubectl get secret .* -o (yaml|json)' "$script"; then
  fail 'session script could expose a Secret value'
fi

grep -Fq 'scripts/ops/hoodi-session.sh' "$runbook" || fail 'runbook does not point to the operator script'

wrapper="$root/scripts/ops/with-private-eks.sh"
# The installer supplies the discovered host; tests must not inherit a retired
# maintainer instance ID from production defaults.
export SSM_OPS_INSTANCE_ID=i-0123456789abcdef0
test -f "$wrapper" || fail 'missing private EKS wrapper'
bash -n "$wrapper"

scratch="$(mktemp -d "${TMPDIR:-/tmp}/private-eks-session-contract.XXXXXX")"
trap 'rm -rf "$scratch"' EXIT
mkdir -p "$scratch/bin"

cat > "$scratch/bin/aws" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

case "${1:-} ${2:-}" in
  'eks describe-cluster')
    printf '%s\n' 'https://private.eks.example.test'
    ;;
  'eks update-kubeconfig')
    kubeconfig=''
    while [ "$#" -gt 0 ]; do
      if [ "$1" = --kubeconfig ]; then
        kubeconfig="$2"
        break
      fi
      shift
    done
    : > "$kubeconfig"
    ;;
  'ssm describe-instance-information')
    # The wrapper must wait for the exact selected ops host before it starts
    # its tunnel. This fake is intentionally Online rather than bypassing the
    # readiness check, so the exercised path remains the production one.
    printf '%s\n' 'Online'
    ;;
  'ssm start-session')
    test -z "${ANTHROPIC_API_KEY:-}"
    test -z "${OPENAI_API_KEY:-}"
    test -z "${GITHUB_TOKEN:-}"
    printf 'start-session %s\n' "$*" >> "$MOCK_TRACE"
    case "${MOCK_SSM_MODE:-owned}" in
      owned)
        printf '%s\n' 'Starting session with SessionId: owned-session'
        ;;
      ambiguous)
        printf '%s\n' 'Starting session with SessionId: owned-session'
        printf '%s\n' 'Starting session with SessionId: unrelated-session'
        ;;
      fail)
        exit 42
        ;;
      *)
        exit 64
        ;;
    esac
    trap 'exit 0' INT HUP TERM
    while :; do sleep 1; done
    ;;
  'ssm terminate-session')
    test -z "${ANTHROPIC_API_KEY:-}"
    test -z "${OPENAI_API_KEY:-}"
    test -z "${GITHUB_TOKEN:-}"
    printf 'terminate-session %s\n' "$*" >> "$MOCK_TRACE"
    ;;
  *)
    printf 'unexpected aws invocation: %s\n' "$*" >&2
    exit 64
    ;;
esac
EOF

cat > "$scratch/bin/kubectl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
case " $* " in
  *' config view '*) printf '%s' 'mock-private-eks-context' ;;
  *' config set-cluster '*) ;;
  *) printf 'unexpected kubectl invocation: %s\n' "$*" >&2; exit 64 ;;
esac
EOF

cat > "$scratch/bin/nc" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' 'tunnel-ready' >> "$MOCK_TRACE"
exit 0
EOF
chmod +x "$scratch/bin/aws" "$scratch/bin/kubectl" "$scratch/bin/nc"

trace="$scratch/trace"
: > "$trace"
PATH="$scratch/bin:$PATH" MOCK_TRACE="$trace" MOCK_SSM_MODE=owned \
  ANTHROPIC_API_KEY=mocked-anthropic OPENAI_API_KEY=mocked-openai GITHUB_TOKEN=mocked-github \
  bash "$wrapper" -- /usr/bin/true
grep -Fq 'start-session ssm start-session' "$trace" || fail 'wrapper did not start a mocked SSM session'
grep -Fxq 'terminate-session ssm terminate-session --session-id owned-session --region ap-northeast-2' "$trace" ||
  fail 'wrapper did not terminate exactly its owned SSM session'
test "$(grep -Fc 'terminate-session ' "$trace")" -eq 1 || fail 'wrapper terminated more than one session'
if grep -Eiq 'list-sessions|describe-sessions' "$wrapper"; then
  fail 'wrapper must not enumerate sessions during cleanup'
fi

: > "$trace"
if PATH="$scratch/bin:$PATH" MOCK_TRACE="$trace" MOCK_SSM_MODE=owned \
  bash "$wrapper" -- /bin/sh -c 'exit 42'; then
  fail 'wrapper masked a failing child command'
else
  child_status=$?
fi
test "$child_status" -eq 42 || fail "wrapper returned $child_status instead of child status 42"
grep -Fxq 'terminate-session ssm terminate-session --session-id owned-session --region ap-northeast-2' "$trace" ||
  fail 'wrapper did not terminate its owned session after child failure'
test "$(grep -Fc 'terminate-session ' "$trace")" -eq 1 || fail 'failing child cleanup terminated more than one session'

: > "$trace"
stdin_round_trip="$(printf '%s\n' 'stdin-survives-backgrounding' | \
  PATH="$scratch/bin:$PATH" MOCK_TRACE="$trace" MOCK_SSM_MODE=owned \
  bash "$wrapper" -- /bin/sh -c 'IFS= read -r input; printf "%s" "$input"')"
test "$stdin_round_trip" = stdin-survives-backgrounding || fail 'wrapper did not preserve caller stdin for child command'
grep -Fxq 'terminate-session ssm terminate-session --session-id owned-session --region ap-northeast-2' "$trace" ||
  fail 'wrapper did not terminate its owned session after stdin round-trip'
test "$(grep -Fc 'terminate-session ' "$trace")" -eq 1 || fail 'stdin round-trip cleanup terminated more than one session'

: > "$trace"
if PATH="$scratch/bin:$PATH" MOCK_TRACE="$trace" MOCK_SSM_MODE=fail \
  bash "$wrapper" -- /usr/bin/true >/dev/null 2>&1; then
  fail 'wrapper accepted a failed SSM startup'
fi
if grep -Fq 'terminate-session ' "$trace"; then
  fail 'wrapper terminated a session without an owned session ID'
fi

: > "$trace"
if PATH="$scratch/bin:$PATH" MOCK_TRACE="$trace" MOCK_SSM_MODE=ambiguous \
  bash "$wrapper" -- /usr/bin/true >/dev/null 2>&1; then
  fail 'wrapper accepted ambiguous SSM session ownership'
fi
if grep -Fq 'terminate-session ' "$trace"; then
  fail 'wrapper terminated a session after ambiguous ownership output'
fi

: > "$trace"
PATH="$scratch/bin:$PATH" MOCK_TRACE="$trace" MOCK_SSM_MODE=owned \
  bash "$wrapper" -- /bin/sh -c 'while :; do sleep 1; done' >/dev/null 2>&1 &
wrapper_pid=$!
for _ in $(seq 1 20); do
  grep -Fq 'tunnel-ready' "$trace" && break
  sleep 1
done
grep -Fq 'tunnel-ready' "$trace" || fail 'wrapper did not become ready before signal test'
kill -TERM "$wrapper_pid"
if wait "$wrapper_pid"; then
  fail 'wrapper unexpectedly succeeded after SIGTERM'
fi
grep -Fxq 'terminate-session ssm terminate-session --session-id owned-session --region ap-northeast-2' "$trace" ||
  fail 'wrapper did not terminate its owned session after SIGTERM'
test "$(grep -Fc 'terminate-session ' "$trace")" -eq 1 || fail 'signal cleanup terminated more than one session'

printf 'PASS Hoodi and private EKS session wrappers preserve explicit, non-secret activation and exact SSM cleanup boundaries.\n'
