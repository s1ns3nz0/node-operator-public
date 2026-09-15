#!/usr/bin/env bash
# Check objective: Verify Vault recovery authentication rejects unsafe inputs with mocked tools.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
library="$root/scripts/ops/lib/vault-recovery-auth.sh"
test -f "$library"

scratch="$(mktemp -d)"
trap 'rm -rf -- "$scratch"' EXIT
tools="$scratch/tools"
mkdir -p "$tools"

cat > "$tools/vault" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "$MOCK_VAULT_TRACE"
case "$*" in
  'status -format=json')
    case "${MOCK_STATUS:-ok2}" in
      ok1) printf '%s\n' '{"initialized":true,"sealed":false,"version":"1.20.4"}' ;;
      ok2) printf '%s\n' '{"initialized":true,"sealed":false,"version":"2.1.0"}' ;;
      sealed) printf '%s\n' '{"initialized":true,"sealed":true,"version":"2.1.0"}' ;;
      uninitialized) printf '%s\n' '{"initialized":false,"sealed":false,"version":"2.1.0"}' ;;
      malformed) printf '%s\n' '{not-json' ;;
      malformed_version) printf '%s\n' '{"initialized":true,"sealed":false,"version":"2.current"}' ;;
      unknown) printf '%s\n' '{"initialized":true,"sealed":false,"version":"3.0.0"}' ;;
      failure) exit 1 ;;
      *) exit 64 ;;
    esac
    ;;
  'operator generate-root -status -format=json')
    test "${MOCK_GENERATE_ROOT:-allow}" = allow || exit 2
    case "${MOCK_STATUS:-ok2}" in
      ok2) test "${VAULT_TOKEN:-}" = 'synthetic-ceremony-token' || exit 2 ;;
    esac
    ;;
  *) exit 64 ;;
esac
EOF
chmod 0755 "$tools/vault"

run_case() {
  local name="$1" expected="$2"
  shift 2
  local output trace rc
  trace="$scratch/$name.trace"
  set +e
  output="$(PATH="$tools:$PATH" MOCK_VAULT_TRACE="$trace" "$@" 2>&1)"
  rc=$?
  set -e
  if [ "$expected" = success ]; then
    [ "$rc" -eq 0 ] || { printf 'case failed unexpectedly: %s: %s\n' "$name" "$output" >&2; exit 1; }
  else
    [ "$rc" -ne 0 ] || { printf 'case succeeded unexpectedly: %s\n' "$name" >&2; exit 1; }
  fi
  if grep -Eq 'synthetic-ceremony-token|invalid-synthetic-token' <<<"$output"; then
    printf 'credential leaked by case: %s\n' "$name" >&2
    exit 1
  fi
  if [ -f "$trace" ] && grep -Ev '^(status -format=json|operator generate-root -status -format=json)$' "$trace" >/dev/null; then
    printf 'preflight performed a write or persisted credentials: %s\n' "$name" >&2
    exit 1
  fi
}

runner="$scratch/run-preflight.sh"
cat > "$runner" <<EOF
#!/usr/bin/env bash
set -euo pipefail
set -x
source "$library"
vault_recovery_auth_preflight
EOF
chmod 0755 "$runner"

no_tty_runner="$scratch/no-tty.py"
cat > "$no_tty_runner" <<'EOF'
import subprocess
import sys

result = subprocess.run([sys.argv[1]], stdin=subprocess.DEVNULL, start_new_session=True)
raise SystemExit(result.returncode)
EOF

run_case vault1_legacy success env -u VAULT_TOKEN MOCK_STATUS=ok1 MOCK_GENERATE_ROOT=allow "$runner"
run_case vault1_auth_denied failure env -u VAULT_TOKEN MOCK_STATUS=ok1 MOCK_GENERATE_ROOT=deny "$runner"
run_case vault2_env success env VAULT_TOKEN=synthetic-ceremony-token MOCK_STATUS=ok2 MOCK_GENERATE_ROOT=allow "$runner"
run_case vault2_invalid_token failure env VAULT_TOKEN=invalid-synthetic-token MOCK_STATUS=ok2 MOCK_GENERATE_ROOT=allow "$runner"
run_case vault2_no_tty failure env -u VAULT_TOKEN MOCK_STATUS=ok2 MOCK_GENERATE_ROOT=allow python3 "$no_tty_runner" "$runner"
run_case sealed failure env VAULT_TOKEN=synthetic-ceremony-token MOCK_STATUS=sealed MOCK_GENERATE_ROOT=allow "$runner"
run_case uninitialized failure env VAULT_TOKEN=synthetic-ceremony-token MOCK_STATUS=uninitialized MOCK_GENERATE_ROOT=allow "$runner"
run_case malformed failure env VAULT_TOKEN=synthetic-ceremony-token MOCK_STATUS=malformed MOCK_GENERATE_ROOT=allow "$runner"
run_case malformed_version failure env VAULT_TOKEN=synthetic-ceremony-token MOCK_STATUS=malformed_version MOCK_GENERATE_ROOT=allow "$runner"
run_case status_failure failure env VAULT_TOKEN=synthetic-ceremony-token MOCK_STATUS=failure MOCK_GENERATE_ROOT=allow "$runner"
run_case unsupported_major failure env VAULT_TOKEN=synthetic-ceremony-token MOCK_STATUS=unknown MOCK_GENERATE_ROOT=allow "$runner"

printf '%s\n' 'PASS Vault recovery auth preflight fake-CLI contract (not server authentication proof).'
