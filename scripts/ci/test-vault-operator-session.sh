#!/usr/bin/env bash
# Check objective: Verify Vault operator sessions contain credentials and clean up mocked processes.
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
scratch="$(mktemp -d)"
cleanup() {
  for file in aws vault child calls output with-private-vault.sh with-private-vault-operator.sh; do
    test ! -f "$scratch/$file" || unlink "$scratch/$file"
  done
  rmdir "$scratch"
}
trap cleanup EXIT
cat > "$scratch/aws" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
if [ "$SCENARIO" = identity ]; then echo arn:aws:iam::123456789012:user/other; else echo arn:aws:iam::123456789012:user/jsyang; fi
MOCK
cat > "$scratch/vault" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
case "$1 $2" in
  'login -method=aws')
    test "${VAULT_TOKEN:-}" = ''
    [[ " $* " == *' -no-store '* && " $* " == *' -path=operator-aws '* ]]
    [[ " $* " == *' region=ap-northeast-2 '* && " $* " == *' role=operator-recovery '* ]]
    [[ " $* " == *' header_value=node-operator-vault-operator-123456789012-apne2 '* ]]
    echo login >> "$CALLS"
    if [ "$SCENARIO" = login ]; then echo synthetic-sensitive-error >&2; exit 1; fi
    policy=operator-recovery; ttl=300
    [ "$SCENARIO" != policy ] || policy=root
    [ "$SCENARIO" != ttl ] || ttl=601
    jq -n --arg policy "$policy" --argjson ttl "$ttl" '{auth:{client_token:"synthetic-operator-token",policies:[$policy],lease_duration:$ttl}}'
    ;;
  'operator generate-root')
    test "$*" = 'operator generate-root -status -format=json'
    test "$VAULT_TOKEN" = synthetic-operator-token
    echo status >> "$CALLS"
    [ "$SCENARIO" != status ] || exit 1
    echo '{"started":false}'
    ;;
  'token revoke')
    test "$*" = 'token revoke -self'
    test "$VAULT_TOKEN" = synthetic-operator-token
    echo revoke >> "$CALLS"
    [ "$SCENARIO" != revoke ] || exit 1
    ;;
  *) exit 97 ;;
esac
MOCK
cat > "$scratch/child" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
test "$VAULT_TOKEN" = synthetic-operator-token
test "$#" = 1 && test "$1" = 'two words'
echo child >> "$CALLS"
[ "$SCENARIO" != child ] || exit 42
MOCK
chmod 0755 "$scratch/aws" "$scratch/vault" "$scratch/child"
for scenario in success child identity login policy ttl status revoke; do
  : > "$scratch/calls"
  rc=0
  SCENARIO="$scenario" CALLS="$scratch/calls" PATH="$scratch:$PATH" PRIVATE_VAULT_SESSION=1 VAULT_TOKEN=stale-parent-token \
    bash "$root/scripts/ops/with-private-vault-operator.sh" -- "$scratch/child" 'two words' > "$scratch/output" 2>&1 || rc=$?
  if grep -Eq 'synthetic-operator-token|stale-parent-token|synthetic-sensitive-error' "$scratch/output"; then
    echo "FAIL: credential/error disclosure in $scenario" >&2; exit 1
  fi
  case "$scenario" in
    success) test "$rc" = 0; test "$(tr '\n' ',' < "$scratch/calls")" = login,status,child,revoke, ;;
    child) test "$rc" = 42; test "$(tr '\n' ',' < "$scratch/calls")" = login,status,child,revoke, ;;
    identity) test "$rc" != 0; test ! -s "$scratch/calls" ;;
    login) test "$rc" != 0; test "$(tr '\n' ',' < "$scratch/calls")" = login, ;;
    policy|ttl) test "$rc" != 0; test "$(tr '\n' ',' < "$scratch/calls")" = login,revoke, ;;
    status) test "$rc" != 0; test "$(tr '\n' ',' < "$scratch/calls")" = login,status,revoke, ;;
    revoke) test "$rc" != 0; test "$(tr '\n' ',' < "$scratch/calls")" = login,status,child,revoke, ;;
  esac
done
cp "$root/scripts/ops/with-private-vault-operator.sh" "$scratch/with-private-vault-operator.sh"
cat > "$scratch/with-private-vault.sh" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
test "$1" = --
shift
echo tunnel >> "$CALLS"
exec "$@"
MOCK
chmod 0755 "$scratch/with-private-vault.sh"
: > "$scratch/calls"
SCENARIO=success CALLS="$scratch/calls" PATH="$scratch:$PATH" PRIVATE_VAULT_SESSION='' \
  bash "$scratch/with-private-vault-operator.sh" -- "$scratch/child" 'two words' > "$scratch/output" 2>&1
test "$(tr '\n' ',' < "$scratch/calls")" = tunnel,login,status,child,revoke,
: > "$scratch/calls"
rc=0
CALLS="$scratch/calls" PRIVATE_VAULT_SESSION='' \
  bash "$scratch/with-private-vault-operator.sh" -- > "$scratch/output" 2>&1 || rc=$?
test "$rc" = 64 && test ! -s "$scratch/calls"
echo 'PASS: operator session mock lifecycle: success, child failure, identity, login, policy, TTL, status and revoke failure'
echo 'PASS: private tunnel re-entry preserves command arguments; invalid usage does not open a tunnel'
