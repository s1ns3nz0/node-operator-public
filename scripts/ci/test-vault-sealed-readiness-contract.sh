#!/usr/bin/env bash
# Check objective: Validate the Vault sealed-readiness contract.
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd -P)"
helper="$root/scripts/ops/verify-hoodi-vault-readiness.sh"
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
mkdir "$tmp/bin"
cat >"$tmp/bin/kubectl" <<'EOF'
#!/usr/bin/env bash
[[ " $* " == *" --request-timeout=10s "* ]] || exit 66
if [[ " $* " == *" get pods "* ]]; then
  case "${PODS_MODE:-running}" in
    running) printf '%s\n' '{"items":[{"status":{"phase":"Running","conditions":[{"type":"Ready","status":"True"}]}},{"status":{"phase":"Running","conditions":[{"type":"Ready","status":"True"}]}},{"status":{"phase":"Running","conditions":[{"type":"Ready","status":"True"}]}}]}' ;;
    unready) printf '%s\n' '{"items":[{"status":{"phase":"Running","conditions":[{"type":"Ready","status":"False"}]}},{"status":{"phase":"Running","conditions":[{"type":"Ready","status":"False"}]}},{"status":{"phase":"Running","conditions":[{"type":"Ready","status":"False"}]}}]}' ;;
    *) printf '%s\n' '{"items":[]}' ;;
  esac
  exit 0
elif [[ " $* " == *" exec vault-0 "* ]]; then
  status_json="${VAULT_STATUS_JSON:-}"
  [ -n "$status_json" ] || status_json='{}'
  printf '%s\n' "$status_json"
  exit "${VAULT_STATUS_RC:-1}"
fi
exit 64
EOF
chmod 700 "$tmp/bin/kubectl"
run() { export VAULT_STATUS_JSON VAULT_STATUS_RC PODS_MODE; PATH="$tmp/bin:$PATH" "$helper" --mode "$1"; }
VAULT_STATUS_JSON='{"initialized":false,"sealed":true}' VAULT_STATUS_RC=2 run sealed-deployment >/dev/null
VAULT_STATUS_JSON='{"initialized":true,"sealed":false}' VAULT_STATUS_RC=0 run sealed-deployment >/dev/null
VAULT_STATUS_JSON='{"initialized":true,"sealed":false}' VAULT_STATUS_RC=0 run post-init-ready >/dev/null
if VAULT_STATUS_JSON='not-json' VAULT_STATUS_RC=2 run sealed-deployment >/dev/null 2>&1; then exit 1; fi
if PODS_MODE=unready VAULT_READINESS_ATTEMPTS=1 VAULT_STATUS_JSON='{"initialized":true,"sealed":false}' VAULT_STATUS_RC=0 run post-init-ready >/dev/null 2>&1; then exit 1; fi
if PODS_MODE=missing VAULT_READINESS_ATTEMPTS=1 VAULT_STATUS_JSON='{"initialized":false,"sealed":true}' VAULT_STATUS_RC=2 run sealed-deployment >/dev/null 2>&1; then exit 1; fi
printf '%s\n' 'PASS sealed/post-init Vault readiness contract'
