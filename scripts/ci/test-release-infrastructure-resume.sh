#!/usr/bin/env bash
# Check objective: Verify infrastructure release resumption behavior.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
release="$root/scripts/release/node-operator-release.sh"
workspace="$(mktemp -d)"
trap 'rm -rf "$workspace"' EXIT
fail() { printf 'FAIL infrastructure resume: %s\n' "$*" >&2; exit 1; }

mkdir "$workspace/bin" "$workspace/module"
printf '%s\n' '#!/usr/bin/env bash' 'set -eu' 'args=("$@")' 'if [[ "${args[0]}" == -chdir=* ]]; then args=("${args[@]:1}"); fi' 'case "${args[0]}" in' 'init) exit 0 ;;' 'plan) for x in "${args[@]}"; do [[ "$x" == -out=* ]] && : > "${x#-out=}"; done; exit 0 ;;' 'show) if [ "${TF_PLAN_MODE:-create}" = delete ]; then printf "{\"configuration\":{\"root_module\":{\"resources\":[{\"address\":\"aws_test.x\"}]}},\"resource_changes\":[{\"address\":\"aws_test.x\",\"change\":{\"actions\":[\"delete\",\"create\"]}}]}\n"; else printf "{\"configuration\":{\"root_module\":{\"resources\":[{\"address\":\"aws_test.x\"}]}},\"resource_changes\":[{\"address\":\"aws_test.x\",\"change\":{\"actions\":[\"create\"]}}]}\n"; fi ;;' 'apply) exit "${TF_APPLY_RC:-0}" ;;' '*) exit 0 ;;' 'esac' > "$workspace/bin/terraform"
chmod 700 "$workspace/bin/terraform"

# Extract the actual function through the next top-level function boundary.
awk '/^validate_phase_plan\(\)/ {on=1} /^zero_apply\(\)/ {on=0} on' "$release" > "$workspace/apply-phase.sh"
printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' 'fail() { return 97; }' 'source "$1"' 'apply_phase "$2" config backend "$3"' > "$workspace/harness.sh"
chmod 700 "$workspace/harness.sh"

if PATH="$workspace/bin:$PATH" TF_APPLY_RC=7 bash "$workspace/harness.sh" "$workspace/apply-phase.sh" "$workspace/module" "$workspace/failure.tfplan"; then
  fail 'terraform apply failure was reported as success'
else
  status=$?
  [ "$status" -eq 7 ] || fail "terraform apply failure exit was not preserved (got $status)"
fi
if PATH="$workspace/bin:$PATH" TF_PLAN_MODE=delete bash "$workspace/harness.sh" "$workspace/apply-phase.sh" "$workspace/module" "$workspace/delete.tfplan"; then
  fail 'destructive replacement plan was accepted'
fi

rg -F 'zero-inputs.sha256' "$release" >/dev/null || fail 'checkpoint input binding is missing'
rg -F 'nonempty work directory lacks a zero-resource checkpoint binding' "$release" >/dev/null || fail 'unknown nonempty workdir takeover is not rejected'
rg -F 'output -json network > "$foundation_output"' "$release" >/dev/null || fail 'foundation output is not refetched after replay'
rg -F 'init -input=false -reconfigure -backend-config="$backend_config"' "$release" >/dev/null || fail 'foundation retry is not bound to the configured backend'

printf 'PASS release infrastructure retry guards preserve apply failures and reject destructive plans.\n'
