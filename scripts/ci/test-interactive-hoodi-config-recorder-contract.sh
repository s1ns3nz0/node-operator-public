#!/usr/bin/env bash
# Check objective: Verify the legacy installer Config recorder safety gate.
# Regression coverage for the legacy installer Config recorder safety gate.
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
root="$(cd "$script_dir/../.." && pwd -P)"
source_script="$root/scripts/release/interactive-hoodi-release.sh"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

awk '
  /^discover_config_recorder_management\(\)/ { emit=1 }
  emit { print }
  emit && /^}/ { exit }
' "$source_script" >"$tmp/recorder-function.sh"

[ -s "$tmp/recorder-function.sh" ]
if rg -q "describe-configuration-recorders.*\|\| printf '0'" "$source_script"; then
  printf '%s\n' 'legacy Config recorder discovery still converts command failure to absence' >&2
  exit 1
fi

mkdir "$tmp/bin"
cat >"$tmp/bin/aws" <<'EOF'
#!/usr/bin/env bash
if [ "${FAKE_AWS_MODE:-}" = fail ]; then
  printf '%s\n' denied >&2
  exit 255
fi
[ "$1" = configservice ] && [ "$2" = describe-configuration-recorders ]
printf '%s\n' "${FAKE_AWS_RESULT:?}"
EOF
chmod +x "$tmp/bin/aws"

run_case() {
  local mode="$1" result="$2" expected_rc="$3" expected_output="$4"
  set +e
  local output
  output="$(PATH="$tmp/bin:$PATH" FAKE_AWS_MODE="$mode" FAKE_AWS_RESULT="$result" REGION=ap-northeast-2 bash -c '
    region="$REGION"
    source "$1"
    discover_config_recorder_management
  ' _ "$tmp/recorder-function.sh" 2>&1)"
  local rc=$?
  set -e
  [ "$rc" -eq "$expected_rc" ] || { printf 'unexpected exit %s: %s\n' "$rc" "$output" >&2; exit 1; }
  case "$output" in *"$expected_output"*) ;; *) printf 'missing output %s: %s\n' "$expected_output" "$output" >&2; exit 1;; esac
}

run_case ok 0 0 true
run_case ok 1 0 false
run_case ok None 65 'malformed or ambiguous'
run_case ok 2 65 'malformed or ambiguous'
run_case fail ignored 69 'could not inspect'

printf '%s\n' 'interactive Hoodi Config recorder contract tests passed'
