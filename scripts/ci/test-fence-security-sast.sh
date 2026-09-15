#!/usr/bin/env bash
# Check objective: Verify the Fence SAST runner preserves its pinned scanner and failure policy.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
scratch="$(mktemp -d)"; trap 'rm -rf "$scratch"' EXIT
fake="$scratch/gosec"
cat > "$fake" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
for arg in "$@"; do case "$arg" in -out=*) output="${arg#-out=}";; esac; done
[ -n "${output:-}" ]
printf '%s\n' "$GOSEC_REPORT" > "$output"
exit "${GOSEC_EXIT:-0}"
EOF
chmod +x "$fake"
assert_rejected() {
  local report="$1" output="$scratch/out-$2"
  if GOSEC_BIN="$fake" GOSEC_REPORT="$report" GOSEC_EXIT=1 "$root/scripts/ci/run-fence-security-sast.sh" "$output" >/dev/null 2>&1; then
    printf 'accepted invalid synthetic gosec report: %s\n' "$2" >&2; exit 1
  fi
}
assert_rejected '{"Issues":[],"GosecErrors":["package load failed"],"Stats":{"files":1}}' errors
assert_rejected '{"Issues":[],"GosecErrors":{"package":"load failed"},"Stats":{"files":1}}' errors-object
assert_rejected '{"Issues":[],"GosecErrors":[],"Stats":{"files":0}}' zero-files
assert_rejected '{"Issues":[{"severity":"UNKNOWN","rule_id":"G999"}],"GosecErrors":[],"Stats":{"files":1}}' unknown-severity
assert_rejected '{"Issues":[{"severity":"HIGH","rule_id":"G999"}],"GosecErrors":[],"Stats":{"files":1}}' high
printf 'PASS fence SAST rejects malformed, incomplete, and high-finding reports.\n'
