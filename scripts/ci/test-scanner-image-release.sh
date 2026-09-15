#!/usr/bin/env bash
# Check objective: Enforce pinned scanner-image dependencies and its restricted release workflow contract.
# shellcheck disable=SC2016
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$script_dir/../.." && pwd)"
temporary_directory="$(mktemp -d)"
trap 'rm -rf "$temporary_directory"' EXIT

grep -Eqx 'FROM ubuntu@sha256:[0-9a-f]{64}' "$root/.ci/scanners/Dockerfile"
grep -Eq 'GITLEAKS_SHA256=[0-9a-f]{64}' "$root/.ci/scanners/Dockerfile"
grep -Eq 'OSV_SCANNER_SHA256=[0-9a-f]{64}' "$root/.ci/scanners/Dockerfile"
grep -Fq 'gitleaks git "$source_directory"' "$root/scripts/ci/collect-pr-evidence.sh"
if grep -Eq 'gitleaks git .*--no-git([[:space:]]|$)' "$root/scripts/ci/collect-pr-evidence.sh"; then
  printf 'scanner collector must not disable Git history analysis\n' >&2
  exit 1
fi
if grep -qE 'curl[^\n]*\|[[:space:]]*(tar|install)' "$root/.ci/scanners/Dockerfile"; then
  printf 'scanner image must verify downloads before extraction or installation\n' >&2
  exit 1
fi

expected_input_sha="$({
  sha256sum \
    "$root/.ci/scanners/Dockerfile" \
    "$root/.ci/scanners/Dockerfile.dockerignore" \
    "$root/.ci/scanners/run-security-scan.sh" \
    "$root/scripts/ci/collect-pr-evidence.sh" \
    "$root/scripts/ci/collect-security-evidence.sh" \
    "$root/scripts/ci/lib/common.sh"
} | awk '{print $1}' | sha256sum | awk '{print $1}')"
mkdir -p "$temporary_directory/bin"
printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' \
  'case "$1" in' \
  '  pull) exit 0 ;;' \
  '  image) [ "$2" = "inspect" ] && printf "%s\\n" "$EXPECTED_INPUT_SHA" ;;' \
  '  *) printf "unexpected docker command: %s\\n" "$*" >&2; exit 1 ;;' \
  'esac' > "$temporary_directory/bin/docker"
chmod +x "$temporary_directory/bin/docker"

output="$(cd "$root" && EXPECTED_INPUT_SHA="$expected_input_sha" GITHUB_REPOSITORY=s1ns3nz0/node-operator GITHUB_SHA=fixture PATH="$temporary_directory/bin:$PATH" bash .ci/scanners/release-scanner-image.sh)"
test "$output" = 'scanner image inputs are unchanged; skipping build and push'
