#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
installer="$root/scripts/ci/install-policy-tools.sh"

for required in \
  'opa/releases/download/v1.17.0' \
  'conftest/releases/download/v0.69.0' \
  'shellcheck/releases/download/v0.11.0' \
  'Darwin_arm64' \
  'Linux_x86_64' \
  'shasum -a 256 --check --status' \
  'unsupported policy-tool platform'; do
  grep -Fq "$required" "$installer"
done

printf 'PASS policy tool bootstrap pins supported platform downloads and checksums.\n'
