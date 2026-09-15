#!/usr/bin/env bash
# Purpose: Install the pinned Linux/amd64 Go security scanner used by Fence checks.
# Inputs: One installation directory and reviewed tool version/checksum configuration.
# Outputs: Verified scanner executable in the installation directory.
# Side effects: Downloads one pinned public archive and writes local tool files only.
set -euo pipefail

[ "$#" -eq 1 ] || { printf 'usage: %s INSTALL_DIRECTORY\n' "$0" >&2; exit 64; }
if [ "$(uname -s)" != Linux ] || [ "$(uname -m)" != x86_64 ]; then
  printf 'only linux/amd64 is supported\n' >&2
  exit 65
fi
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck disable=SC1091
source "$root/.ci/fence-security/tools.env"
destination="$1"; mkdir -p "$destination"
scratch="$(mktemp -d)"; trap 'rm -rf "$scratch"' EXIT
archive="gosec_${GOSEC_VERSION}_linux_amd64.tar.gz"
curl --fail --location --silent --show-error --output "$scratch/$archive" "https://github.com/securego/gosec/releases/download/v${GOSEC_VERSION}/$archive"
printf '%s  %s\n' "$GOSEC_LINUX_AMD64_SHA256" "$scratch/$archive" | sha256sum --check --status
tar -xzf "$scratch/$archive" -C "$destination" gosec
chmod 0755 "$destination/gosec"
"$destination/gosec" -version >/dev/null
