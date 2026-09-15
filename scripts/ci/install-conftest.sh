#!/usr/bin/env bash
set -euo pipefail

version="0.69.0"
platform="$(uname -s)_$(uname -m)"
case "$platform" in
  Linux_x86_64) archive="conftest_${version}_Linux_x86_64.tar.gz"; checksum="96fc2fbf11f0afde51256647127e6f00a64ce839a4d9a0a1aef2426c0e6f4b3f" ;;
  Darwin_arm64) archive="conftest_${version}_Darwin_arm64.tar.gz"; checksum="78302d045f0ec52e9786a06c6c621ac4516b4c5dd1e54efc8050c86c29b964d9" ;;
  *) printf 'unsupported Conftest platform: %s\n' "$platform" >&2; exit 64 ;;
esac

destination="${CI_TOOL_BIN:-${RUNNER_TEMP:-/tmp}/node-operator-tools}"
mkdir -p "$destination"
temporary_archive="$(mktemp)"
trap 'rm -f "$temporary_archive"' EXIT
curl --fail --silent --show-error --location --output "$temporary_archive" "https://github.com/open-policy-agent/conftest/releases/download/v${version}/${archive}"
printf '%s  %s\n' "$checksum" "$temporary_archive" | shasum -a 256 --check --status
tar -xzf "$temporary_archive" -C "$destination" conftest
chmod 0755 "$destination/conftest"
if [ -n "${GITHUB_PATH:-}" ]; then printf '%s\n' "$destination" >> "$GITHUB_PATH"; fi
printf 'Conftest v%s installed in %s\n' "$version" "$destination"
