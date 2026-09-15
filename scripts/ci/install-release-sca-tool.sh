#!/usr/bin/env bash
# Purpose: Download and checksum-verify the pinned Grype binary for release SBOM scanning.
# Inputs: One Linux/amd64 installation directory.
# Outputs: A verified grype executable in that directory.
# Side effects: Downloads a pinned public archive and writes local tool files only.
set -euo pipefail

if [ "$#" -ne 1 ]; then
  printf 'usage: %s INSTALL_DIRECTORY\n' "$0" >&2
  exit 64
fi

install_directory="$1"
version="0.118.0"
archive_sha256="1d444c5e7360471815f7158f71935fcecc68a3c417d85c7344f770854300bba2"
temporary_directory="$(mktemp -d)"
trap 'rm -rf "$temporary_directory"' EXIT

mkdir -p "$install_directory"
curl --fail --location --silent --show-error \
  --output "$temporary_directory/grype.tar.gz" \
  "https://github.com/anchore/grype/releases/download/v${version}/grype_${version}_linux_amd64.tar.gz"
actual_sha256="$(sha256sum "$temporary_directory/grype.tar.gz" | awk '{print $1}')"
[ "$actual_sha256" = "$archive_sha256" ] || { printf 'Grype archive checksum mismatch\n' >&2; exit 1; }
tar -xzf "$temporary_directory/grype.tar.gz" -C "$install_directory" grype
"$install_directory/grype" version >/dev/null
