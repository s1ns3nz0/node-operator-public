#!/usr/bin/env bash
# Purpose: Install checksum-verified Cosign, Syft, and Grype for Fence and Vault evidence operations.
# Inputs: One reviewed Linux/amd64 installation directory.
# Outputs: Verified tool executables in that directory.
# Side effects: Downloads pinned public release artifacts and writes local tool files only.
set -euo pipefail

if [ "$#" -ne 1 ]; then printf 'usage: %s INSTALL_DIRECTORY\n' "$0" >&2; exit 64; fi
if [ "$(uname -s)" != Linux ] || [ "$(uname -m)" != x86_64 ]; then printf 'only reviewed linux/amd64 tools are supported\n' >&2; exit 65; fi
install_directory="$1"; mkdir -p "$install_directory"
scratch="$(mktemp -d)"; trap 'rm -rf "$scratch"' EXIT
download() {
  name="$1" url="$2" expected="$3" destination="$4"
  curl --fail --location --silent --show-error --output "$scratch/$name" "$url"
  actual="$(sha256sum "$scratch/$name" | awk '{print $1}')"
  [ "$actual" = "$expected" ] || { printf '%s checksum mismatch\n' "$name" >&2; exit 1; }
  mv "$scratch/$name" "$destination"
}
download cosign \
  https://github.com/sigstore/cosign/releases/download/v3.1.2/cosign-linux-amd64 \
  f7622ed3cf22e55e1ae6377c080979ff77a22da9981c11df222a2e444991e7cf \
  "$install_directory/cosign"
download syft.tar.gz \
  https://github.com/anchore/syft/releases/download/v1.42.4/syft_1.42.4_linux_amd64.tar.gz \
  590650c2743b83f327d1bf9bec64f6f83b7fec504187bb84f500c862bf8f2a0f \
  "$scratch/syft.tar.gz.verified"
tar -xzf "$scratch/syft.tar.gz.verified" -C "$install_directory" syft
"$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)/install-release-sca-tool.sh" "$install_directory"
chmod 0755 "$install_directory/cosign" "$install_directory/syft" "$install_directory/grype"
"$install_directory/cosign" version >/dev/null
"$install_directory/syft" version >/dev/null
"$install_directory/grype" version >/dev/null
