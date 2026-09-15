#!/usr/bin/env bash
# Purpose: Download and checksum-verify pinned OPA, Conftest, ShellCheck, and ripgrep for CI policy checks.
# Inputs: Optional installation directory and the host OS/architecture.
# Outputs: Executable tools in the chosen local directory and optional GITHUB_PATH entry.
# Side effects: Downloads pinned public releases and writes only the caller-selected local tool directory.
set -euo pipefail

# The adapter never downloads tools implicitly. This explicit bootstrap writes
# only to the caller-selected local tools directory.
destination="${1:-${CI_TOOL_BIN:-$PWD/.ci-tools/bin}}"
platform="$(uname -s)_$(uname -m)"

case "$platform" in
  Darwin_arm64)
    opa_url="https://github.com/open-policy-agent/opa/releases/download/v1.17.0/opa_darwin_arm64_static"
    opa_sha256="7d7debaf10bba97d32b7e67b7f8ce128c92e911b82e3c6cec24b95c34f8a5003"
    conftest_url="https://github.com/open-policy-agent/conftest/releases/download/v0.69.0/conftest_0.69.0_Darwin_arm64.tar.gz"
    conftest_sha256="78302d045f0ec52e9786a06c6c621ac4516b4c5dd1e54efc8050c86c29b964d9"
    shellcheck_url="https://github.com/koalaman/shellcheck/releases/download/v0.11.0/shellcheck-v0.11.0.darwin.aarch64.tar.xz"
    shellcheck_sha256="56affdd8de5527894dca6dc3d7e0a99a873b0f004d7aabc30ae407d3f48b0a79"
    shellcheck_member="shellcheck-v0.11.0/shellcheck"
    ripgrep_url="https://github.com/BurntSushi/ripgrep/releases/download/15.2.0/ripgrep-15.2.0-aarch64-apple-darwin.tar.gz"
    ripgrep_sha256="3750b2e93f37e0c692657da574d7019a101c0084da05a790c83fd335bad973e4"
    ripgrep_member="ripgrep-15.2.0-aarch64-apple-darwin/rg"
    ;;
  Linux_x86_64)
    opa_url="https://github.com/open-policy-agent/opa/releases/download/v1.17.0/opa_linux_amd64_static"
    opa_sha256="e83da46804832578e9d9e1733dffbe4d3b5f8cc9c26eb124da9ceea4abfe189f"
    conftest_url="https://github.com/open-policy-agent/conftest/releases/download/v0.69.0/conftest_0.69.0_Linux_x86_64.tar.gz"
    conftest_sha256="96fc2fbf11f0afde51256647127e6f00a64ce839a4d9a0a1aef2426c0e6f4b3f"
    shellcheck_url="https://github.com/koalaman/shellcheck/releases/download/v0.11.0/shellcheck-v0.11.0.linux.x86_64.tar.xz"
    shellcheck_sha256="8c3be12b05d5c177a04c29e3c78ce89ac86f1595681cab149b65b97c4e227198"
    shellcheck_member="shellcheck-v0.11.0/shellcheck"
    ripgrep_url="https://github.com/BurntSushi/ripgrep/releases/download/15.2.0/ripgrep-15.2.0-x86_64-unknown-linux-musl.tar.gz"
    ripgrep_sha256="33e15bcf1624b25cdd2a55813a47a2f95dbe126268203e76aa6a585d1e7b149c"
    ripgrep_member="ripgrep-15.2.0-x86_64-unknown-linux-musl/rg"
    ;;
  *) printf 'unsupported policy-tool platform: %s\n' "$platform" >&2; exit 64 ;;
esac

temporary_directory="$(mktemp -d)"
trap 'rm -rf "$temporary_directory"' EXIT
mkdir -p "$destination"

download_and_verify() {
  local url="$1" expected_sha256="$2" output="$3"
  curl --fail --silent --show-error --location --output "$output" "$url"
  printf '%s  %s\n' "$expected_sha256" "$output" | shasum -a 256 --check --status
}

download_and_verify "$opa_url" "$opa_sha256" "$temporary_directory/opa"
install -m 0755 "$temporary_directory/opa" "$destination/opa"
download_and_verify "$conftest_url" "$conftest_sha256" "$temporary_directory/conftest.tar.gz"
tar -xzf "$temporary_directory/conftest.tar.gz" -C "$destination" conftest
chmod 0755 "$destination/conftest"
download_and_verify "$shellcheck_url" "$shellcheck_sha256" "$temporary_directory/shellcheck.tar.xz"
tar -xJf "$temporary_directory/shellcheck.tar.xz" -C "$temporary_directory" "$shellcheck_member"
install -m 0755 "$temporary_directory/$shellcheck_member" "$destination/shellcheck"
download_and_verify "$ripgrep_url" "$ripgrep_sha256" "$temporary_directory/ripgrep.tar.gz"
tar -xzf "$temporary_directory/ripgrep.tar.gz" -C "$temporary_directory" "$ripgrep_member"
install -m 0755 "$temporary_directory/$ripgrep_member" "$destination/rg"

if [ -n "${GITHUB_PATH:-}" ]; then printf '%s\n' "$destination" >> "$GITHUB_PATH"; fi
printf 'Installed pinned OPA 1.17.0, Conftest 0.69.0, ShellCheck 0.11.0, and ripgrep 15.2.0 in %s\n' "$destination"
