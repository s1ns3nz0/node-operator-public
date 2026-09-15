#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$script_dir/lib/common.sh"
root="$(repo_root)"
fail() { printf 'FAIL Vault signer toolchain contract: %s\n' "$*" >&2; exit 1; }

dockerfile="$root/.ci/toolchains/vault-release-signer.Dockerfile"
buildspec="$root/deploy/vault/buildspec-release-sign.yml"
documentation="$root/docs/gitops/vault-codebuild-signing.md"
for file in "$dockerfile" "$buildspec" "$documentation"; do
  test -f "$file" || fail "missing contract file: $file"
done

grep -Fqx '  shell: bash' "$buildspec" || fail 'signer buildspec must select Bash for pipefail-dependent commands'
grep -Fqx 'FROM ubuntu@sha256:33ceb71981b602c1a7443a53469e4dba065f7503eab3078a2d7a57a2ab987517' "$dockerfile" || fail 'Dockerfile base image must be pinned by digest'
grep -Fqx 'ARG VAULT_VERSION=1.20.4' "$dockerfile" || fail 'Dockerfile must pin Vault 1.20.4'
grep -Fqx 'ARG VAULT_SHA256=fc5fb5d01d192f1216b139fb5c6af17e3af742aaeffc289fd861920ec55f2c9c' "$dockerfile" || fail 'Dockerfile must pin the approved Vault SHA-256'
grep -Fq 'sha256sum --check --status' "$dockerfile" || fail 'Dockerfile must verify the Vault archive before extraction'
grep -Fq 'unzip -q /tmp/vault.zip -d /usr/local/bin' "$dockerfile" || fail 'Dockerfile must install Vault after verification'
grep -Fq "io.node-operator.toolchain-input-sha=\"\${TOOLCHAIN_INPUT_SHA}\"" "$dockerfile" || fail 'Dockerfile must retain the generic toolchain input label'

if grep -Eqi '(curl|wget|download|unzip)' "$buildspec"; then
  fail 'buildspec must not download or extract Vault at runtime'
fi
grep -Fq 'expected_vault_version="1.20.4"' "$buildspec" || fail 'buildspec must declare the expected preinstalled Vault version'
grep -Fq "installed_vault_version=\"\$(vault version | awk" "$buildspec" || fail 'buildspec must parse the plaintext Vault version safely'
grep -Fq "\$1 == \"Vault\" && \$2 ~ /^v[0-9]+/" "$buildspec" || fail 'buildspec must parse the plaintext Vault version safely'
grep -Fq "test \"\$installed_vault_version\" = \"\$expected_vault_version\"" "$buildspec" || fail 'buildspec must fail closed on the installed Vault version'
grep -Fq 'vault write -format=json transit/sign/node-operator-release' "$buildspec" || fail 'buildspec must sign through the preinstalled Vault CLI'
grep -Fq 'vault write -format=json transit/verify/node-operator-release' "$buildspec" || fail 'buildspec must verify through the preinstalled Vault CLI'
if grep -Fq '\\"' "$buildspec"; then
  fail 'literal-shell buildspec commands must not retain YAML-irrelevant quote escapes'
fi

grep -Fqi 'image digest' "$documentation" || fail 'documentation must require digest selection'
grep -Fqi 'separately authorized' "$documentation" || fail 'documentation must retain the separate activation boundary'
grep -Fqi 'Tag-only runtime configuration' "$documentation" || fail 'documentation must reject tag-only runtime configuration'
grep -Fqi 'is not accepted' "$documentation" || fail 'documentation must reject tag-only runtime configuration'

printf 'PASS Vault signer toolchain contract pins, verifies, and preinstalls Vault before private signing.\n'
