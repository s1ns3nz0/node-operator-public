#!/usr/bin/env bash
set -euo pipefail

# Local/native verification only. This does not publish an image or prove the
# Linux release artifact, live TLS identity, or validator duty execution.
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
usage() { printf 'Usage: %s --output-dir <new-absolute-directory>\n' "${0##*/}" >&2; exit 64; }
if [ "$#" -ne 2 ] || [ "$1" != --output-dir ]; then usage; fi
output="$2"
case "$output" in /*) ;; *) usage ;; esac
if [ -e "$output" ] || [ -L "$output" ]; then printf '%s\n' 'Output must not already exist.' >&2; exit 65; fi
for command in git go jq shasum mkdir awk grep; do command -v "$command" >/dev/null || exit 69; done
lock="$root/.ci/prysm-mtls/source.lock.json"
revision="$(jq -er '.commit | select(test("^[a-f0-9]{40}$"))' "$lock")"
version="$(jq -er '.go_version' "$lock")"
repository="$(jq -er '.repository' "$lock")"
[ "$repository" = https://github.com/OffchainLabs/prysm.git ] || exit 65
[ "$(go env GOVERSION)" = "go$version" ] || { printf 'Requires Go %s.\n' "$version" >&2; exit 69; }
patch="$root/.ci/prysm-mtls/patches/0001-web3signer-http-mtls.patch"
expected_patch="$(jq -er '.patch_sha256 | select(test("^[a-f0-9]{64}$"))' "$lock")"
actual_patch="$(shasum -a 256 "$patch" | awk '{print $1}')"
[ "$actual_patch" = "$expected_patch" ] || { printf '%s\n' 'Patch checksum mismatch.' >&2; exit 65; }
umask 077
mkdir "$output"
output="$(cd "$output" && pwd -P)"
git init --quiet "$output/source"
git -C "$output/source" remote add origin "$repository"
git -C "$output/source" fetch --quiet --depth=1 origin "$revision"
git -C "$output/source" checkout --quiet --detach FETCH_HEAD
[ "$(git -C "$output/source" rev-parse HEAD)" = "$revision" ] || exit 65
git -C "$output/source" apply --check "$patch"
git -C "$output/source" apply "$patch"
security_patch="$root/.ci/prysm-mtls/patches/0002-security-dependencies.patch"
expected_security="$(jq -er '.security_patch_sha256 | select(test("^[a-f0-9]{64}$"))' "$lock")"
[ "$(shasum -a 256 "$security_patch" | awk '{print $1}')" = "$expected_security" ] || exit 65
git -C "$output/source" apply --check "$security_patch"
git -C "$output/source" apply "$security_patch"
git -C "$output/source" diff --check
(
  cd "$output/source"
  export GOTOOLCHAIN=local
  go mod verify
  go test -mod=readonly ./validator/keymanager/remote-web3signer/internal
  go test -mod=readonly ./validator/keymanager/remote-web3signer
  go test -mod=readonly ./validator/node -run TestWeb3SignerConfig -count=1
  go build -mod=readonly -trimpath -buildvcs=false -o "$output/validator" ./cmd/validator
)
"$output/validator" --help > "$output/validator-help.txt"
for flag in validators-external-signer-http-client-cert validators-external-signer-http-client-key validators-external-signer-http-ca-cert; do
  grep -q -- "--$flag" "$output/validator-help.txt" || { printf 'Missing native CLI option: %s\n' "$flag" >&2; exit 65; }
done
binary_sha="$(shasum -a 256 "$output/validator" | awk '{print $1}')"
jq -n --arg revision "$revision" --arg patch "$actual_patch" --arg security_patch "$expected_security" --arg binary "$binary_sha" --arg go "$(go env GOVERSION)" --arg os "$(go env GOOS)" --arg arch "$(go env GOARCH)" \
  '{schema_version:1,scope:"native-source-build",source_commit:$revision,patch_sha256:$patch,security_patch_sha256:$security_patch,binary_sha256:$binary,go_version:$go,os:$os,arch:$arch,tests:"passed",cli_flags:"present",published:false,deployed:false}' > "$output/build-evidence.json"
printf 'PASS native patched Prysm build. Evidence: %s/build-evidence.json\n' "$output"
