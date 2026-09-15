#!/usr/bin/env bash
set -euo pipefail

# Creates one new Hoodi EIP-2335 key outside this repository. The pinned
# release artifact is checksum- and GitHub-attestation-verified before use.
# This script never uploads material, deposits funds, or starts validator duty.

release_tag='v1.3.0'
asset='ethstaker_deposit-cli-d8016bc-darwin-arm64.tar.gz'
asset_sha256='d52bb248fec9b5ff7376319e7b43bca1778d718727cced3344857ae2bbd2b490'
release_base_url="https://github.com/ethstaker/ethstaker-deposit-cli/releases/download/${release_tag}"
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
repo_root="$(cd "$script_dir/../.." && pwd -P)"

usage() { printf 'Usage: %s --output-dir <new-absolute-directory-outside-repository>\n' "${0##*/}" >&2; exit 64; }
output_dir=''
withdrawal_address="${HOODI_WITHDRAWAL_ADDRESS:-}"
while [ "$#" -gt 0 ]; do
  case "$1" in --output-dir) output_dir="${2:-}"; shift 2 ;; *) usage ;; esac
done
case "$output_dir" in /*) ;; *) usage ;; esac
if [ -n "$withdrawal_address" ]; then
  [[ "$withdrawal_address" =~ ^0x[0-9a-fA-F]{40}$ ]] || { printf '%s\n' 'HOODI_WITHDRAWAL_ADDRESS must be a 20-byte hex address' >&2; exit 64; }
fi
case "$(uname -s)-$(uname -m)" in Darwin-arm64) ;; *) printf 'This verified helper currently supports Apple Silicon macOS only.\n' >&2; exit 69 ;; esac
for command in curl shasum tar mkdir chmod find gh; do command -v "$command" >/dev/null 2>&1 || { printf 'missing command: %s\n' "$command" >&2; exit 69; }; done

umask 077
mkdir -p "$output_dir/validator_keys"
output_dir="$(cd "$output_dir" && pwd -P)"
protected_repository_root="${NODE_OPERATOR_SOURCE_REPOSITORY_ROOT:-$repo_root}"
case "$output_dir" in "$protected_repository_root"|"$protected_repository_root"/*) printf 'Refusing to write custody material inside the repository.\n' >&2; exit 64 ;; esac
if find "$output_dir/validator_keys" -maxdepth 1 -type f -name 'keystore-*.json' -print -quit | grep -q .; then
  printf 'Refusing to reuse a directory containing a prior validator key.\n' >&2; exit 64
fi
chmod 700 "$output_dir" "$output_dir/validator_keys"
archive="$output_dir/$asset"
checksum_file="$output_dir/$asset.sha256"
cleanup() { unlink "$archive" "$checksum_file" 2>/dev/null || true; }
trap cleanup EXIT

printf 'Downloading and verifying the pinned ethstaker deposit CLI.\n'
curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 --output "$archive" "$release_base_url/$asset"
printf '%s  %s\n' "$asset_sha256" "$asset" > "$checksum_file"
(cd "$output_dir" && shasum -a 256 -c "${asset}.sha256")
gh attestation verify "$archive" --repo ethstaker/ethstaker-deposit-cli
tar -xzf "$archive" -C "$output_dir"
deposit_bin="$(find "$output_dir" -type f -name deposit -perm -u+x -print -quit)"
[ -n "$deposit_bin" ] || { printf 'Verified archive did not contain the deposit executable.\n' >&2; exit 65; }
chmod 700 "$deposit_bin"

printf '%s\n' 'The key ceremony is interactive. Never paste its mnemonic or password into chat, shell history, Git, CI, or cloud storage.'
printf '%s\n' 'Use a Hoodi withdrawal address you control. This is a new operational key; do not use any prior test key.'
deposit_args=(new-mnemonic --num_validators=1 --mnemonic_language=english --chain=hoodi --folder "$output_dir")
[ -n "$withdrawal_address" ] && deposit_args+=(--eth1_withdrawal_address "$withdrawal_address")
"$deposit_bin" "${deposit_args[@]}"

keystore_count="$(find "$output_dir/validator_keys" -maxdepth 1 -type f -name 'keystore-*.json' | wc -l | tr -d ' ')"
# Recent deposit-cli releases place deposit_data alongside the keystore under
# validator_keys; older releases placed it at the output root. Accept either
# layout while preserving the files exactly where the verified tool wrote them.
deposit_files="$(find "$output_dir" -maxdepth 2 -type f -name 'deposit_data-*.json' -print)"
deposit_count="$(printf '%s\n' "$deposit_files" | sed '/^$/d' | wc -l | tr -d ' ')"
[ "$keystore_count" = 1 ] && [ "$deposit_count" = 1 ] || { printf 'Expected exactly one keystore and one deposit-data file. Do not upload or deposit.\n' >&2; exit 65; }
chmod 600 "$output_dir/validator_keys"/* $deposit_files
printf 'PASS: new Hoodi key ceremony completed locally. Next, run validate-hoodi-deposit-data.sh; do not deposit before it passes.\n'
