#!/usr/bin/env bash
set -euo pipefail

# Produces a public-only UC-1 deposit attestation. It never sends a transaction,
# reads a wallet, or copies a keystore. The result is suitable for an audit log,
# not a substitute for independently checking the Hoodi Launchpad transaction.

usage() {
  printf 'Usage: %s --deposit-data <absolute-json-file> --withdrawal-address <0x-address> --output-dir <absolute-dir>\n' "${0##*/}" >&2
  exit 64
}

deposit_data=''
withdrawal_address=''
output_dir=''
while [ "$#" -gt 0 ]; do
  case "$1" in
    --deposit-data) deposit_data="${2:-}"; shift 2 ;;
    --withdrawal-address) withdrawal_address="${2:-}"; shift 2 ;;
    --output-dir) output_dir="${2:-}"; shift 2 ;;
    *) usage ;;
  esac
done

case "$deposit_data" in /*) ;; *) usage ;; esac
case "$output_dir" in /*) ;; *) usage ;; esac
case "$withdrawal_address" in 0x[0-9a-fA-F][0-9a-fA-F]*) ;; *) usage ;; esac
for command in jq shasum mkdir date; do command -v "$command" >/dev/null 2>&1 || { printf 'missing command: %s\n' "$command" >&2; exit 69; }; done

[ -r "$deposit_data" ] || { printf 'deposit data is not readable\n' >&2; exit 66; }
[ "${#withdrawal_address}" -eq 42 ] || { printf 'withdrawal address must be exactly 20 bytes\n' >&2; exit 64; }
withdrawal_address="$(printf '%s' "$withdrawal_address" | tr '[:upper:]' '[:lower:]')"
expected_credentials="0x010000000000000000000000${withdrawal_address#0x}"

entry_count="$(jq 'if type == "array" then length else 0 end' "$deposit_data")"
[ "$entry_count" = 1 ] || { printf 'expected exactly one deposit-data entry; found %s\n' "$entry_count" >&2; exit 65; }
network="$(jq -r '.[0].network_name // empty' "$deposit_data")"
# The deposit-cli serializes SSZ byte fields without a 0x prefix, whereas our
# public evidence envelope deliberately stores hexadecimal identifiers with
# one. Accept exactly either representation and normalize only after strict
# length and alphabet validation.
normalize_hex() {
  value="$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')"
  case "$value" in 0x*) value="${value#0x}" ;; esac
  printf '0x%s' "$value"
}
pubkey="$(normalize_hex "$(jq -r '.[0].pubkey // empty' "$deposit_data")")"
amount="$(jq -r '.[0].amount // empty' "$deposit_data")"
credentials="$(normalize_hex "$(jq -r '.[0].withdrawal_credentials // empty' "$deposit_data")")"
printf '%s' "$pubkey" | grep -Eq '^0x[0-9a-f]{96}$' || { printf 'invalid validator public key\n' >&2; exit 65; }
[ "$network" = hoodi ] || { printf 'deposit data network must be hoodi; got %s\n' "$network" >&2; exit 65; }
[ "$amount" = 32000000000 ] || { printf 'deposit amount must be exactly 32000000000 Gwei (32 ETH); got %s\n' "$amount" >&2; exit 65; }
[ "$credentials" = "$expected_credentials" ] || { printf 'withdrawal credentials do not match the supplied address; do not deposit\n' >&2; exit 65; }

mkdir -p "$output_dir"
chmod 700 "$output_dir"
output_dir="$(cd "$output_dir" && pwd -P)"
sha="$(shasum -a 256 "$deposit_data" | awk '{print $1}')"
timestamp="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
attestation="$output_dir/uc-1-deposit-attestation.json"
jq -n --arg created_at_utc "$timestamp" --arg deposit_data_sha256 "$sha" --arg validator_public_key "$pubkey" --arg withdrawal_address "$withdrawal_address" --arg withdrawal_credentials "$credentials" \
  '{use_case:"UC-1",network:"hoodi",amount_gwei:32000000000,created_at_utc:$created_at_utc,deposit_data_sha256:$deposit_data_sha256,validator_public_key:$validator_public_key,withdrawal_address:$withdrawal_address,withdrawal_credentials:$withdrawal_credentials,operator_action_required:"Independently verify these public fields in the Hoodi Launchpad, then sign exactly one 32 HoodiETH deposit with your own wallet."}' > "$attestation"
chmod 600 "$attestation"
printf 'PASS UC-1: public deposit attestation written to %s\n' "$attestation"
