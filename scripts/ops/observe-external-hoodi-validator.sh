#!/usr/bin/env bash
set -euo pipefail

# Public corroboration only. Private Beacon results remain operational truth.
# BEACONCHAIN_API_TOKEN is read only from the environment. It is never emitted,
# retained in evidence, or placed in a URL. Deposit corroboration uses an
# explicit JSON-RPC endpoint, not an explorer label.
usage() { printf 'Usage: %s --validator-set <hoodi-id> --validator-public-key <0x-key> --correlation-id <id> --output-dir <absolute-dir> [--deposit-tx <0x-hash> --withdrawal-credentials <0x-credentials> --public-rpc-url <https-url>]\n' "${0##*/}" >&2; exit 64; }
validator_set=''; public_key=''; correlation_id=''; output_dir=''; deposit_tx=''; withdrawal_credentials=''; public_rpc_url=''
while [ "$#" -gt 0 ]; do
  case "$1" in
    --validator-set) validator_set="${2:-}"; shift 2 ;;
    --validator-public-key) public_key="${2:-}"; shift 2 ;;
    --correlation-id) correlation_id="${2:-}"; shift 2 ;;
    --output-dir) output_dir="${2:-}"; shift 2 ;;
    --deposit-tx) deposit_tx="${2:-}"; shift 2 ;;
    --withdrawal-credentials) withdrawal_credentials="${2:-}"; shift 2 ;;
    --public-rpc-url) public_rpc_url="${2:-}"; shift 2 ;;
    *) usage ;;
  esac
done
case "$validator_set" in hoodi-[a-z0-9][a-z0-9-]*) ;; *) usage ;; esac
case "$public_key" in 0x????????????????????????????????????????????????????????????????????????????????????????????????) ;; *) usage ;; esac
case "$correlation_id" in [a-f0-9-][a-f0-9-][a-f0-9-][a-f0-9-][a-f0-9-][a-f0-9-][a-f0-9-][a-f0-9-]*) ;; *) usage ;; esac
case "$output_dir" in /*) ;; *) usage ;; esac
case "$deposit_tx" in ''|0x????????????????????????????????????????????????????????????????) ;; *) usage ;; esac
case "$withdrawal_credentials" in ''|0x????????????????????????????????????????????????????????????????) ;; *) usage ;; esac
case "$public_rpc_url" in ''|https://*) ;; *) usage ;; esac
case "$public_rpc_url" in *'?'*|*'#'*|*'@'*) usage ;; esac
for command in curl jq shasum mkdir date mktemp unlink chmod; do command -v "$command" >/dev/null 2>&1 || { printf 'missing command: %s\n' "$command" >&2; exit 69; }; done

mkdir -p "$output_dir"; chmod 700 "$output_dir"; output_dir="$(cd "$output_dir" && pwd -P)"
timestamp="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
deposit_contract='0x00000000219ab540356cbb839cbe05303d7705fa'
record_base="$output_dir/external-$(date -u +%Y%m%dT%H%M%SZ)"

beacon_tmp="$(mktemp /private/tmp/node-operator-beaconcha.XXXXXX)"
beacon_config="$(mktemp /private/tmp/node-operator-beaconcha-curl.XXXXXX)"
trap 'unlink "$beacon_tmp" "$beacon_config" "${rpc_chain_tmp:-}" "${rpc_receipt_tmp:-}" 2>/dev/null || true' EXIT
beacon_url='https://beaconcha.in/api/v2/ethereum/validators'
beacon_result='not-configured'
if [ -n "${BEACONCHAIN_API_TOKEN:-}" ]; then
  chmod 600 "$beacon_config"
  printf '%s\n' 'header = "Content-Type: application/json"' "header = \"Authorization: Bearer ${BEACONCHAIN_API_TOKEN}\"" > "$beacon_config"
  beacon_request="$(jq -cn --arg key "$public_key" '{chain:"hoodi",validator:{validator_identifiers:[$key]},page_size:1}')"
  if curl --fail --silent --show-error --max-time 20 --config "$beacon_config" --request POST --header 'Accept: application/json' --data "$beacon_request" --output "$beacon_tmp" "$beacon_url"; then beacon_result='observed'; else beacon_result='unavailable'; printf '{}' > "$beacon_tmp"; fi
else
  printf '{}' > "$beacon_tmp"
fi
beacon_sha="$(shasum -a 256 "$beacon_tmp" | awk '{print $1}')"
jq -n --arg collected "$timestamp" --arg correlation "$correlation_id" --arg set "$validator_set" --arg key "$public_key" --arg url "$beacon_url" --arg result "$beacon_result" --arg sha "$beacon_sha" \
  '{schema_version:1,event_type:"uc-3",collected_at_utc:$collected,correlation_id:$correlation,network:"hoodi",validator_set:$set,validator_public_key:$key,source:"beaconcha-in",payload:{verification_status:$result,explorer_url:$url,api_version:"v2",response_sha256:$sha}}' > "${record_base}-beaconcha-in.json"

if [ -n "$deposit_tx" ]; then
  [ -n "$withdrawal_credentials" ] && [ -n "$public_rpc_url" ] || { printf '%s\n' 'deposit receipt validation requires --withdrawal-credentials and --public-rpc-url' >&2; exit 64; }
  command -v python3 >/dev/null 2>&1 || { printf '%s\n' 'missing command: python3' >&2; exit 69; }
  rpc_chain_tmp="$(mktemp /private/tmp/node-operator-hoodi-rpc-chain.XXXXXX)"
  rpc_receipt_tmp="$(mktemp /private/tmp/node-operator-hoodi-rpc-receipt.XXXXXX)"
  rpc_chain_request='{"jsonrpc":"2.0","id":"hoodi-chain-id","method":"eth_chainId","params":[]}'
  rpc_receipt_request="$(jq -cn --arg tx "$deposit_tx" '{jsonrpc:"2.0",id:"hoodi-deposit-receipt",method:"eth_getTransactionReceipt",params:[$tx]}')"
  curl --fail --silent --show-error --max-time 20 --request POST --header 'Content-Type: application/json' --header 'Accept: application/json' --data "$rpc_chain_request" --output "$rpc_chain_tmp" "$public_rpc_url"
  curl --fail --silent --show-error --max-time 20 --request POST --header 'Content-Type: application/json' --header 'Accept: application/json' --data "$rpc_receipt_request" --output "$rpc_receipt_tmp" "$public_rpc_url"

  # The canonical deposit contract emits an unindexed DepositEvent(bytes,bytes,
  # bytes,bytes,bytes). Validate all ABI data against the requested public
  # values; a successful receipt with any arbitrary contract log is not proof.
  python3 - "$rpc_chain_tmp" "$rpc_receipt_tmp" "$deposit_tx" "$public_key" "$withdrawal_credentials" "$deposit_contract" <<'PY'
import json
import re
import sys

CHAIN_ID = "0x88bb0"
DEPOSIT_EVENT_TOPIC = "0x649bbc62d0e31342afea4e5cd82d4049e7e1ee912fc0889aa790803be39038c5"
DEPOSIT_AMOUNT_GWEI = 32_000_000_000
HEX = re.compile(r"^0x[0-9a-fA-F]*$")


class Rejected(Exception):
    pass


def decode_hex(value, size=None):
    if not isinstance(value, str) or not HEX.fullmatch(value) or len(value[2:]) % 2:
        raise Rejected()
    decoded = bytes.fromhex(value[2:])
    if size is not None and len(decoded) != size:
        raise Rejected()
    return decoded


def rpc_result(path, request_id):
    try:
        with open(path, encoding="utf-8") as response_file:
            response = json.load(response_file)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        raise Rejected() from None
    if not isinstance(response, dict) or set(response) != {"jsonrpc", "id", "result"}:
        raise Rejected()
    if response["jsonrpc"] != "2.0" or response["id"] != request_id or response["result"] is None:
        raise Rejected()
    return response["result"]


def decode_canonical_event(data):
    encoded = decode_hex(data)
    head_size = 32 * 5
    if len(encoded) < head_size:
        raise Rejected()
    values = []
    cursor = head_size
    for position in range(5):
        offset = int.from_bytes(encoded[position * 32:(position + 1) * 32], "big")
        if offset != cursor or offset % 32:
            raise Rejected()
        if cursor + 32 > len(encoded):
            raise Rejected()
        length = int.from_bytes(encoded[cursor:cursor + 32], "big")
        value_start = cursor + 32
        value_end = value_start + length
        padded_end = (value_end + 31) // 32 * 32
        if value_end > len(encoded) or padded_end > len(encoded) or any(encoded[value_end:padded_end]):
            raise Rejected()
        values.append(encoded[value_start:value_end])
        cursor = padded_end
    if cursor != len(encoded):
        raise Rejected()
    return values


try:
    chain_id = rpc_result(sys.argv[1], "hoodi-chain-id")
    receipt = rpc_result(sys.argv[2], "hoodi-deposit-receipt")
    requested_tx = decode_hex(sys.argv[3], 32).hex()
    requested_pubkey = decode_hex(sys.argv[4], 48)
    requested_withdrawal_credentials = decode_hex(sys.argv[5], 32)
    contract = decode_hex(sys.argv[6], 20).hex()
    if chain_id != CHAIN_ID or not isinstance(receipt, dict):
        raise Rejected()
    if receipt.get("status") != "0x1":
        raise Rejected()
    if decode_hex(receipt.get("transactionHash"), 32).hex() != requested_tx:
        raise Rejected()
    if decode_hex(receipt.get("to"), 20).hex() != contract:
        raise Rejected()
    logs = receipt.get("logs")
    if not isinstance(logs, list):
        raise Rejected()
    matches = []
    for log in logs:
        if not isinstance(log, dict) or log.get("removed", False) is not False:
            raise Rejected()
        if decode_hex(log.get("address"), 20).hex() != contract:
            continue
        if log.get("topics") != [DEPOSIT_EVENT_TOPIC]:
            raise Rejected()
        if decode_hex(log.get("transactionHash"), 32).hex() != requested_tx:
            raise Rejected()
        matches.append(decode_canonical_event(log.get("data")))
    if len(matches) != 1:
        raise Rejected()
    pubkey, withdrawal_credentials, amount, signature, index = matches[0]
    if pubkey != requested_pubkey or withdrawal_credentials != requested_withdrawal_credentials:
        raise Rejected()
    if amount != DEPOSIT_AMOUNT_GWEI.to_bytes(8, "little") or len(signature) != 96 or len(index) != 8:
        raise Rejected()
except (IndexError, OSError, Rejected, TypeError, ValueError, UnicodeDecodeError):
    print("Hoodi deposit receipt validation rejected an error, malformed response, or non-canonical event", file=sys.stderr)
    sys.exit(65)
PY
  receipt_sha="$(shasum -a 256 "$rpc_receipt_tmp" | awk '{print $1}')"
  jq -n --arg collected "$timestamp" --arg correlation "$correlation_id" --arg set "$validator_set" --arg key "$public_key" --arg tx "$deposit_tx" --arg sha "$receipt_sha" \
    '{schema_version:1,event_type:"uc-1",collected_at_utc:$collected,correlation_id:$correlation,network:"hoodi",validator_set:$set,validator_public_key:$key,source:"public-rpc",payload:{verification_status:"observed",chain_id:560048,transaction_hash:$tx,deposit_contract_event_observed:true,response_sha256:$sha}}' > "${record_base}-public-rpc.json"
fi
printf 'PASS: external corroboration evidence written with no explorer response body retained.\n'
