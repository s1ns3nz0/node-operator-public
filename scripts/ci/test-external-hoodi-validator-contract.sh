#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
observer="$root/scripts/ops/observe-external-hoodi-validator.sh"
tmp="$(mktemp -d /private/tmp/node-operator-external-validator.XXXXXX)"
cleanup() { rm -rf "$tmp"; }
trap cleanup EXIT INT TERM

python3 - "$tmp" <<'PY'
import json
import os
import sys

directory = sys.argv[1]
contract = "0x00000000219ab540356cbb839cbe05303d7705fa"
topic = "0x649bbc62d0e31342afea4e5cd82d4049e7e1ee912fc0889aa790803be39038c5"
transaction = "0x" + "ab" * 32
public_key = bytes.fromhex("11" * 48)
withdrawal = bytes.fromhex("01" + "00" * 11 + "22" * 20)


def encode_event(pubkey=public_key, credentials=withdrawal, amount=(32_000_000_000).to_bytes(8, "little")):
    values = [pubkey, credentials, amount, bytes.fromhex("33" * 96), (0).to_bytes(8, "little")]
    head = bytearray()
    body = bytearray()
    offset = 32 * len(values)
    for value in values:
        head.extend(offset.to_bytes(32, "big"))
        padded = value + b"\x00" * ((32 - len(value) % 32) % 32)
        body.extend(len(value).to_bytes(32, "big") + padded)
        offset += 32 + len(padded)
    return "0x" + (head + body).hex()


def receipt(**changes):
    event = {
        "address": contract,
        "topics": [topic],
        "data": encode_event(),
        "transactionHash": transaction,
        "removed": False,
    }
    result = {
        "status": "0x1",
        "transactionHash": transaction,
        "to": contract,
        "logs": [event],
    }
    for path, value in changes.items():
        if path == "pubkey":
            event["data"] = encode_event(pubkey=value)
        elif path == "amount":
            event["data"] = encode_event(amount=value)
        elif path == "topic":
            event["topics"] = [value]
        elif path == "contract":
            event["address"] = value
        else:
            result[path] = value
    return {"jsonrpc": "2.0", "id": "hoodi-deposit-receipt", "result": result}


with open(os.path.join(directory, "chain.json"), "w", encoding="utf-8") as output:
    json.dump({"jsonrpc": "2.0", "id": "hoodi-chain-id", "result": "0x88bb0"}, output)
fixtures = {
    "valid": receipt(),
    "wrong-key": receipt(pubkey=bytes.fromhex("44" * 48)),
    "wrong-topic": receipt(topic="0x" + "55" * 32),
    "wrong-amount": receipt(amount=(31_000_000_000).to_bytes(8, "little")),
    "wrong-contract": receipt(contract="0x" + "66" * 20),
    "failed-status": receipt(status="0x0"),
    "rpc-error": {"jsonrpc": "2.0", "id": "hoodi-deposit-receipt", "error": {"code": -32000, "message": "synthetic"}},
}
for name, content in fixtures.items():
    with open(os.path.join(directory, f"{name}.json"), "w", encoding="utf-8") as output:
        json.dump(content, output)
PY

mkdir "$tmp/bin"
cat > "$tmp/bin/curl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
output=''; request=''
while [ "$#" -gt 0 ]; do
  case "$1" in
    --output) output="$2"; shift 2 ;;
    --data) request="$2"; shift 2 ;;
    *) shift ;;
  esac
done
case "$request" in
  *'"method":"eth_chainId"'*) cp "$MOCK_CHAIN" "$output" ;;
  *'"method":"eth_getTransactionReceipt"'*) cp "$MOCK_RECEIPT" "$output" ;;
  *) exit 64 ;;
esac
EOF
chmod +x "$tmp/bin/curl"

key="0x$(printf '11%.0s' {1..48})"
withdrawal="0x01$(printf '00%.0s' {1..11})$(printf '22%.0s' {1..20})"
tx="0x$(printf 'ab%.0s' {1..32})"
run_observer() {
  case_name="$1"
  PATH="$tmp/bin:$PATH" MOCK_CHAIN="$tmp/chain.json" MOCK_RECEIPT="$tmp/$case_name.json" BEACONCHAIN_API_TOKEN='' \
    "$observer" --validator-set hoodi-test-001 --validator-public-key "$key" --correlation-id aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa --output-dir "$tmp/out-$case_name" --deposit-tx "$tx" --withdrawal-credentials "$withdrawal" --public-rpc-url https://rpc.example.test >/dev/null
}

run_observer valid
jq -e '.source == "public-rpc" and .payload.chain_id == 560048 and .payload.verification_status == "observed"' "$tmp/out-valid"/*-public-rpc.json >/dev/null
for rejected in wrong-key wrong-topic wrong-amount wrong-contract failed-status rpc-error; do
  if run_observer "$rejected" >/dev/null 2>&1; then
    printf 'external observer accepted invalid synthetic receipt: %s\n' "$rejected" >&2
    exit 1
  fi
done
grep -Fq 'DEPOSIT_EVENT_TOPIC = "0x649bbc62d0e31342afea4e5cd82d4049e7e1ee912fc0889aa790803be39038c5"' "$observer"
grep -Fq 'DEPOSIT_AMOUNT_GWEI = 32_000_000_000' "$observer"
grep -Fq 'source:"public-rpc"' "$observer"
if grep -Fq 'source:"etherscan"' "$observer"; then
  printf '%s\n' 'explicit public RPC was mislabeled as Etherscan' >&2
  exit 1
fi
printf '%s\n' 'PASS: external Hoodi deposit corroboration requires a canonical successful JSON-RPC DepositEvent receipt.'
