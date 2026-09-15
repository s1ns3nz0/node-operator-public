#!/usr/bin/env bash
set -euo pipefail

usage() { printf 'Usage: %s --file <evidence-json>\n' "${0##*/}" >&2; exit 64; }
[ "$#" = 2 ] && [ "$1" = --file ] || usage
evidence_file="$2"
[ -r "$evidence_file" ] || { printf 'evidence file is not readable\n' >&2; exit 66; }
command -v jq >/dev/null 2>&1 || { printf 'missing command: jq\n' >&2; exit 69; }

jq -e '
  .schema_version == 1 and
  (.event_type | IN("uc-1", "uc-2", "uc-3", "uc-4", "uc-5", "archive-manifest", "source-disagreement")) and
  (.network == "hoodi") and
  (.validator_set | test("^hoodi-[a-z0-9][a-z0-9-]*$")) and
  (.validator_public_key | test("^0x[0-9a-fA-F]{96}$")) and
  (.correlation_id | test("^[a-f0-9-]{16,64}$")) and
  (.source | IN("private-beacon", "vault-audit", "kubernetes", "etherscan", "public-rpc", "beaconcha-in", "archive")) and
  (.payload | type == "object")
' "$evidence_file" >/dev/null || { printf 'evidence envelope is invalid\n' >&2; exit 65; }

if jq -e '[.. | objects | keys[]? | ascii_downcase | test("mnemonic|keystore|password|token|recovery|kubeconfig|secret_access_key")] | any' "$evidence_file" >/dev/null; then
  printf 'evidence contains a forbidden field name\n' >&2
  exit 65
fi
printf 'PASS: validator evidence envelope is schema-valid and contains no forbidden field names.\n'
