#!/usr/bin/env bash
set -euo pipefail

# Rebuilds a derived, public-only OpenSearch bulk payload from canonical
# evidence. It never ingests raw application logs or Vault audit bodies.
usage() { printf 'Usage: %s --evidence-dir <absolute-dir> --output <absolute-ndjson>\n' "${0##*/}" >&2; exit 64; }
evidence_dir=''; output=''
while [ "$#" -gt 0 ]; do
  case "$1" in --evidence-dir) evidence_dir="${2:-}"; shift 2 ;; --output) output="${2:-}"; shift 2 ;; *) usage ;; esac
done
case "$evidence_dir" in /*) ;; *) usage ;; esac
case "$output" in /*) ;; *) usage ;; esac
for command in jq find shasum mkdir; do command -v "$command" >/dev/null 2>&1 || { printf 'missing command: %s\n' "$command" >&2; exit 69; }; done
[ -d "$evidence_dir" ] || { printf 'evidence directory does not exist\n' >&2; exit 66; }
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
validator="$script_dir/validate-validator-evidence-envelope.sh"
[ -x "$validator" ] || { printf 'evidence validator is missing\n' >&2; exit 69; }
mkdir -p "$(dirname "$output")"; : > "$output"; chmod 600 "$output"
count=0
while IFS= read -r evidence; do
  "$validator" --file "$evidence" >/dev/null
  digest="$(shasum -a 256 "$evidence" | awk '{print $1}')"
  jq -cn --arg id "$digest" '{index:{_index:"hoodi-validator-evidence-v1",_id:$id}}' >> "$output"
  jq -c --arg id "$digest" '
    {event_id:$id,"@timestamp":.collected_at_utc,event_type:.event_type,correlation_id:.correlation_id,network:.network,validator_set:.validator_set,validator_public_key:.validator_public_key,source:.source,
     validator_index:(.payload.validator.validator.index? // .payload.validator_index? // null),validator_status:(.payload.validator.validator.status? // .payload.status? // null),transaction_hash:(.payload.transaction_hash? // null),explorer_url:(.payload.explorer_url? // null),response_sha256:(.payload.response_sha256? // null),release_sha:(.payload.release_sha? // null)}' "$evidence" >> "$output"
  count=$((count + 1))
done < <(find "$evidence_dir" -type f -name '*.json' -print | sort)
[ "$count" -gt 0 ] || { printf 'no evidence JSON files found\n' >&2; exit 65; }
printf 'PASS: built %s public-only OpenSearch bulk records in %s\n' "$count" "$output"
