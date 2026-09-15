#!/usr/bin/env bash
set -euo pipefail

# Builds a non-secret manifest from already-redacted evidence. Delivery to the
# Object-Lock archive is a separate identity-controlled step.
usage() { printf '%s\n' "Usage: ${0##*/} --evidence-dir <absolute-dir> --output <absolute-json>" >&2; exit 64; }
evidence_dir=''; output=''
while [ "$#" -gt 0 ]; do case "$1" in --evidence-dir) evidence_dir="${2:-}"; shift 2 ;; --output) output="${2:-}"; shift 2 ;; *) usage ;; esac; done
case "$evidence_dir" in /*) ;; *) usage ;; esac
case "$output" in /*) ;; *) usage ;; esac
for command in find sort shasum jq mktemp mv mkdir dirname basename date wc tr awk unlink; do command -v "$command" >/dev/null 2>&1 || { printf 'missing command: %s\n' "$command" >&2; exit 69; }; done
[ -d "$evidence_dir" ] || { printf '%s\n' 'evidence directory is not readable' >&2; exit 66; }
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
validator="$root/scripts/ops/validate-validator-evidence-envelope.sh"
files="$(find "$evidence_dir" -type f -name '*.json' -print | sort)"
[ -n "$files" ] || { printf '%s\n' 'no evidence JSON files found' >&2; exit 65; }
mkdir -p "$(dirname "$output")"
entries="$(mktemp /private/tmp/node-operator-audit-manifest.XXXXXX)"
temporary="$(mktemp "${output}.tmp.XXXXXX")"
cleanup() { set +e; unlink "$entries" "$temporary" 2>/dev/null || true; }
trap cleanup EXIT INT TERM
while IFS= read -r file; do
  "$validator" --file "$file" >/dev/null
  sha="$(shasum -a 256 "$file" | awk '{print $1}')"
  jq -n --arg file "$(basename "$file")" --arg sha "$sha" --arg event "$(jq -r .event_type "$file")" --arg correlation "$(jq -r .correlation_id "$file")" '{file:$file,sha256:$sha,event_type:$event,correlation_id:$correlation}' >> "$entries"
done <<< "$files"
jq -s --arg created "$(date -u +%Y-%m-%dT%H:%M:%SZ)" '{schema_version:1,event_type:"archive-manifest",created_at_utc:$created,records:.}' "$entries" > "$temporary"
mv "$temporary" "$output"
printf 'PASS: audit manifest with %s redacted evidence records written to %s.\n' "$(wc -l < "$entries" | tr -d ' ')" "$output"
