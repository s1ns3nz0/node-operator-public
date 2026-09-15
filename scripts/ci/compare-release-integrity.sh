#!/usr/bin/env bash
# Purpose: Compare required current release metadata against the previous approved release.
# Inputs: Previous directory, current directory, and output JSON path.
# Outputs: Integrity JSON containing bounded diffs and identical|changed status.
# Side effects: Read-only local comparisons plus temporary and output-file writes; no release mutation.
set -euo pipefail

if [ "$#" -ne 3 ]; then
  printf 'usage: %s PREVIOUS_DIR CURRENT_DIR OUTPUT_JSON\n' "$0" >&2
  exit 64
fi
previous="$1"; current="$2"; output="$3"
for name in manifest.json sbom.cyclonedx.json provenance-input.json; do
  [ -f "$previous/$name" ] || { printf 'previous artifact missing %s\n' "$name" >&2; exit 1; }
  [ -f "$current/$name" ] || { printf 'current artifact missing %s\n' "$name" >&2; exit 1; }
done
mkdir -p "$(dirname "$output")"
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
diff -u "$previous/manifest.json" "$current/manifest.json" > "$tmp/manifest.diff" || true
diff -u "$previous/sbom.cyclonedx.json" "$current/sbom.cyclonedx.json" > "$tmp/sbom.diff" || true
diff -u "$previous/provenance-input.json" "$current/provenance-input.json" > "$tmp/provenance.diff" || true
jq -n --rawfile manifest "$tmp/manifest.diff" --rawfile sbom "$tmp/sbom.diff" --rawfile provenance "$tmp/provenance.diff" \
  '{schema_version:"v1",status:(if ($manifest=="" and $sbom=="" and $provenance=="") then "identical" else "changed" end),manifest_diff:$manifest,sbom_diff:$sbom,provenance_diff:$provenance}' > "$output"
