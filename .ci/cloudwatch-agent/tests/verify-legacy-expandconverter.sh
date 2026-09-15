#!/bin/sh
# Verifies that the archived converter bytes, not merely its version, are locked.
set -eu

root_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
verifier="$root_dir/scripts/verify-legacy-expandconverter.sh"
lock_file="$root_dir/legacy-expandconverter.lock"
lock_sha=19681f3395929434cc5eea397f1bf73089cdd33c4f2be257b702735895549772
module_dir=/Users/s1ns3nz0/go/pkg/mod/go.opentelemetry.io/collector/confmap/converter/expandconverter@v0.113.0
scratch_dir=$(mktemp -d)
trap 'rm -rf "$scratch_dir"' EXIT HUP INT TERM

test -d "$module_dir"
sh "$verifier" "$lock_file" "$lock_sha" "$module_dir"

cp -R "$module_dir" "$scratch_dir/module"
chmod -R u+w "$scratch_dir/module"
printf '\n// tampered fixture\n' >> "$scratch_dir/module/expand.go"
if sh "$verifier" "$lock_file" "$lock_sha" "$scratch_dir/module"; then
  echo 'tampered archived converter was accepted' >&2
  exit 1
fi
