#!/bin/sh
# Validates or emits the official v0.128 core-module mapping for a Go closure.
set -eu

usage() {
  echo "usage: $0 verify|emit map.yaml map-sha256 legacy.lock legacy-lock-sha256 modules.txt" >&2
  exit 64
}

test "$#" -eq 6 || usage
mode=$1
map_file=$2
expected_sha=$3
legacy_lock=$4
expected_legacy_lock_sha=$5
modules_file=$6

test -f "$map_file"
test -f "$legacy_lock"
test -f "$modules_file"
actual_sha=$(sha256sum "$map_file" | awk '{print $1}')
test "$actual_sha" = "$expected_sha" || {
  echo "OpenTelemetry module map checksum mismatch" >&2
  exit 1
}
test "$(sha256sum "$legacy_lock" | awk '{print $1}')" = "$expected_legacy_lock_sha" || {
  echo "legacy expandconverter lock checksum mismatch" >&2
  exit 1
}
legacy_module=$(sed -n 's/^module=//p' "$legacy_lock")
legacy_version=$(sed -n 's/^version=//p' "$legacy_lock")
test "$legacy_module" = go.opentelemetry.io/collector/confmap/converter/expandconverter
test "$legacy_version" = v0.113.0

scratch_dir=$(mktemp -d)
trap 'rm -rf "$scratch_dir"' EXIT HUP INT TERM
mapping="$scratch_dir/mapping.txt"

awk '
  $1 == "stable:" { set = "stable"; version = ""; next }
  $1 == "beta:" { set = "beta"; version = ""; next }
  $1 == "excluded-modules:" { set = ""; version = ""; next }
  set != "" && $1 == "version:" { version = $2; next }
  set != "" && $1 == "-" && $2 ~ /^go\.opentelemetry\.io\/collector/ {
    if (version == "") { exit 2 }
    print $2, version
  }
' "$map_file" | sort -u > "$mapping"

test -s "$mapping" || {
  echo "OpenTelemetry module map contains no modules" >&2
  exit 1
}

case "$mode" in
  verify|emit) ;;
  *) usage ;;
esac

core_rows=0
while IFS=' ' read -r module version extra; do
  if test "$module" = "$legacy_module"; then
    test -n "$version" && test -z "$extra" && test "$version" = "$legacy_version" || {
      echo "legacy expandconverter version mismatch: selected $version expected $legacy_version" >&2
      exit 1
    }
    if test "$mode" = emit; then
      printf '%s@%s\n' "$legacy_module" "$legacy_version"
    fi
    continue
  fi
  case "$module" in
    '') continue ;;
    go.opentelemetry.io/collector|go.opentelemetry.io/collector/*)
      test -n "$version" && test -z "$extra" || {
        echo "invalid OpenTelemetry core closure record: $module${version:+ $version}${extra:+ $extra}" >&2
        exit 1
      }
      core_rows=$((core_rows + 1))
      ;;
    *) continue ;;
  esac
  expected=$(awk -v module="$module" '$1 == module { print $2; exit }' "$mapping")
  test -n "$expected" || {
    echo "unmapped OpenTelemetry core module: $module" >&2
    exit 1
  }
  if test "$mode" = emit; then
    printf '%s@%s\n' "$module" "$expected"
  elif test "$version" != "$expected"; then
    echo "OpenTelemetry core version mismatch: $module selected $version expected $expected" >&2
    exit 1
  fi
done < "$modules_file"

test "$core_rows" -gt 0 || {
  echo "production closure contains no OpenTelemetry core modules" >&2
  exit 1
}
