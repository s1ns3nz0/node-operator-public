#!/bin/sh
# Verifies the one archived compatibility module's lock and source bytes.
set -eu

test "$#" -eq 3 || {
  echo "usage: $0 lock-file expected-lock-sha256 module-directory" >&2
  exit 64
}

lock_file=$1
expected_lock_sha=$2
module_dir=$3

test "$(sha256sum "$lock_file" | awk '{print $1}')" = "$expected_lock_sha" || {
  echo "legacy expandconverter lock checksum mismatch" >&2
  exit 1
}

lock_value() {
  key=$1
  value=$(sed -n "s/^${key}=//p" "$lock_file")
  test -n "$value" || {
    echo "missing legacy lock field: $key" >&2
    exit 1
  }
  printf '%s\n' "$value"
}

module=$(lock_value module)
version=$(lock_value version)
go_mod_sha=$(lock_value go_mod_sha256)
expand_go_sha=$(lock_value expand_go_sha256)

case "$module" in
  go.opentelemetry.io/collector/confmap/converter/expandconverter) ;;
  *) echo "unexpected archived module: $module" >&2; exit 1 ;;
esac
test "$version" = v0.113.0 || {
  echo "unexpected archived module version: $version" >&2
  exit 1
}
test -f "$module_dir/go.mod"
test -f "$module_dir/expand.go"
test "$(sha256sum "$module_dir/go.mod" | awk '{print $1}')" = "$go_mod_sha" || {
  echo "legacy expandconverter go.mod checksum mismatch" >&2
  exit 1
}
test "$(sha256sum "$module_dir/expand.go" | awk '{print $1}')" = "$expand_go_sha" || {
  echo "legacy expandconverter expand.go checksum mismatch" >&2
  exit 1
}
