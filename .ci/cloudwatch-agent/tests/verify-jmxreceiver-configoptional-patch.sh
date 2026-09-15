#!/bin/sh
# Usage: sh tests/verify-jmxreceiver-configoptional-patch.sh /path/to/receiver.go
# Applies the JMX compatibility patch with GNU patch to a private fixture and
# proves an altered, checksum-bound preimage is rejected.
set -eu

source_file=${1:?receiver.go path is required}
root_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
patch_file=${2:-"$root_dir/patches/jmxreceiver-configoptional.patch"}
expected_source_sha=9737f7f30b1fd0e3fa003ba8cdf68f39352932d1323641e38998360b25bc5ebe
expected_patch_sha=093728a3d68de9f20d6bb7e21c5366548391abaa74e4f023b01e7d3297ea914f
scratch_dir=$(mktemp -d)
trap 'rm -rf "$scratch_dir"' EXIT HUP INT TERM

patch --version | grep -F 'GNU patch' >/dev/null
test "$(sha256sum "$source_file" | awk '{print $1}')" = "$expected_source_sha"
test "$(sha256sum "$patch_file" | awk '{print $1}')" = "$expected_patch_sha"

cp "$source_file" "$scratch_dir/receiver.go"
chmod u+w "$scratch_dir/receiver.go"
patch --dry-run --batch --fuzz=0 -d "$scratch_dir" -p1 < "$patch_file"
patch --batch --fuzz=0 -d "$scratch_dir" -p1 < "$patch_file"

grep -F '"go.opentelemetry.io/collector/config/configoptional"' "$scratch_dir/receiver.go" >/dev/null
grep -F '"go.opentelemetry.io/collector/confmap"' "$scratch_dir/receiver.go" >/dev/null
grep -F 'func insertDefault[T any](opt *configoptional.Optional[T]) error {' "$scratch_dir/receiver.go" >/dev/null
grep -F 'if err := insertDefault(&config.GRPC); err != nil {' "$scratch_dir/receiver.go" >/dev/null
grep -F 'config.GRPC.Get().NetAddr = confignet.AddrConfig{Endpoint: endpoint, Transport: confignet.TransportTypeTCP}' "$scratch_dir/receiver.go" >/dev/null
! grep -F 'config.HTTP = nil' "$scratch_dir/receiver.go" >/dev/null

mkdir "$scratch_dir/tampered"
cp "$source_file" "$scratch_dir/tampered/receiver.go"
chmod u+w "$scratch_dir/tampered/receiver.go"
sed -i.bak 's/config\.HTTP = nil/config.HTTP = disabled/' "$scratch_dir/tampered/receiver.go"
rm -f "$scratch_dir/tampered/receiver.go.bak"
if patch --dry-run --batch --fuzz=0 -d "$scratch_dir/tampered" -p1 < "$patch_file"; then
  echo 'expected changed preimage to reject the patch' >&2
  exit 1
fi
