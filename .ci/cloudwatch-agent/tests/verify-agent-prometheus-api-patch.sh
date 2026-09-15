#!/bin/sh
# Usage: sh tests/verify-agent-prometheus-api-patch.sh /pinned/cwa/source
# Validates the four-file agent compatibility patch against private fixtures.
set -eu

source_root=${1:?pinned CloudWatch Agent source directory is required}
root_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
patch_file="$root_dir/patches/agent-prometheus-api.patch"
expected_patch_sha=391df71072d838d66c77447bd4ecca4b667e52dbf625e1653d533411169f2592
scratch_dir=$(mktemp -d)
trap 'rm -rf "$scratch_dir"' EXIT HUP INT TERM

check_hash() {
  expected=$1
  path=$2
  test "$(sha256sum "$path" | awk '{print $1}')" = "$expected"
}

patch --version | grep -F 'GNU patch' >/dev/null
check_hash a66d2613eb6cd171e1bfa6d90acc665a31e236258fd19ac772491f051344f3a5 "$source_root/plugins/inputs/prometheus/target_allocator.go"
check_hash bdea2a14351f7717c9dc9afcf1bfce08dcbc23a12c64246f2668272be6bb1856 "$source_root/plugins/inputs/prometheus/metrics_receiver.go"
check_hash 380adb6b4578c1b69895317ba3cb14cbb6c47c203aba1d4de2e68411dc8d7482 "$source_root/plugins/inputs/prometheus/metrics_type_handler.go"
check_hash cb47b97775443d030c02d39e66664325f2d2c76b3c3051d6e4e16adbec8f173c "$source_root/plugins/inputs/prometheus/start.go"
check_hash "$expected_patch_sha" "$patch_file"

mkdir -p "$scratch_dir/source/plugins/inputs"
cp -R "$source_root/plugins/inputs/prometheus" "$scratch_dir/source/plugins/inputs/prometheus"
chmod -R u+w "$scratch_dir/source"
patch --dry-run --batch --fuzz=0 -d "$scratch_dir/source" -p1 < "$patch_file"
patch --batch --fuzz=0 -d "$scratch_dir/source" -p1 < "$patch_file"
test -z "$(gofmt -d "$scratch_dir/source/plugins/inputs/prometheus/target_allocator.go" "$scratch_dir/source/plugins/inputs/prometheus/metrics_receiver.go" "$scratch_dir/source/plugins/inputs/prometheus/metrics_type_handler.go" "$scratch_dir/source/plugins/inputs/prometheus/start.go")"
! grep -E 'AllowedLevel|TLSSetting' "$scratch_dir/source/plugins/inputs/prometheus/target_allocator.go" >/dev/null
! grep -E 'AllowedLevel|AllowedFormat' "$scratch_dir/source/plugins/inputs/prometheus/start.go" >/dev/null
! grep -F 'DiscoveredLabels()' "$scratch_dir/source/plugins/inputs/prometheus/metrics_type_handler.go" >/dev/null
grep -F 'promslog.NewLevel()' "$scratch_dir/source/plugins/inputs/prometheus/start.go" >/dev/null
grep -F 'promslog.NewFormat()' "$scratch_dir/source/plugins/inputs/prometheus/start.go" >/dev/null
test "$(grep -c 'TargetAllocator.TLS\.' "$scratch_dir/source/plugins/inputs/prometheus/target_allocator.go")" -eq 4
grep -F 'labelMap := make(map[string]string, ls.Len())' "$scratch_dir/source/plugins/inputs/prometheus/metrics_receiver.go" >/dev/null
grep -F 'ls.Range(func(l labels.Label) {' "$scratch_dir/source/plugins/inputs/prometheus/metrics_receiver.go" >/dev/null
awk '/metricName = l.Value/ { getline; if ($0 ~ /^[[:space:]]*return$/) found = 1 } END { exit !found }' "$scratch_dir/source/plugins/inputs/prometheus/metrics_receiver.go"
test "$(grep -c 'target.DiscoveredLabels(labels.NewBuilder(labels.EmptyLabels()))' "$scratch_dir/source/plugins/inputs/prometheus/metrics_type_handler.go")" -eq 1

mkdir -p "$scratch_dir/tampered/plugins/inputs"
cp -R "$source_root/plugins/inputs/prometheus" "$scratch_dir/tampered/plugins/inputs/prometheus"
chmod -R u+w "$scratch_dir/tampered"
sed -i.bak 's/labelMap := make(map\[string\]string, len(ls))/labelMap := make(map[string]string, changedLen(ls))/' "$scratch_dir/tampered/plugins/inputs/prometheus/metrics_receiver.go"
rm -f "$scratch_dir/tampered/plugins/inputs/prometheus/metrics_receiver.go.bak"
if patch --dry-run --batch --fuzz=0 -d "$scratch_dir/tampered" -p1 < "$patch_file"; then
  echo 'expected altered agent preimage to reject the patch' >&2
  exit 1
fi
