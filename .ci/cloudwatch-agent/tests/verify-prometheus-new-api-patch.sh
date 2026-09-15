#!/bin/sh
# Usage: sh tests/verify-prometheus-new-api-patch.sh /path/to/prometheusreceiver-module
# Runs GNU patch against a private fixture and rejects an altered preimage.
set -eu

module_dir=${1:?prometheusreceiver module directory is required}
root_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
patch_file="$root_dir/patches/prometheus-new-api.patch"
expected_source_sha=0300f81650a05684ff378d81d15668c394d43fd14dcb784d7a308e4809f8ea82
expected_patch_sha=87e993a6869906cb14ef642f9f46f3b26c9f7ee99a342bb7b60a3b19b5e35a2d
scratch_dir=$(mktemp -d)
trap 'rm -rf "$scratch_dir"' EXIT HUP INT TERM

patch --version | grep -F 'GNU patch' >/dev/null
test "$(sha256sum "$module_dir/metrics_receiver.go" | awk '{print $1}')" = "$expected_source_sha"
test "$(sha256sum "$patch_file" | awk '{print $1}')" = "$expected_patch_sha"

cp "$module_dir/metrics_receiver.go" "$scratch_dir/metrics_receiver.go"
chmod u+w "$scratch_dir/metrics_receiver.go"
patch --dry-run --batch --fuzz=0 -d "$scratch_dir" -p1 < "$patch_file"
patch --batch --fuzz=0 -d "$scratch_dir" -p1 < "$patch_file"
grep -F '&api_v1.PrometheusVersion{' "$scratch_dir/metrics_receiver.go" >/dev/null
! grep -F '&web.PrometheusVersion{' "$scratch_dir/metrics_receiver.go" >/dev/null
grep -F 'o.EnableOTLPWriteReceiver,' "$scratch_dir/metrics_receiver.go" >/dev/null
grep -F 'o.ConvertOTLPDelta,' "$scratch_dir/metrics_receiver.go" >/dev/null
grep -F 'o.NativeOTLPDeltaIngestion,' "$scratch_dir/metrics_receiver.go" >/dev/null
grep -F 'o.CTZeroIngestionEnabled,' "$scratch_dir/metrics_receiver.go" >/dev/null
otlp_line=$(grep -n -F 'o.EnableOTLPWriteReceiver,' "$scratch_dir/metrics_receiver.go" | cut -d: -f1)
convert_line=$(grep -n -F 'o.ConvertOTLPDelta,' "$scratch_dir/metrics_receiver.go" | cut -d: -f1)
native_line=$(grep -n -F 'o.NativeOTLPDeltaIngestion,' "$scratch_dir/metrics_receiver.go" | cut -d: -f1)
ctzero_line=$(grep -n -F 'o.CTZeroIngestionEnabled,' "$scratch_dir/metrics_receiver.go" | cut -d: -f1)
test "$otlp_line" -lt "$convert_line"
test "$convert_line" -lt "$native_line"
test "$native_line" -lt "$ctzero_line"

mkdir "$scratch_dir/tampered"
cp "$module_dir/metrics_receiver.go" "$scratch_dir/tampered/metrics_receiver.go"
chmod u+w "$scratch_dir/tampered/metrics_receiver.go"
sed -i.bak 's/web\.PrometheusVersion/web.LegacyPrometheusVersion/' "$scratch_dir/tampered/metrics_receiver.go"
rm -f "$scratch_dir/tampered/metrics_receiver.go.bak"
if patch --dry-run --batch --fuzz=0 -d "$scratch_dir/tampered" -p1 < "$patch_file"; then
  echo 'expected altered NewAPI preimage to reject the patch' >&2
  exit 1
fi
