#!/bin/sh
# Usage: sh tests/verify-prometheusreceiver-patch.sh /path/to/prometheusreceiver-module
# Validates the patch against a copy so Go's shared module cache is never changed.
set -eu

module_dir=${1:?module directory is required}
patch_file="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)/patches/prometheusreceiver-metric-family.patch"
scratch_dir=$(mktemp -d)
trap 'rm -rf "$scratch_dir"' EXIT HUP INT TERM

test "$(sha256sum "$module_dir/internal/metadata.go" | awk '{print $1}')" = "23f4e8697f83ecefc3d3aae33fc05a0617d16d3373155ffbefcecf9e5ec9e327"
test "$(sha256sum "$module_dir/internal/metricfamily.go" | awk '{print $1}')" = "f65be0b69ee4ff5c9294d417b8634510c7ccee3bb473d666294e4eeedcd608fb"
test "$(sha256sum "$module_dir/internal/transaction.go" | awk '{print $1}')" = "5f456ee16b91e756610dbdd604ac30c21c73a8ef31abea379b812dca3df6168a"
test "$(sha256sum "$module_dir/targetallocator/manager.go" | awk '{print $1}')" = "fd745739940e3cf456840e390c3a4bf1fbb1fe0d2560c8f95e26826e29e2bf11"
test "$(sha256sum "$patch_file" | awk '{print $1}')" = "c3b8f473b146cd5b7044fdc45c9bbc484c4ad068be9513fdfd62b6bb923561d5"

cp -R "$module_dir" "$scratch_dir/module"
chmod -R u+w "$scratch_dir/module"
mkdir "$scratch_dir/tmp"
TMPDIR="$scratch_dir/tmp" patch --batch --fuzz=0 -d "$scratch_dir/module" -p1 < "$patch_file"

test "$(grep -c 'Metric:' "$scratch_dir/module/internal/metadata.go")" -eq 0
test "$(grep -c 'MetricFamily:' "$scratch_dir/module/internal/metadata.go")" -eq 6
test "$(grep -c 'metadata.Metric+metricSuffixCreated' "$scratch_dir/module/internal/metricfamily.go")" -eq 0
test "$(grep -c 'metadata.MetricFamily+metricSuffixCreated' "$scratch_dir/module/internal/metricfamily.go")" -eq 3
test "$(grep -c 'target.DiscoveredLabels()' "$scratch_dir/module/internal/transaction.go")" -eq 0
test "$(grep -c 'target.DiscoveredLabels(labels.NewBuilder(labels.EmptyLabels()))' "$scratch_dir/module/internal/transaction.go")" -eq 1
grep -F 'func (t *transaction) initTransaction(seriesLabels labels.Labels)' "$scratch_dir/module/internal/transaction.go" >/dev/null
grep -F 'rKey, err := t.getJobAndInstance(seriesLabels)' "$scratch_dir/module/internal/transaction.go" >/dev/null
test "$(grep -c 'AlwaysScrapeClassicHistograms = true' "$scratch_dir/module/targetallocator/manager.go")" -eq 0
test "$(grep -c 'AlwaysScrapeClassicHistograms = &alwaysScrapeClassicHistograms' "$scratch_dir/module/targetallocator/manager.go")" -eq 1
