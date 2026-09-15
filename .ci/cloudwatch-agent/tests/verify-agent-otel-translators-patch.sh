#!/bin/sh
# Usage: sh tests/verify-agent-otel-translators-patch.sh /pinned/cwa/source
# Applies the translator compatibility patch only to private source fixtures.
set -eu

source_root=${1:?pinned CloudWatch Agent source directory is required}
root_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
patch_file="$root_dir/patches/agent-otel-translators.patch"
expected_patch_sha=d7a5022563217e495d4be1b56c4eca9fe6a9652e00531413c9a575813619549b
scratch_dir=$(mktemp -d)
trap 'rm -rf "$scratch_dir"' EXIT HUP INT TERM

check_hash() {
  expected=$1
  path=$2
  test "$(sha256sum "$path" | awk '{print $1}')" = "$expected"
}

patch --version | grep -F 'GNU patch' >/dev/null
check_hash f9ebe6105d57b83c8861f32d276d6de9d3b1001d98710c9ceb139b28f5c7a67f "$source_root/translator/translate/otel/exporter/otlphttp/translator.go"
check_hash 07020b847fc14fca3120440e08553a8bb273ab35d94452233182101d8e548662 "$source_root/translator/translate/otel/exporter/prometheusremotewrite/translator.go"
check_hash 14844f5c0be24ba58ba9619cb94242e1e8e11d3d660c8583462c733be1c6363f "$source_root/translator/translate/otel/receiver/otlp/translator.go"
check_hash 0716816ef98fe82522990414c9b5dc4d9d496b5fe108b0f202c1b7d96b38eb8d "$source_root/translator/translate/otel/receiver/prometheus/translator.go"
check_hash "$expected_patch_sha" "$patch_file"

mkdir -p "$scratch_dir/source"
for file in \
  translator/translate/otel/exporter/otlphttp/translator.go \
  translator/translate/otel/exporter/prometheusremotewrite/translator.go \
  translator/translate/otel/receiver/otlp/translator.go \
  translator/translate/otel/receiver/prometheus/translator.go; do
  mkdir -p "$scratch_dir/source/$(dirname "$file")"
  cp "$source_root/$file" "$scratch_dir/source/$file"
done
chmod -R u+w "$scratch_dir/source"
patch --dry-run --batch --fuzz=0 -d "$scratch_dir/source" -p1 < "$patch_file"
patch --batch --fuzz=0 -d "$scratch_dir/source" -p1 < "$patch_file"
test -z "$(gofmt -d $(find "$scratch_dir/source" -name '*.go' -print))"
! grep -R -E 'configauth\.Authentication|TLSSetting|cfg\.GRPC = nil|cfg\.HTTP = nil' "$scratch_dir/source" --include '*.go' >/dev/null
test "$(grep -R -h -c 'configauth.Config' "$scratch_dir/source/translator/translate/otel/exporter" | awk '{sum += $1} END {print sum + 0}')" -eq 2
grep -F 'cfg.GRPC = configoptional.None[configgrpc.ServerConfig]()' "$scratch_dir/source/translator/translate/otel/receiver/otlp/translator.go" >/dev/null
grep -F 'cfg.HTTP = configoptional.None[otlpreceiver.HTTPConfig]()' "$scratch_dir/source/translator/translate/otel/receiver/otlp/translator.go" >/dev/null
test "$(grep -c 'insertDefault(&cfg.HTTP)' "$scratch_dir/source/translator/translate/otel/receiver/otlp/translator.go")" -eq 1
test "$(grep -c 'insertDefault(&cfg.GRPC)' "$scratch_dir/source/translator/translate/otel/receiver/otlp/translator.go")" -eq 1
grep -F 'cfg.HTTP.Get().ServerConfig.TLS = tlsSettings' "$scratch_dir/source/translator/translate/otel/receiver/otlp/translator.go" >/dev/null
grep -F 'cfg.GRPC.Get().TLS = tlsSettings' "$scratch_dir/source/translator/translate/otel/receiver/otlp/translator.go" >/dev/null
test "$(grep -c 'TargetAllocator.TLS\.' "$scratch_dir/source/translator/translate/otel/receiver/prometheus/translator.go")" -eq 4

mkdir -p "$scratch_dir/tampered"
for file in \
  translator/translate/otel/exporter/otlphttp/translator.go \
  translator/translate/otel/exporter/prometheusremotewrite/translator.go \
  translator/translate/otel/receiver/otlp/translator.go \
  translator/translate/otel/receiver/prometheus/translator.go; do
  mkdir -p "$scratch_dir/tampered/$(dirname "$file")"
  cp "$source_root/$file" "$scratch_dir/tampered/$file"
done
chmod -R u+w "$scratch_dir/tampered"
sed -i.bak 's/configauth\.Authentication/configauth.LegacyAuthentication/' "$scratch_dir/tampered/translator/translate/otel/exporter/otlphttp/translator.go"
rm -f "$scratch_dir/tampered/translator/translate/otel/exporter/otlphttp/translator.go.bak"
if patch --dry-run --batch --fuzz=0 -d "$scratch_dir/tampered" -p1 < "$patch_file"; then
  echo 'expected altered translator preimage to reject the patch' >&2
  exit 1
fi
