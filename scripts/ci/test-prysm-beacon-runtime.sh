#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
patch="$root/.ci/prysm-mtls/patches/0002-security-dependencies.patch"
mtls_dockerfile="$root/.ci/prysm-mtls/Dockerfile"; mtls_lock="$root/.ci/prysm-mtls/source.lock.json"
dockerfile="$root/.ci/prysm-beacon-runtime/Dockerfile"; lock="$root/.ci/prysm-beacon-runtime/source.lock.json"
security_patch_sha256="ff4f2db3b57b8d5d2756bfdf03e4d16ee12b62f218beb12a56e6c60f342a4b91"
for file in "$patch" "$mtls_dockerfile" "$mtls_lock" "$dockerfile" "$lock"; do test -f "$file" || { echo "missing: $file" >&2; exit 1; }; done
test "$(shasum -a 256 "$patch" | awk '{print $1}')" = "$security_patch_sha256"
grep -Fqx '+	google.golang.org/grpc v1.83.2' "$patch"
grep -Fqx '+google.golang.org/grpc v1.83.2 h1:EManeRomTObA0BU7I8vXgg/78uE5MJ9M8B39EX2WscU=' "$patch"
grep -Fqx '+google.golang.org/grpc v1.83.2/go.mod h1:YPI1hK3kDked6iHvgX3tR0y+nX/qpMFKhPgFsokw1S8=' "$patch"
! grep -Fq 'google.golang.org/grpc v1.83.1' "$patch"
grep -Fqx '+	golang.org/x/net v0.58.0 // indirect' "$patch"
grep -Fqx '+golang.org/x/net v0.58.0 h1:ynWG7rqYi4ccpTEuPZ2QGWHktVEM9DMCj9yzDE0Q7To=' "$patch"
! grep -Fq 'golang.org/x/net v0.57.0' "$patch"
jq -e --arg sha "$security_patch_sha256" '.commit == "51b5a75ebbadf05af22bd2601b5baf7a9e99b66d" and .target == "./cmd/beacon-chain" and .security_patch_sha256 == $sha' "$lock" >/dev/null
jq -e --arg sha "$security_patch_sha256" '.commit == "51b5a75ebbadf05af22bd2601b5baf7a9e99b66d" and .target == "./cmd/validator" and .security_patch_sha256 == $sha' "$mtls_lock" >/dev/null
for consumer in "$mtls_dockerfile" "$dockerfile"; do
  grep -Fq "$security_patch_sha256  /tmp/security.patch" "$consumer"
  grep -Fq "io.node-operator.prysm-security-patch-sha256=\"$security_patch_sha256\"" "$consumer"
done
grep -Fq '51b5a75ebbadf05af22bd2601b5baf7a9e99b66d' "$dockerfile"
grep -Fq 'go test -mod=readonly -count=1 ./cmd/beacon-chain/flags ./cmd/beacon-chain/jwt ./beacon-chain/core/blocks' "$dockerfile"
grep -Fq 'go list -mod=readonly -deps ./cmd/beacon-chain' "$dockerfile"
grep -Fq 'go version -m /out/beacon-chain' "$dockerfile"
grep -Fq 'USER 1000:1000' "$dockerfile"
printf '%s\n' 'PASS: Prysm consumers pin the verified gRPC 1.83.2 dependency patch, source, tests, and inventory.'
