#!/usr/bin/env bash
set -euo pipefail
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
helper="$(cd "$(dirname "$0")/.." && pwd)/scripts/update-etcd.sh"
for kind in tab space missing wrong duplicate mixed; do mkdir "$tmp/$kind"; done
printf '\tgo.etcd.io/etcd/client/pkg/v3 v3.6.8\n' > "$tmp/tab/go.mod"
printf '  go.etcd.io/etcd/client/pkg/v3 v3.6.8\n' > "$tmp/space/go.mod"
printf 'go.etcd.io/etcd/client/pkg/v3 v3.6.7\n' > "$tmp/wrong/go.mod"
printf 'go.etcd.io/etcd/client/pkg/v3 v3.6.8\ngo.etcd.io/etcd/client/pkg/v3 v3.6.8\n' > "$tmp/duplicate/go.mod"
printf 'go.etcd.io/etcd/client/pkg/v3 v3.6.8\ngo.etcd.io/etcd/client/pkg/v3 v3.6.7\n' > "$tmp/mixed/go.mod"
for x in tab space; do bash "$helper" --check-only "$tmp/$x"; done
for x in missing wrong duplicate mixed; do if bash "$helper" --check-only "$tmp/$x"; then exit 1; fi; done
