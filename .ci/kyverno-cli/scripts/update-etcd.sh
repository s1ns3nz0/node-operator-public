#!/usr/bin/env bash
set -euo pipefail
check_only=0
if [ "${1:-}" = --check-only ]; then check_only=1; shift; fi
[ "$#" -le 1 ] || exit 64
dir="${1:-.}"; cd "$dir"; mod=go.mod
[ -f "$mod" ] || exit 65
count="$(awk '$1=="go.etcd.io/etcd/client/pkg/v3" {n++} END {print n+0}' "$mod")"; [ "$count" = 1 ] || exit 65
count="$(awk '$1=="go.etcd.io/etcd/client/pkg/v3" && $2=="v3.6.8" {n++} END {print n+0}' "$mod")"; [ "$count" = 1 ] || exit 65
# Allows the source-contract test to exercise the exact precondition without
# resolving modules or altering its fixture.
[ "$check_only" != 1 ] || exit 0
GOTOOLCHAIN=local GOMAXPROCS=2 GOMEMLIMIT=2GiB go get go.etcd.io/etcd/client/pkg/v3@v3.6.14
GOTOOLCHAIN=local GOMAXPROCS=2 GOMEMLIMIT=2GiB go mod tidy
count="$(awk '$1=="go.etcd.io/etcd/client/pkg/v3" && $2=="v3.6.14" {n++} END {print n+0}' "$mod")"; [ "$count" = 1 ] || exit 65
GOTOOLCHAIN=local GOFLAGS=-mod=readonly go list -m -json all
