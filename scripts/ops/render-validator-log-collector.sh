#!/usr/bin/env bash
set -euo pipefail

# Rendering is deliberately separate from the base overlay: the collector is a
# privileged host-log reader and must never be admitted with a mutable/public
# image reference.
usage() { printf 'Usage: %s --image <same-account-ecr@sha256:digest> --output <absolute-yaml-path>\n' "${0##*/}" >&2; exit 64; }
image=''; output=''
while [ "$#" -gt 0 ]; do
  case "$1" in --image) image="${2:-}"; shift 2 ;; --output) output="${2:-}"; shift 2 ;; *) usage ;; esac
done
case "$output" in /*) ;; *) usage ;; esac
case "$image" in 123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/*@sha256:????????????????????????????????????????????????????????????????) ;; *) printf 'image must be a private ap-northeast-2 ECR SHA-256 digest\n' >&2; exit 64 ;; esac
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
template="$script_dir/../../deploy/observability/fluent-bit-daemonset.template.yaml"
[ -r "$template" ] || { printf 'collector template is missing\n' >&2; exit 66; }
mkdir -p "$(dirname "$output")"; umask 077
sed "s|REPLACE_WITH_APPROVED_PRIVATE_ECR_DIGEST|${image}|g" "$template" > "$output"
grep -Fq "$image" "$output" || { printf 'rendered collector image mismatch\n' >&2; exit 65; }
printf 'PASS: rendered digest-pinned validator log collector to %s\n' "$output"
