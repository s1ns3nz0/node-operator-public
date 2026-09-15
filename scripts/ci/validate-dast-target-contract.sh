#!/usr/bin/env bash
set -euo pipefail

# This validates a source-only plan. It never starts a scanner or connects.
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$script_dir/lib/common.sh"
require_command jq
fail() { printf 'FAIL DAST target contract: %s\n' "$*" >&2; exit 1; }
contract_path="${1:-}"
test -n "$contract_path" || fail 'usage: validate-dast-target-contract.sh <contract.json>'
require_file "$contract_path"

jq -e '
  type == "object" and (keys | sort) == ["execution", "scanner", "schema_version", "scope", "target"] and .schema_version == "v1" and
  (.execution | type == "object" and (keys | sort) == ["live_scan_authorized", "mode", "required_approval"] and .mode == "source-only" and .live_scan_authorized == false and .required_approval == "separate-private-deployment-task") and
  (.scanner | type == "object" and (keys | sort) == ["image", "profile"] and .profile == "baseline-passive" and (.image | test("^123456789012\\.dkr\\.ecr\\.ap-northeast-2\\.amazonaws\\.com/node-operator/[a-z0-9][a-z0-9._/-]*@sha256:[0-9a-f]{64}$"))) and
  (.target | type == "object" and (keys | sort) == ["approved_private_target", "url"] and .approved_private_target == true and (.url | type == "string")) and
  (.scope | type == "object" and (keys | sort) == ["max_duration_seconds", "max_paths", "max_requests", "methods", "paths"] and .methods == ["GET"] and (.paths | type == "array" and length >= 1 and length <= 3 and all(.[]; . == "/healthz" or . == "/health" or . == "/metrics") and (unique | length) == length) and .max_paths == (.paths | length) and (.max_requests | type == "number" and . >= 1 and . <= 50) and (.max_duration_seconds | type == "number" and . >= 1 and . <= 300))
' "$contract_path" >/dev/null || fail 'schema, source-only state, scanner digest, or GET scope is invalid'

target_url="$(jq -r '.target.url' "$contract_path")"
[[ "$target_url" =~ ^https?:// ]] || fail 'target URL must use HTTP(S)'
[[ "$target_url" != *\?* && "$target_url" != *\#* && "$target_url" != *@* ]] || fail 'target URL must not contain a query, fragment, or userinfo'
authority="${target_url#http://}"; authority="${authority#https://}"; authority="${authority%%/*}"
host="${authority%%:*}"
test -n "$host" || fail 'target URL has no host'
is_private_ipv4() { local a b c d; IFS=. read -r a b c d <<< "$1"; [[ "$a" =~ ^[0-9]+$ && "$b" =~ ^[0-9]+$ && "$c" =~ ^[0-9]+$ && "$d" =~ ^[0-9]+$ ]] && (( a <= 255 && b <= 255 && c <= 255 && d <= 255 )) && (( a == 10 || (a == 172 && b >= 16 && b <= 31) || (a == 192 && b == 168) )); }
is_loopback_ipv4() { [[ "$1" =~ ^127\.([0-9]{1,3}\.){2}[0-9]{1,3}$ ]]; }
is_private_service_dns() { [[ "$1" =~ ^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.){2,}svc(\.cluster\.local)?$ ]]; }
if [[ "$host" != "localhost" ]] && ! is_loopback_ipv4 "$host" && ! is_private_ipv4 "$host" && ! is_private_service_dns "$host"; then fail 'target host must be loopback, RFC1918 IPv4, or Kubernetes service DNS'; fi
printf 'PASS DAST source-only target contract is private, bounded, credential-free, and digest-pinned.\n'
