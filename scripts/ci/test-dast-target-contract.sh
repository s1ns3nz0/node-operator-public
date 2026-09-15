#!/usr/bin/env bash
# Check objective: Reject private DAST contracts with public, credentialed, unsafe, or unbounded targets.
set -euo pipefail
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$script_dir/lib/common.sh"
require_command jq
root="$(repo_root)"; validator="$script_dir/validate-dast-target-contract.sh"; contract="$root/policy/dast/private-target-contract.json"
temporary_directory="$(mktemp -d)"; trap 'rm -rf "$temporary_directory"' EXIT
assert_rejected() { local candidate="$temporary_directory/$1.json"; jq "$2" "$contract" > "$candidate"; if bash "$validator" "$candidate" >/dev/null 2>&1; then printf 'DAST validator accepted unsafe fixture: %s\n' "$1" >&2; exit 1; fi; }
bash "$validator" "$contract"
assert_rejected public_host '.target.url = "https://example.com/healthz"'
assert_rejected credentials '.target.url = "https://operator:password@node-operator-dast.node-operator.svc.cluster.local/healthz"'
assert_rejected credential_field '.credentials = {"token":"redacted"}'
assert_rejected unpinned_scanner '.scanner.image = "registry.example.invalid/security/zap-baseline:stable"'
assert_rejected unsafe_method '.scope.methods = ["POST"]'
assert_rejected blockchain_control_path '.scope.paths = ["/engine/v1/newPayloadV3"] | .scope.max_paths = 1'
assert_rejected unbounded_requests '.scope.max_requests = 51'
assert_rejected live_authorized '.execution.live_scan_authorized = true'
printf 'PASS DAST contract rejects public, credential-bearing, unsafe, unbounded, and live-scan fixtures.\n'
