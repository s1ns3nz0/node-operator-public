#!/usr/bin/env bash
# Check objective: Verify the PR policy gate rejects malformed or blocking evidence decisions.
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
"$script_dir/test-pr-evidence.sh"
"$script_dir/test-pr-baseline-findings.sh"
"$script_dir/test-scm-posture.sh"
"$script_dir/test-publish-evidence.sh"
