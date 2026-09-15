#!/usr/bin/env bash
# Check objective: Collect source-security findings while explicitly recording Terraform as not run by this entrypoint.
set -euo pipefail
if [ "$#" -lt 2 ] || [ "$#" -gt 4 ]; then echo "usage: $0 OUTPUT_DIRECTORY COMMIT_SHA [SOURCE_DIRECTORY] [BASE_SHA]" >&2; exit 64; fi
# The security workflow uses the shared collector contract with Terraform
# explicitly represented as not-run; Terraform evidence is owned by ci-terraform.
export SKIP_TERRAFORM=true
exec "$(dirname "$0")/collect-pr-evidence.sh" "$@"
