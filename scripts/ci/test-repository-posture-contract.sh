#!/usr/bin/env bash
# Check objective: Enforce the pinned OpenSSF Scorecard workflow and bounded evidence output.
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
workflow="$root/.github/workflows/repository-posture.yml"
script="$root/scripts/ci/normalize-scorecard-evidence.sh"
grep -Fq 'ossf/scorecard-action@2d1146689b8cda280b9bc96326124645441f03bc' "$workflow"
grep -Fq 'github/codeql-action/upload-sarif@b56ba49b26e50535fa1e7f7db0f4f7b4bf65d80d' "$workflow"
grep -Fq 'publish_results: true' "$workflow"
grep -Fq 'security-events: write' "$workflow"
grep -Fq 'id-token: write' "$workflow"
grep -Fq 'retention-days: 90' "$workflow"
grep -Fq 'Scorecard SARIF schema is invalid' "$script"
printf '%s\n' 'PASS: repository posture and Scorecard evidence contracts are pinned and bounded.'
