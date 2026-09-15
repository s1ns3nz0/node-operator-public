#!/usr/bin/env bash
# Static contracts inspect only implementation scripts explicitly called by the workflow.
workflow_source() {
  python3 "${BASH_SOURCE[0]%/*}/workflow-source.py" "$1"
}

# Expand explicitly called scripts, then retain one named workflow job's body.
workflow_job_source() {
  local workflow="$1" job="$2"
  workflow_source "$workflow" | awk -v job="$job" '
    $0 == "  " job ":" { selected = 1; next }
    selected && /^  [[:alnum:]_-]+:$/ { exit }
    selected { print }
  '
}
