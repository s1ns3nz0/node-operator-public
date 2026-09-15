#!/usr/bin/env bash
# Check objective: Bind reusable evidence to its exact subject, base, trusted control revision and originating runs.
# Purpose: Create provenance metadata that binds reusable policy evidence to exact source and control identities.
# Inputs: SUBJECT_SHA, BASE_SHA, GITHUB_SHA, GITHUB_RUN_ID, GITHUB_EVENT_PATH, and published evidence.
# Outputs: EVIDENCE_ROOT/published/cache-context.json.
# Side effects: Writes one local metadata file; no network, scanner, or publication action.
set -euo pipefail
jq -e --arg sha "$SUBJECT_SHA" '.subject.commit_sha == $sha and (.evidence | type == "object")' "$EVIDENCE_ROOT/published/evidence.json" >/dev/null
jq -n --arg subject "$SUBJECT_SHA" --arg base "$BASE_SHA" --arg trusted "$GITHUB_SHA" \
  --argjson gate "$GITHUB_RUN_ID" --slurpfile event "$GITHUB_EVENT_PATH" \
  '{schema_version:1,subject_sha:$subject,base_sha:$base,trusted_sha:$trusted,gate_run_id:$gate,source_run_id:$event[0].workflow_run.id}' \
  > "$EVIDENCE_ROOT/published/cache-context.json"
