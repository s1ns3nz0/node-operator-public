#!/usr/bin/env bash
# Purpose: Publish an exact-head CI Evidence Decision check from a validated policy decision or fail-closed dash.
# Inputs: Head SHA, decision path or '-', Actions details URL, GH_TOKEN, and GITHUB_REPOSITORY.
# Outputs: One completed CI Evidence Decision check and a concise local status line.
# Side effects: Creates a scoped GitHub check; does not alter code, reviews, releases, or environments.
set -euo pipefail

if [ "$#" -ne 3 ]; then
  printf 'usage: %s HEAD_SHA DECISION_JSON_OR_DASH DETAILS_URL\n' "$0" >&2
  exit 64
fi

: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}"
: "${GH_TOKEN:?GH_TOKEN is required}"
head_sha="$1"
decision_path="$2"
details_url="$3"

[[ "$head_sha" =~ ^[0-9a-f]{40}$ ]] || { printf 'head SHA must be 40 lowercase hexadecimal characters\n' >&2; exit 64; }
[[ "$GITHUB_REPOSITORY" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || { printf 'invalid GitHub repository slug\n' >&2; exit 64; }
case "$details_url" in
  "https://github.com/$GITHUB_REPOSITORY/actions/runs/"[0-9]*) ;;
  *) printf 'details URL must identify this repository Actions run\n' >&2; exit 64 ;;
esac
publisher_run_id="$(printf '%s' "$details_url" | sed -E 's#^.*/actions/runs/([0-9]+)(/.*)?$#\1#')"
[[ "$publisher_run_id" =~ ^[0-9]+$ ]] || { printf 'details URL must contain a numeric Actions run ID\n' >&2; exit 64; }

conclusion="failure"
title="CI evidence policy rejected this revision"
summary="Trusted evidence was missing, malformed, or rejected by policy."
if [ "$decision_path" != "-" ] && [ -f "$decision_path" ] && jq -e '
  (.summary | type == "object") and
  (.summary.block | type == "number") and
  (.summary.require_approval | type == "number") and
  (.violations | type == "array")
' "$decision_path" >/dev/null 2>&1; then
  block="$(jq -r '.summary.block' "$decision_path")"
  approvals="$(jq -r '.summary.require_approval' "$decision_path")"
  if [ "$block" -eq 0 ] && [ "$approvals" -eq 0 ]; then
    conclusion="success"
    title="CI evidence policy approved this revision"
    summary="Trusted scanner, Terraform, SCM, and OPA evidence passed."
  else
    summary="Trusted OPA decision reported block=$block and require_approval=$approvals."
  fi
fi

gh api --method POST "repos/$GITHUB_REPOSITORY/check-runs" \
  -f name='CI Evidence Decision' \
  -f head_sha="$head_sha" \
  -f status=completed \
  -f conclusion="$conclusion" \
  -f details_url="$details_url" \
  -f external_id="ci-evidence-workflow-run:$publisher_run_id:$head_sha" \
  -f "output[title]=$title" \
  -f "output[summary]=$summary" >/dev/null

printf 'published CI Evidence Decision=%s for %s\n' "$conclusion" "$head_sha"
