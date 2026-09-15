#!/usr/bin/env bash
# Check objective: Publish a fail-closed review decision only while the PR still matches the cached head and base.
# Purpose: Publish a PR check only when refreshed evidence remains bound to the live open PR head and base.
# Inputs: SUBJECT_SHA, PR_NUMBER, EVALUATION_RESULT, DETAILS_URL, cache context, and GitHub API access.
# Outputs: A CI Evidence Decision check and an exit status that rejects unavailable or stale evidence.
# Side effects: Reads the PR and creates a GitHub check through the scoped publisher; no scanner execution.
set -euo pipefail
current="$(gh api "repos/$GITHUB_REPOSITORY/pulls/$PR_NUMBER")"
jq -e --arg sha "$SUBJECT_SHA" '.state == "open" and .head.sha == $sha' <<<"$current" >/dev/null || {
  printf 'PR head changed; refusing to publish an obsolete review check.\n' >&2
  exit 1
}
decision=-
if [ "${EVALUATION_RESULT:-}" = success ] && [ -f "$EVIDENCE_ROOT/published/decision.json" ] && [ -f "$EVIDENCE_ROOT/cache/cache-context.json" ]; then
  base="$(jq -er .base_sha "$EVIDENCE_ROOT/cache/cache-context.json")"
  if jq -e --arg base "$base" '.base.sha == $base' <<<"$current" >/dev/null; then
    decision="$EVIDENCE_ROOT/published/decision.json"
  fi
fi
scripts/ci/publish-pr-evidence-check.sh "$SUBJECT_SHA" "$decision" "$DETAILS_URL"
if [ "$decision" = - ]; then
  printf 'Reusable evidence unavailable or stale; rerun CI to trigger fresh full CI Evidence Gate verification.\n' >&2
  exit 1
fi
scripts/ci/verify-policy-decision.sh "$decision"
