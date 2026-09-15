#!/usr/bin/env bash
# Check objective: Verify a release source commit is eligible under reviewed GitHub provenance.
# Purpose: Require exact trusted CI checks, merged-main ancestry, and policy evidence before release use.
# Inputs: Source SHA, local origin/main history, GH_TOKEN, GITHUB_REPOSITORY, and unzip.
# Outputs: Exit status and a non-sensitive provenance confirmation.
# Side effects: Read-only GitHub/Git/artifact access and temporary local files; no release publication.
set -euo pipefail

if [ "$#" -ne 1 ]; then
  printf 'usage: %s SOURCE_SHA\n' "$0" >&2
  exit 64
fi
: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}"
: "${GH_TOKEN:?GH_TOKEN is required}"
command -v unzip >/dev/null || { printf 'missing command: unzip\n' >&2; exit 1; }
source_sha="$1"
[[ "$source_sha" =~ ^[0-9a-f]{40}$ ]] || { printf 'source SHA must be 40 lowercase hexadecimal characters\n' >&2; exit 64; }
git merge-base --is-ancestor "$source_sha" refs/remotes/origin/main || { printf 'release source is not reachable from origin/main\n' >&2; exit 1; }

temporary_directory="$(mktemp -d)"
trap 'rm -rf "$temporary_directory"' EXIT
checks="$temporary_directory/checks.json"
fetch_checks() {
  local sha="$1" destination="$2"
  gh api --paginate -H 'Accept: application/vnd.github+json' \
    "repos/$GITHUB_REPOSITORY/commits/$sha/check-runs?filter=latest&per_page=100" \
    --jq '.check_runs[]' | jq -s . > "$destination"
}
trusted_check_present() {
  local input="$1" name="$2" sha="$3" expected_path="$4" expected_event="$5" require_run_head="$6"
  local check_json details_url run_id run_json check_id external_id custom_check=false artifacts artifact_id archive evidence_member decision_member details_run_id
  check_json="$(jq -ec --arg name "$name" --arg repo "$GITHUB_REPOSITORY" --arg sha "$sha" '
    [.[] | select(
      .name == $name and .status == "completed" and .conclusion == "success" and .head_sha == $sha and
      .app.slug == "github-actions" and
      (.details_url | type == "string")
    )] | select(length == 1) | .[0]
  ' "$input")" || return 1
  details_url="$(jq -r '.details_url' <<<"$check_json")"
  if [ "$name" = 'CI Evidence Decision' ]; then
    custom_check=true
    external_id="$(jq -er --arg sha "$sha" '.external_id | select(type == "string" and test("^ci-evidence-workflow-run:[0-9]+:[0-9a-f]{40}$")) | select(endswith(":" + $sha)) | split(":")[1]' <<<"$check_json")" || return 1
    run_id="$external_id"
  fi
  case "$details_url" in
    "https://github.com/$GITHUB_REPOSITORY/actions/runs/"*)
      details_run_id="$(printf '%s' "$details_url" | sed -E 's#^https://github.com/[^/]+/[^/]+/actions/runs/([0-9]+)(/.*)?$#\1#')"
      if [ "$custom_check" = true ]; then [ "$details_run_id" = "$run_id" ] || return 1; else run_id="$details_run_id"; fi
      ;;
    "https://github.com/$GITHUB_REPOSITORY/runs/"*)
      [ "$custom_check" = true ] || return 1
      check_id="$(printf '%s' "$details_url" | sed -E 's#^https://github.com/[^/]+/[^/]+/runs/([0-9]+)(/.*)?$#\1#')"
      [ "$(jq -r '.id | tostring' <<<"$check_json")" = "$check_id" ] || return 1
      ;;
    *) return 1 ;;
  esac
  [[ "$run_id" =~ ^[0-9]+$ ]] || return 1
  run_json="$temporary_directory/run-$run_id.json"
  gh api "repos/$GITHUB_REPOSITORY/actions/runs/$run_id" > "$run_json" || return 1
  jq -se --arg repo "$GITHUB_REPOSITORY" --arg path "$expected_path" --arg event "$expected_event" --arg sha "$sha" --arg require_head "$require_run_head" '
    length == 1 and (.[0] |
      .repository.full_name == $repo and .path == $path and .event == $event and
      .status == "completed" and .conclusion == "success" and
      (if $require_head == "true" then .head_sha == $sha else true end))
  ' "$run_json" >/dev/null || return 1
  if [ "$custom_check" = true ]; then
    artifacts="$temporary_directory/artifacts-$run_id.json"
    gh api "repos/$GITHUB_REPOSITORY/actions/runs/$run_id/artifacts?per_page=100" > "$artifacts" || return 1
    artifact_id="$(jq -er --arg name "ci-evidence-gate-$sha" --arg review_name "ci-review-decision-$run_id" --argjson run_id "$run_id" '
      [.artifacts[] | select((.name == $name or .name == $review_name) and .expired == false and .workflow_run.id == $run_id)] |
      select(length == 1) | .[0].id
    ' "$artifacts")" || return 1
    [[ "$artifact_id" =~ ^[1-9][0-9]*$ ]] || return 1
    archive="$temporary_directory/evidence-$artifact_id.zip"
    gh api "repos/$GITHUB_REPOSITORY/actions/artifacts/$artifact_id/zip" > "$archive" || return 1
    evidence_member="$(unzip -Z1 "$archive" | awk -F/ '$NF == "evidence.json"' | sed -n '1p')" || return 1
    decision_member="$(unzip -Z1 "$archive" | awk -F/ '$NF == "decision.json"' | sed -n '1p')" || return 1
    [ -n "$evidence_member" ] && [ "$(unzip -Z1 "$archive" | awk -F/ '$NF == "evidence.json"' | wc -l | tr -d ' ')" = 1 ] || return 1
    [ -n "$decision_member" ] && [ "$(unzip -Z1 "$archive" | awk -F/ '$NF == "decision.json"' | wc -l | tr -d ' ')" = 1 ] || return 1
    unzip -p "$archive" "$evidence_member" > "$temporary_directory/evidence-$artifact_id.json" || return 1
    unzip -p "$archive" "$decision_member" > "$temporary_directory/decision-$artifact_id.json" || return 1
    jq -se --arg sha "$sha" 'length == 1 and (.[0].subject.commit_sha == $sha)' "$temporary_directory/evidence-$artifact_id.json" >/dev/null || return 1
    jq -se 'length == 1 and (.[0].summary.block == 0 and .[0].summary.require_approval == 0 and (.[0].violations | type == "array"))' "$temporary_directory/decision-$artifact_id.json" >/dev/null || return 1
  fi
}
fetch_checks "$source_sha" "$checks"

trusted_check_present "$checks" quality "$source_sha" '.github/workflows/continuous-integration.yml' push true || { printf 'required trusted source check is absent or invalid: quality\n' >&2; exit 1; }
trusted_check_present "$checks" scanners "$source_sha" '.github/workflows/continuous-integration.yml' push true || { printf 'required trusted source check is absent or invalid: scanners\n' >&2; exit 1; }
trusted_check_present "$checks" 'Policy Rules' "$source_sha" '.github/workflows/continuous-integration.yml' push true || { printf 'required trusted source check is absent or invalid: policy\n' >&2; exit 1; }
trusted_check_present "$checks" 'Terraform Validation' "$source_sha" '.github/workflows/continuous-integration.yml' push true || { printf 'required trusted source check is absent or invalid: terraform\n' >&2; exit 1; }
trusted_check_present "$checks" 'Evidence Contracts' "$source_sha" '.github/workflows/continuous-integration.yml' push true || { printf 'required trusted source check is absent or invalid: policy-foundation\n' >&2; exit 1; }

pulls="$temporary_directory/pulls.json"
gh api -H 'Accept: application/vnd.github+json' "repos/$GITHUB_REPOSITORY/commits/$source_sha/pulls" > "$pulls"
jq -e --arg repo "$GITHUB_REPOSITORY" --arg sha "$source_sha" 'type == "array" and ([.[] | select(.merged_at != null and .merge_commit_sha == $sha and .base.ref == "main" and .base.repo.full_name == $repo)] | length == 1)' "$pulls" >/dev/null || {
  printf 'release source must map to exactly one merged main pull request\n' >&2
  exit 1
}
pr_head_sha="$(jq -er --arg repo "$GITHUB_REPOSITORY" --arg sha "$source_sha" '[.[] | select(.merged_at != null and .merge_commit_sha == $sha and .base.ref == "main" and .base.repo.full_name == $repo)][0].head.sha | select(test("^[0-9a-f]{40}$"))' "$pulls")"
pr_checks="$temporary_directory/pr-checks.json"
fetch_checks "$pr_head_sha" "$pr_checks"
trusted_check_present "$pr_checks" 'CI Evidence Decision' "$pr_head_sha" '.github/workflows/evidence-gate.yml' workflow_run false || {
  printf 'merged pull-request head lacks the trusted CI Evidence Decision\n' >&2
  exit 1
}
printf 'PASS: release source %s has the complete trusted security decision set.\n' "$source_sha"
