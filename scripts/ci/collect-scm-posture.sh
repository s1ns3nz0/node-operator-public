#!/usr/bin/env bash
# Purpose: Collect normalized PR posture needed by policy evaluation.
# Inputs: Subject SHA, output path, PR number, GH_TOKEN, and GITHUB_REPOSITORY.
# Outputs: One SCM posture JSON document at the requested path.
# Side effects: Read-only GitHub API calls and a local JSON write; no review or repository mutation.
# Check objective: Bind changed files and reviewers' latest approvals to the exact pull-request head SHA for policy evaluation.
set -euo pipefail

if [ "$#" -ne 2 ] && [ "$#" -ne 3 ]; then printf 'usage: %s COMMIT_SHA OUTPUT_JSON [PULL_REQUEST_NUMBER]\n' "$0" >&2; exit 64; fi
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$script_dir/lib/common.sh"
commit_sha="$1"; output_path="$2"; pull_request_number="${3:-}"
[[ "$commit_sha" =~ ^[0-9a-f]{40}$ ]] || { printf 'commit SHA must be 40 lowercase hexadecimal characters\n' >&2; exit 64; }
require_command gh; require_command jq; require_file "${GITHUB_EVENT_PATH:?GITHUB_EVENT_PATH is required}"
repository="${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}"
temporary_directory="$(mktemp -d)"; trap 'rm -rf "$temporary_directory"' EXIT
if [ -n "$pull_request_number" ]; then
  [[ "$pull_request_number" =~ ^[1-9][0-9]*$ ]] || { printf 'pull request number must be a positive integer\n' >&2; exit 64; }
  gh api "repos/$repository/pulls/$pull_request_number" > "$temporary_directory/pull-request.json"
  author="$(jq -er '.user.login' "$temporary_directory/pull-request.json")"
  event_head="$(jq -er '.head.sha' "$temporary_directory/pull-request.json")"
  number="$pull_request_number"
else
  number="$(jq -er '.pull_request.number' "$GITHUB_EVENT_PATH")"
  author="$(jq -er '.pull_request.user.login' "$GITHUB_EVENT_PATH")"
  event_head="$(jq -er '.pull_request.head.sha' "$GITHUB_EVENT_PATH")"
fi
[ "$event_head" = "$commit_sha" ] || { printf 'event head SHA does not match evidence subject\n' >&2; exit 1; }
gh api --paginate "repos/$repository/pulls/$number/files?per_page=100" > "$temporary_directory/files.json"
gh api --paginate "repos/$repository/pulls/$number/reviews?per_page=100" > "$temporary_directory/reviews.json"
mkdir -p "$(dirname "$output_path")"
jq -n --arg author "$author" --arg head "$commit_sha" --slurpfile files "$temporary_directory/files.json" --slurpfile reviews "$temporary_directory/reviews.json" '
  {changed_files:([$files[][]? | .filename] | unique), pull_request:{author:$author, head_sha:$head}, approvers:([
    $reviews[][]? | select(.commit_id == $head)
  ] | sort_by(.id) | group_by(.user.login) | map(last) | map(select(.state == "APPROVED") | .user.login) | unique)}' > "$output_path"
