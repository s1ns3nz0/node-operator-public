#!/usr/bin/env bash
set -euo pipefail
umask 077

usage() { printf '%s\n' "usage: ${0##*/} --handoff /absolute/gitops-publisher-handoff.json --output /absolute/new-promotion-handoff.json"; exit 64; }
handoff=''; output=''
while [ "$#" -gt 0 ]; do case "$1" in --handoff) handoff="${2:-}"; shift 2;; --output) output="${2:-}"; shift 2;; *) usage;; esac; done
case "$handoff:$output" in /*:/*) ;; *) usage;; esac
[ -f "$handoff" ] && [ ! -L "$handoff" ] || { printf '%s\n' 'handoff must be a regular file' >&2; exit 65; }
[ ! -e "$output" ] && [ ! -L "$output" ] || { printf '%s\n' 'output must not already exist' >&2; exit 65; }
for command in jq gh unzip uuidgen tr sleep seq sed wc; do command -v "$command" >/dev/null 2>&1 || { printf 'missing command: %s\n' "$command" >&2; exit 127; }; done
# Preserve the caller's GITHUB_TOKEN exactly; gh selects the authenticated
# operator or CI credential without altering process environment state.
github() { gh "$@"; }
repository="$(jq -er '.schema_version == "v1" and .gitops_repository | select(test("^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$"))' "$handoff")" || exit 65
account="$(jq -er '.aws_account_id | select(test("^[0-9]{12}$"))' "$handoff")" || exit 65

promotion_id="node-operator-$(uuidgen | tr '[:upper:]' '[:lower:]')"
artifact_name="gitops-chart-evidence-${promotion_id}"
github workflow run publish-oci.yml --repo "$repository" --ref main -f "promotion_id=$promotion_id"

# Never trust the most recent workflow run: another operator can publish at the
# same time. The GitOps workflow binds this unique non-secret ID into exactly
# one evidence artifact, which is the authority for selecting its run.
run_id=''; artifact_id=''
for _ in $(seq 1 90); do
  matches=''
  while IFS= read -r candidate; do
    # shellcheck disable=SC2016 # $name is a jq variable, not a shell expansion.
    candidate_artifact="$(github api "repos/$repository/actions/runs/$candidate/artifacts?per_page=100" --jq --arg name "$artifact_name" '.artifacts[] | select(.name == $name and .expired == false) | .id')"
    [ -z "$candidate_artifact" ] || matches="${matches}${candidate}:${candidate_artifact}"$'\n'
  done < <(github run list --repo "$repository" --workflow publish-oci.yml --branch main --limit 100 --json databaseId --jq '.[].databaseId')
  match_count="$(printf '%s' "$matches" | sed '/^$/d' | wc -l | tr -d ' ')"
  [ "$match_count" -le 1 ] || { printf '%s\n' 'multiple workflow runs produced the same promotion evidence identifier' >&2; exit 70; }
  if [ "$match_count" = 1 ]; then
    run_id="${matches%%:*}"
    artifact_id="${matches#*:}"; artifact_id="${artifact_id%$'\n'}"
    break
  fi
  sleep 2
done
[[ "$run_id" =~ ^[1-9][0-9]*$ ]] && [[ "$artifact_id" =~ ^[1-9][0-9]*$ ]] || { printf '%s\n' 'timed out waiting for uniquely bound publisher evidence' >&2; exit 70; }
github run view "$run_id" --repo "$repository" --json status,conclusion --jq 'select(.status == "completed" and .conclusion == "success")' >/dev/null || { printf '%s\n' 'publisher run did not complete successfully' >&2; exit 70; }
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
github api "repos/$repository/actions/artifacts/$artifact_id/zip" > "$tmp/evidence.zip"
subject="$(unzip -Z1 "$tmp/evidence.zip" | awk -F/ '$NF == "gitops-chart-subject.json" {print; exit}')"
[ -n "$subject" ] || { printf '%s\n' 'publisher evidence has no chart subject' >&2; exit 70; }
unzip -p "$tmp/evidence.zip" "$subject" > "$tmp/subject.json"
jq -e --arg account "$account" '.schema_version == "v1" and (.oci_digest | test("^sha256:[a-f0-9]{64}$")) and (.chart_version | test("^0\\.1\\.[0-9]+$"))' "$tmp/subject.json" >/dev/null || { printf '%s\n' 'publisher evidence has invalid chart identity' >&2; exit 70; }
jq --arg repository "$repository" --arg account "$account" '{schema_version:"v1",gitops_repository:$repository,aws_account_id:$account,chart_version:.chart_version,chart_oci_digest:.oci_digest,chart_archive_digest:.chart_archive_digest}' "$tmp/subject.json" > "$output"
chmod 600 "$output"
printf 'PASS: immutable GitOps chart promotion handoff saved to %s\n' "$output"
