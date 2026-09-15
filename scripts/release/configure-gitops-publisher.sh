#!/usr/bin/env bash
set -euo pipefail
umask 077

usage() {
  printf '%s\n' "usage: ${0##*/} --handoff /absolute/gitops-publisher-handoff.json"
  exit 64
}

handoff=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --handoff) handoff="${2:-}"; shift 2 ;;
    *) usage ;;
  esac
done
case "$handoff" in /*) ;; *) usage ;; esac
[ -f "$handoff" ] && [ ! -L "$handoff" ] || { printf '%s\n' 'handoff must be a regular file' >&2; exit 65; }
for command in jq gh; do command -v "$command" >/dev/null 2>&1 || { printf 'missing command: %s\n' "$command" >&2; exit 127; }; done

# Preserve the caller's GITHUB_TOKEN exactly; gh selects the authenticated
# operator or CI credential without altering process environment state.
github() { gh "$@"; }

repository="$(jq -er '.schema_version == "v1" and .gitops_repository | select(test("^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$"))' "$handoff")" || { printf '%s\n' 'invalid GitOps repository handoff' >&2; exit 65; }
environment="$(jq -er '.publisher_environment | select(. == "gitops-client-ecr-publish")' "$handoff")" || { printf '%s\n' 'unexpected publisher environment' >&2; exit 65; }
account="$(jq -er '.aws_account_id | select(test("^[0-9]{12}$"))' "$handoff")" || { printf '%s\n' 'invalid AWS account handoff' >&2; exit 65; }
role="$(jq -er --arg account "$account" '.publisher_role_arn | select(test("^arn:aws:iam::" + $account + ":role/[A-Za-z0-9+=,.@_-]+$"))' "$handoff")" || { printf '%s\n' 'invalid publisher role handoff' >&2; exit 65; }

github variable set AWS_ACCOUNT_ID --repo "$repository" --env "$environment" --body "$account"
github variable set GITOPS_CLIENT_ECR_PUBLISHER_ROLE_ARN --repo "$repository" --env "$environment" --body "$role"
printf 'PASS: configured non-secret GitOps publisher variables for %s/%s. Protected-environment approval remains required before publish.\n' "$repository" "$environment"
