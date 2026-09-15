#!/usr/bin/env bash
# Purpose: Exchange GitHub Actions OIDC for the short-lived CI evidence archive role.
set -euo pipefail
: "${AWS_ROLE_ARN:?CI_EVIDENCE_ARCHIVE_ROLE_ARN is required}"
: "${GITHUB_ENV:?GITHUB_ENV is required}"
: "${RUNNER_TEMP:?RUNNER_TEMP is required}"
: "${ACTIONS_ID_TOKEN_REQUEST_TOKEN:?GitHub OIDC token request is unavailable}"
: "${ACTIONS_ID_TOKEN_REQUEST_URL:?GitHub OIDC token request URL is unavailable}"
token_file="$RUNNER_TEMP/ci-evidence-archive-oidc.token"
creds_file="$RUNNER_TEMP/ci-evidence-archive-creds.json"
trap 'rm -f "$token_file" "$creds_file"' EXIT
curl --fail --silent --show-error -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
  "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=sts.amazonaws.com" | jq -er .value > "$token_file"
chmod 0600 "$token_file"
aws sts assume-role-with-web-identity --role-arn "$AWS_ROLE_ARN" \
  --role-session-name "ci-evidence-archive-${GITHUB_RUN_ID}" \
  --web-identity-token "file://$token_file" --duration-seconds 900 > "$creds_file"
jq -r '.Credentials | "AWS_ACCESS_KEY_ID=\(.AccessKeyId)\nAWS_SECRET_ACCESS_KEY=\(.SecretAccessKey)\nAWS_SESSION_TOKEN=\(.SessionToken)"' "$creds_file" >> "$GITHUB_ENV"
printf 'PASS: assumed short-lived CI evidence archive role.\n'
