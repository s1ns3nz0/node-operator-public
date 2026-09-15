#!/usr/bin/env bash
# Purpose: Obtain short-lived credentials for the dedicated private DAST ECR mirror role.
# Inputs: OIDC request context, AWS_ROLE_ARN, RUNNER_TEMP, GITHUB_ENV, and GITHUB_RUN_ID.
# Outputs: Masked temporary AWS credential entries appended to GITHUB_ENV.
# Side effects: Calls AWS STS and writes local temporary credentials; does not mirror or publish an image.
set -euo pipefail

: "${AWS_ROLE_ARN:?PRIVATE_DAST_ECR_MIRROR_ROLE_ARN is required}"
: "${GITHUB_ENV:?GITHUB_ENV is required}"
token="$(curl --fail --silent --show-error -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=sts.amazonaws.com" | jq -er .value)"
aws sts assume-role-with-web-identity --role-arn "$AWS_ROLE_ARN" --role-session-name "private-dast-${GITHUB_RUN_ID}" --web-identity-token "$token" --duration-seconds 900 > "$RUNNER_TEMP/private-dast-creds.json"
jq -r '.Credentials | "AWS_ACCESS_KEY_ID=\(.AccessKeyId)\nAWS_SECRET_ACCESS_KEY=\(.SecretAccessKey)\nAWS_SESSION_TOKEN=\(.SessionToken)"' "$RUNNER_TEMP/private-dast-creds.json" >> "$GITHUB_ENV"
printf 'PASS: assumed the dedicated private DAST mirror role.\n'
