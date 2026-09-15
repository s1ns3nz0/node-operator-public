#!/usr/bin/env bash
# Check objective: Assume ECR mirror role.
# Purpose: Exchange the GitHub OIDC token for the GitOps OCI mirror role.
# Inputs: AWS_ROLE_ARN, GitHub OIDC request variables, GITHUB_RUN_ID, and RUNNER_TEMP.
# Outputs: Masked AWS credential variables appended to GITHUB_ENV; temporary STS JSON.
# Side effects: Calls GitHub OIDC and AWS STS; makes credentials available to later workflow steps.
set -euo pipefail

test -n "$AWS_ROLE_ARN"
token="$(curl --fail --silent -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=sts.amazonaws.com" | jq -er .value)"
claims="$(python3 -c 'import base64, sys; payload = sys.argv[1].split(".")[1]; print(base64.urlsafe_b64decode(payload + "===").decode())' "$token")"
printf '%s\n' "$claims" | jq -e '{sub, aud, repository, environment}'
aws sts assume-role-with-web-identity --role-arn "$AWS_ROLE_ARN" --role-session-name "gitops-oci-${GITHUB_RUN_ID}" --web-identity-token "$token" --duration-seconds 900 > "$RUNNER_TEMP/creds.json"
access_key="$(jq -er '.Credentials.AccessKeyId' "$RUNNER_TEMP/creds.json")"
secret_key="$(jq -er '.Credentials.SecretAccessKey' "$RUNNER_TEMP/creds.json")"
session_token="$(jq -er '.Credentials.SessionToken' "$RUNNER_TEMP/creds.json")"
printf '::add-mask::%s\n' "$access_key" "$secret_key" "$session_token"
{
  printf 'AWS_ACCESS_KEY_ID=%s\n' "$access_key"
  printf 'AWS_SECRET_ACCESS_KEY=%s\n' "$secret_key"
  printf 'AWS_SESSION_TOKEN=%s\n' "$session_token"
} >> "$GITHUB_ENV"
