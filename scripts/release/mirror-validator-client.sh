#!/usr/bin/env bash
# Check objective: Mirror reviewed Prysm digest to private ECR.
# Purpose: Allowlist-check and mirror the reviewed Prysm validator image to private ECR.
# Inputs: SOURCE_IMAGE, ACCOUNT_ID, AWS_ROLE_ARN, AWS_REGION, GitHub OIDC variables, GITHUB_RUN_ID, and RUNNER_TEMP.
# Outputs: The verified private image digest in GITHUB_STEP_SUMMARY; temporary STS credential file.
# Side effects: Calls GitHub OIDC/AWS STS and creates an image in private ECR.
set -euo pipefail

[[ "$SOURCE_IMAGE" =~ ^offchainlabs/prysm-validator@sha256:[a-f0-9]{64}$ ]] || { echo 'source must be an immutable reviewed Prysm validator digest' >&2; exit 1; }
jq -e --arg source "$SOURCE_IMAGE" '.schema_version == 2 and (.images[] | select(.source == $source and .mirror_eligible == true and .release_channel == "upstream-mirror" and .provenance_status == "upstream-release-mirror"))' .ci/validator/approved-client-images.json >/dev/null || {
  echo 'source is not in the reviewed Prysm validator allowlist' >&2
  exit 1
}
test -n "$ACCOUNT_ID"; test -n "$AWS_ROLE_ARN"
token="$(curl --fail --silent -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=sts.amazonaws.com" | jq -er .value)"
aws sts assume-role-with-web-identity --role-arn "$AWS_ROLE_ARN" --role-session-name "prysm-mirror-${GITHUB_RUN_ID}" --web-identity-token "$token" --duration-seconds 900 > "$RUNNER_TEMP/creds.json"
access_key="$(jq -er .Credentials.AccessKeyId "$RUNNER_TEMP/creds.json")"
secret_key="$(jq -er .Credentials.SecretAccessKey "$RUNNER_TEMP/creds.json")"
session_token="$(jq -er .Credentials.SessionToken "$RUNNER_TEMP/creds.json")"
printf '::add-mask::%s\n' "$access_key" "$secret_key" "$session_token"
export AWS_ACCESS_KEY_ID="$access_key" AWS_SECRET_ACCESS_KEY="$secret_key" AWS_SESSION_TOKEN="$session_token"
destination="$ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com/node-operator-baseline-validator-prysm:${SOURCE_IMAGE#*@sha256:}"
aws ecr get-login-password --region "$AWS_REGION" | docker login --username AWS --password-stdin "$ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com"
docker buildx imagetools create --tag "$destination" "$SOURCE_IMAGE"
digest="$(aws ecr describe-images --region "$AWS_REGION" --repository-name node-operator-baseline-validator-prysm --image-ids "imageTag=${SOURCE_IMAGE#*@sha256:}" --query 'imageDetails[0].imageDigest' --output text)"
[[ "$digest" =~ ^sha256:[a-f0-9]{64}$ ]] || exit 1
test "$digest" = "${SOURCE_IMAGE#*@}"
printf 'private_image=%s@%s\n' "${destination%:*}" "$digest" >> "$GITHUB_STEP_SUMMARY"
