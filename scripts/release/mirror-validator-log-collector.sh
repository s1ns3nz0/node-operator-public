#!/usr/bin/env bash
# Check objective: Mirror reviewed Fluent Bit digest to private ECR.
# Purpose: Mirror the reviewed Fluent Bit image and require exact source/destination digest equality.
# Inputs: SOURCE_IMAGE, ACCOUNT_ID, AWS_ROLE_ARN, AWS_REGION, GitHub OIDC variables, GITHUB_RUN_ID, and RUNNER_TEMP.
# Outputs: The private image digest in GITHUB_STEP_SUMMARY; temporary STS credential file.
# Side effects: Calls GitHub OIDC/AWS STS and creates an image in private ECR.
set -euo pipefail

[[ "$SOURCE_IMAGE" =~ ^cr.fluentbit.io/fluent/fluent-bit@sha256:[a-f0-9]{64}$ ]] || { echo 'source must be a reviewed immutable Fluent Bit digest' >&2; exit 1; }
test -n "$ACCOUNT_ID"; test -n "$AWS_ROLE_ARN"
token="$(curl --fail --silent -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=sts.amazonaws.com" | jq -er .value)"
aws sts assume-role-with-web-identity --role-arn "$AWS_ROLE_ARN" --role-session-name "fluent-bit-mirror-${GITHUB_RUN_ID}" --web-identity-token "$token" --duration-seconds 900 > "$RUNNER_TEMP/creds.json"
AWS_ACCESS_KEY_ID="$(jq -r .Credentials.AccessKeyId "$RUNNER_TEMP/creds.json")"
AWS_SECRET_ACCESS_KEY="$(jq -r .Credentials.SecretAccessKey "$RUNNER_TEMP/creds.json")"
AWS_SESSION_TOKEN="$(jq -r .Credentials.SessionToken "$RUNNER_TEMP/creds.json")"
export AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN
destination="$ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com/node-operator-baseline-validator-fluent-bit:${SOURCE_IMAGE#*@sha256:}"
aws ecr get-login-password --region "$AWS_REGION" | docker login --username AWS --password-stdin "$ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com"
docker buildx imagetools create --prefer-index=false --tag "$destination" "$SOURCE_IMAGE"
digest="$(aws ecr describe-images --region "$AWS_REGION" --repository-name node-operator-baseline-validator-fluent-bit --image-ids "imageTag=${SOURCE_IMAGE#*@sha256:}" --query 'imageDetails[0].imageDigest' --output text)"
[[ "$digest" =~ ^sha256:[a-f0-9]{64}$ ]] || exit 1
[[ "$digest" == "${SOURCE_IMAGE##*@}" ]] || { echo 'ECR Fluent Bit digest differs from the reviewed source digest; no verified output emitted' >&2; exit 1; }
printf 'private_image=%s@%s\n' "${destination%:*}" "$digest" >> "$GITHUB_STEP_SUMMARY"
