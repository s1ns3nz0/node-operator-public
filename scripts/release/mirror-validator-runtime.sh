#!/usr/bin/env bash
# Check objective: Mirror reviewed runtime digests to private ECR.
# Purpose: Mirror allowlisted Web3Signer and PostgreSQL runtime images to private ECR.
# Inputs: ACCOUNT_ID, AWS_ROLE_ARN, AWS_REGION, GitHub OIDC variables, GITHUB_RUN_ID, RUNNER_TEMP, and the runtime allowlist.
# Outputs: Verified private image digests in GITHUB_STEP_SUMMARY; temporary STS credential file.
# Side effects: Calls GitHub OIDC/AWS STS and creates images in private ECR.
set -euo pipefail

test -n "$ACCOUNT_ID"; test -n "$AWS_ROLE_ARN"
approved=.ci/validator/approved-runtime-images.json
web3signer="$(jq -er '.images.web3signer.source' "$approved")"
postgres="$(jq -er '.images.postgres.source' "$approved")"
[[ "$web3signer" =~ ^consensys/web3signer@sha256:[a-f0-9]{64}$ ]]
[[ "$postgres" =~ ^postgres@sha256:[a-f0-9]{64}$ ]]
token="$(curl --fail --silent -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=sts.amazonaws.com" | jq -er .value)"
aws sts assume-role-with-web-identity --role-arn "$AWS_ROLE_ARN" --role-session-name "validator-runtime-mirror-${GITHUB_RUN_ID}" --web-identity-token "$token" --duration-seconds 900 > "$RUNNER_TEMP/creds.json"
AWS_ACCESS_KEY_ID="$(jq -r .Credentials.AccessKeyId "$RUNNER_TEMP/creds.json")"
AWS_SECRET_ACCESS_KEY="$(jq -r .Credentials.SecretAccessKey "$RUNNER_TEMP/creds.json")"
AWS_SESSION_TOKEN="$(jq -r .Credentials.SessionToken "$RUNNER_TEMP/creds.json")"
export AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN
registry="$ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com"
aws ecr get-login-password --region "$AWS_REGION" | docker login --username AWS --password-stdin "$registry"
mirror() {
  local component="$1" source="$2" repo="node-operator-baseline-validator-runtime-$1" tag digest source_digest
  tag="${source#*@sha256:}"
  source_digest="sha256:$tag"
  docker buildx imagetools create --tag "$registry/$repo:$tag" "$source"
  digest="$(aws ecr describe-images --region "$AWS_REGION" --repository-name "$repo" --image-ids "imageTag=$tag" --query 'imageDetails[0].imageDigest' --output text)"
  [[ "$digest" =~ ^sha256:[a-f0-9]{64}$ ]]
  [[ "$digest" == "$source_digest" ]] || { echo "ECR digest differs from reviewed source digest" >&2; exit 1; }
  printf '%s_private_image=%s/%s@%s\n' "$component" "$registry" "$repo" "$digest" >> "$GITHUB_STEP_SUMMARY"
}
mirror web3signer "$web3signer"
mirror postgres "$postgres"
