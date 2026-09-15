#!/usr/bin/env bash
# Check objective: Mirror approved image to private ECR.
# Purpose: Copy the approved release-signer image to private ECR and require exact source/destination digest equality.
# Inputs: ACCOUNT_ID, AWS_REGION, SOURCE, SOURCE_DIGEST, REGISTRY_TOKEN, REGISTRY_USERNAME, and inherited AWS credentials.
# Outputs: ecr_image in GITHUB_OUTPUT and source/destination information in GITHUB_STEP_SUMMARY.
# Side effects: Copies the source manifest or index from GHCR to private ECR without platform selection.
set -euo pipefail

[[ "$SOURCE" =~ ^ghcr\.io/s1ns3nz0/node-operator/vault-release-signer@sha256:[a-f0-9]{64}$ ]] || { echo 'source must be the approved immutable signer reference' >&2; exit 1; }
[[ "$SOURCE_DIGEST" =~ ^sha256:[a-f0-9]{64}$ && "$SOURCE_DIGEST" == "${SOURCE##*@}" ]] || { echo 'source digest does not match the pinned signer reference' >&2; exit 1; }
test -n "$ACCOUNT_ID"
destination_repository='node-operator-baseline-vault-release-signer'
destination_registry="$ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com"
immutable_tag="approved-${SOURCE_DIGEST#sha256:}"
echo "$REGISTRY_TOKEN" | docker login ghcr.io -u "$REGISTRY_USERNAME" --password-stdin
aws ecr get-login-password --region "$AWS_REGION" | docker login --username AWS --password-stdin "$destination_registry"
# Preserve a single manifest or the complete index; do not replace it with the runner's platform image.
docker buildx imagetools create --prefer-index=false --tag "$destination_registry/$destination_repository:$immutable_tag" "$SOURCE"
destination_digest="$(aws ecr describe-images --region "$AWS_REGION" --repository-name "$destination_repository" --image-ids "imageTag=$immutable_tag" --query 'imageDetails[0].imageDigest' --output text)"
[[ "$destination_digest" =~ ^sha256:[a-f0-9]{64}$ ]] || { echo 'ECR returned an invalid signer digest' >&2; exit 1; }
[[ "$destination_digest" == "$SOURCE_DIGEST" ]] || { echo 'ECR signer digest differs from the reviewed source digest; no verified output emitted' >&2; exit 1; }
printf 'ecr_image=%s/%s@%s\n' "$destination_registry" "$destination_repository" "$destination_digest" >> "$GITHUB_OUTPUT"
# shellcheck disable=SC2016 # Backticks delimit Markdown code, not shell commands.
printf '### Private signer image mirror\n\n- Source: `%s`\n- Destination digest: `%s`\n' "$SOURCE" "$destination_digest" >> "$GITHUB_STEP_SUMMARY"
