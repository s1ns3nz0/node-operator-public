#!/usr/bin/env bash
# Check objective: Copy approved OCI digest to private ECR.
# Purpose: Copy one allowlisted GitOps OCI artifact to its private ECR repository and verify its digest.
# Inputs: ACCOUNT_ID, AWS_REGION, SOURCE, DESTINATION, ECR_TAG, MIRROR_TOOL_IMAGE, RUNNER_TEMP, and inherited AWS credentials.
# Outputs: Mirror source and verified destination digest written to GITHUB_STEP_SUMMARY.
# Side effects: Logs into ECR and may copy an OCI artifact into private ECR.
set -euo pipefail

test -n "$ACCOUNT_ID"
[[ "$MIRROR_TOOL_IMAGE" =~ ^ghcr\.io/s1ns3nz0/node-operator/gitops-oci-mirror@sha256:[a-f0-9]{64}$ ]] || { echo 'mirror tool image must be a pinned repository-owned digest' >&2; exit 1; }
source_digest="${SOURCE##*@}"
repository="node-operator-baseline-gitops-$DESTINATION"
destination_ref="$ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com/$repository:$ECR_TAG"
export DOCKER_CONFIG="$RUNNER_TEMP/ecr-docker-config"
mkdir -p "$DOCKER_CONFIG"
aws ecr get-login-password --region "$AWS_REGION" | docker login --username AWS --password-stdin "$ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com"
existing_digest="$(aws ecr describe-images --region "$AWS_REGION" --repository-name "$repository" --image-ids "imageTag=$ECR_TAG" --query 'imageDetails[0].imageDigest' --output text 2>/dev/null || true)"
if [ "$existing_digest" = "None" ]; then existing_digest=''; fi
if [ -n "$existing_digest" ]; then
  test "$existing_digest" = "$source_digest"
else
  docker run --rm \
    --env REGISTRY_AUTH_FILE=/auth/config.json \
    --volume "$DOCKER_CONFIG:/auth:ro" \
    "$MIRROR_TOOL_IMAGE" \
    copy --all "docker://$SOURCE" "docker://$destination_ref"
fi
destination_digest="$(aws ecr describe-images --region "$AWS_REGION" --repository-name "$repository" --image-ids "imageTag=$ECR_TAG" --query 'imageDetails[0].imageDigest' --output text)"
test "$destination_digest" = "$source_digest"
{
  echo '### GitOps OCI mirror'
  echo
  echo "- Source digest: \`$source_digest\`"
  echo "- Destination: \`$destination_ref\`"
  echo "- Verified ECR digest: \`$destination_digest\`"
} >> "$GITHUB_STEP_SUMMARY"
