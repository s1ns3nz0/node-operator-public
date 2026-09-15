#!/usr/bin/env bash
# Check objective: Build, scan, attest, and publish the reviewed validator signing-fence image.
# Purpose: Build, scan, sign, attest, and publish the validator signing-fence image from main.
# Inputs: GITHUB_REF, GITHUB_SHA, GITHUB_RUN_ID, ACCOUNT_ID, AWS_ROLE_ARN, AWS_REGION, GitHub OIDC variables, and RUNNER_TEMP.
# Outputs: SBOM, scan, provenance, and release-verification files under RUNNER_TEMP; image metadata in GITHUB_STEP_SUMMARY.
# Side effects: Calls GitHub OIDC/AWS STS, pushes to private ECR, and writes Cosign signatures and attestations.
set -euo pipefail

die() { printf '%s\n' "$1" >&2; exit 65; }
test "${GITHUB_REF:-}" = refs/heads/main || die 'publication is restricted to main'
DEPLOYMENT_NAME="${DEPLOYMENT_NAME:-node-operator}"
[[ "$DEPLOYMENT_NAME" =~ ^[a-z][a-z0-9-]{1,18}[a-z0-9]$ ]] || die 'deployment name is invalid'
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
scripts/ci/install-validator-signing-fence-release-tools.sh "$RUNNER_TEMP/fence-tools"
export PATH="$RUNNER_TEMP/fence-tools:$PATH"
bash scripts/ci/test-release-scan-cosign-roundtrip.sh
input_sha="$(python3 "$root/scripts/release/fence_build_inputs.py" --root "$root")"
token="$(curl --fail --silent -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=sts.amazonaws.com" | jq -er .value)"
token_file="$RUNNER_TEMP/aws-web-identity-token"
(umask 077; printf '%s' "$token" > "$token_file")
unset token
aws sts assume-role-with-web-identity --role-arn "$AWS_ROLE_ARN" --role-session-name "fence-image-${GITHUB_RUN_ID}" --web-identity-token "file://$token_file" --duration-seconds 900 > "$RUNNER_TEMP/creds.json"
rm -f "$token_file"
access_key="$(jq -er .Credentials.AccessKeyId "$RUNNER_TEMP/creds.json")"
secret_key="$(jq -er .Credentials.SecretAccessKey "$RUNNER_TEMP/creds.json")"
session_token="$(jq -er .Credentials.SessionToken "$RUNNER_TEMP/creds.json")"
printf '::add-mask::%s\n' "$access_key" "$secret_key" "$session_token"
export AWS_ACCESS_KEY_ID="$access_key" AWS_SECRET_ACCESS_KEY="$secret_key" AWS_SESSION_TOKEN="$session_token"
registry="$ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com"
repository="${DEPLOYMENT_NAME}-baseline-validator-fence"
tag="fence-${GITHUB_SHA}-${GITHUB_RUN_ID}"
destination="$registry/$repository:$tag"
aws ecr get-login-password --region "$AWS_REGION" | docker login --username AWS --password-stdin "$registry"
docker build --pull=false --build-arg "FENCE_INPUT_SHA=$input_sha" -f .ci/validator-signing-fence/Dockerfile -t "$destination" .
docker push "$destination"
digest="$(aws ecr describe-images --region "$AWS_REGION" --repository-name "$repository" --image-ids "imageTag=$tag" --query 'imageDetails[0].imageDigest' --output text)"
[[ "$digest" =~ ^sha256:[a-f0-9]{64}$ ]] || exit 1
subject="${destination%:*}@$digest"
syft scan "registry:$subject" --source-name "$repository" --source-version "$digest" --output "cyclonedx-json=$RUNNER_TEMP/fence-sbom.json"
scripts/ci/scan-release-sbom.sh "$RUNNER_TEMP/fence-sbom.json" "$RUNNER_TEMP/fence-scan.json"
jq -e '.status == "passed"' "$RUNNER_TEMP/fence-scan.json" >/dev/null
jq -n --arg revision "$GITHUB_SHA" --arg run "$GITHUB_RUN_ID" --arg input_sha "$input_sha" \
  '{buildDefinition:{buildType:"https://slsa.dev/container-based-build/v1",externalParameters:{input_sha256:$input_sha},resolvedDependencies:[{uri:"git+https://github.com/s1ns3nz0/node-operator",digest:{gitCommit:$revision}}]},runDetails:{builder:{id:"https://github.com/Attestations/GitHubHostedActions@v1"},metadata:{invocationId:$run}}}' > "$RUNNER_TEMP/fence-provenance.json"
cosign sign --yes "$subject"
cosign attest --yes --type slsaprovenance1 --predicate "$RUNNER_TEMP/fence-provenance.json" "$subject"
cosign attest --yes --type cyclonedx --predicate "$RUNNER_TEMP/fence-sbom.json" "$subject"
cosign attest --yes --type https://github.com/s1ns3nz0/node-operator/attestations/scan-summary/v1 --predicate "$RUNNER_TEMP/fence-scan.json" "$subject"
scripts/ci/collect-validator-signing-fence-release-evidence.sh "$subject" "$GITHUB_SHA" "$RUNNER_TEMP/fence-release-verification.json"
printf 'private_image=%s\nsource_revision=%s\ninput_sha256=%s\nrelease_verification=PASS\n' "$subject" "$GITHUB_SHA" "$input_sha" >> "$GITHUB_STEP_SUMMARY"
