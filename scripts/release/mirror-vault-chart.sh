#!/usr/bin/env bash
# Check objective: Verify and mirror the approved Vault chart to the private OCI registry.
# Purpose: Download, checksum-verify, and mirror the approved Vault Helm chart.
# Inputs: ACCOUNT_ID, AWS_ROLE_ARN, AWS_REGION, GitHub OIDC variables, GITHUB_RUN_ID, RUNNER_TEMP, and the approved artifact file.
# Outputs: Temporary STS credentials in GITHUB_ENV and the verified manifest digest in GITHUB_STEP_SUMMARY.
# Side effects: Calls the upstream chart endpoint and AWS STS/ECR, and pushes the chart to private ECR.
set -euo pipefail
chart="$(jq -er '.helm_archives[] | select(.name == "vault")' .ci/gitops/approved-oci-artifacts.json)"
chart_version="$(jq -er '.version' <<<"$chart")"
chart_source="$(jq -er '.source' <<<"$chart")"
chart_sha256="$(jq -er '.sha256' <<<"$chart")"
chart_manifest_digest="$(jq -er '.ecrManifestDigest' <<<"$chart")"
chart_destination="$(jq -er '.destination' <<<"$chart")"
chart_tag="$(jq -er '.ecrTag' <<<"$chart")"
test "$chart_destination" = vault
test "$chart_tag" = "$chart_version"
test "$chart_source" = "https://helm.releases.hashicorp.com/vault-$chart_version.tgz"
[[ "$chart_sha256" =~ ^[a-f0-9]{64}$ ]]
[[ "$chart_manifest_digest" =~ ^sha256:[a-f0-9]{64}$ ]]
test -n "$ACCOUNT_ID"
test -n "$AWS_ROLE_ARN"
token="$(curl --fail --silent -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=sts.amazonaws.com" | jq -er .value)"
aws sts assume-role-with-web-identity --role-arn "$AWS_ROLE_ARN" --role-session-name "vault-chart-${GITHUB_RUN_ID}" --web-identity-token "$token" --duration-seconds 900 > "$RUNNER_TEMP/creds.json"
jq -r '.Credentials | "AWS_ACCESS_KEY_ID=\(.AccessKeyId)\nAWS_SECRET_ACCESS_KEY=\(.SecretAccessKey)\nAWS_SESSION_TOKEN=\(.SessionToken)"' "$RUNNER_TEMP/creds.json" >> "$GITHUB_ENV"
AWS_ACCESS_KEY_ID="$(jq -er '.Credentials.AccessKeyId' "$RUNNER_TEMP/creds.json")"
export AWS_ACCESS_KEY_ID
AWS_SECRET_ACCESS_KEY="$(jq -er '.Credentials.SecretAccessKey' "$RUNNER_TEMP/creds.json")"
export AWS_SECRET_ACCESS_KEY
AWS_SESSION_TOKEN="$(jq -er '.Credentials.SessionToken' "$RUNNER_TEMP/creds.json")"
export AWS_SESSION_TOKEN
curl --fail --location --silent --show-error --output "$RUNNER_TEMP/vault-$chart_version.tgz" "$chart_source"
printf '%s  %s\n' "$chart_sha256" "$RUNNER_TEMP/vault-$chart_version.tgz" | sha256sum --check --status
aws ecr get-login-password --region "$AWS_REGION" | helm registry login --username AWS --password-stdin "$ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com"
helm push "$RUNNER_TEMP/vault-$chart_version.tgz" "oci://$ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com/node-operator-baseline-gitops-vault"
ecr_manifest_digest="$(aws ecr describe-images --region "$AWS_REGION" --repository-name node-operator-baseline-gitops-vault/vault --image-ids "imageTag=$chart_tag" --query 'imageDetails[0].imageDigest' --output text)"
test "$ecr_manifest_digest" = "$chart_manifest_digest"
printf 'Verified Vault chart OCI manifest digest: %s\n' "$ecr_manifest_digest" >> "$GITHUB_STEP_SUMMARY"
