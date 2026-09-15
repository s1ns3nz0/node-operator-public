#!/usr/bin/env bash
# Check objective: Verify frozen candidate without rebuilding or publishing.
# Purpose: Read and assess one approved Vault runtime candidate without building, publishing, or deploying it.
# Inputs: Main-branch/OIDC context, AWS verifier role, component, candidate allowlist, and pinned tools.
# Outputs: Component verification JSON and verification-run metadata beneath RUNNER_TEMP/vault-runtime-evidence.
# Side effects: Read-only ECR/AWS access and local Docker pulls; temporary credentials and files are removed.
set -euo pipefail

umask 077
test "$GITHUB_REF" = refs/heads/main
test -n "$AWS_ROLE_ARN"
scratch="$(mktemp -d)"
cleanup() { rm -rf "$scratch"; }
trap cleanup EXIT
export DOCKER_CONFIG="$scratch/docker"
mkdir -p "$DOCKER_CONFIG"
scripts/ci/install-validator-signing-fence-release-tools.sh "$RUNNER_TEMP/vault-runtime-tools"
export PATH="$RUNNER_TEMP/vault-runtime-tools:$PATH"
printf 'header = "Authorization: bearer %s"\n' "$ACTIONS_ID_TOKEN_REQUEST_TOKEN" > "$scratch/oidc.conf"
curl --fail --silent --show-error --config "$scratch/oidc.conf" --output "$scratch/oidc.json" "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=sts.amazonaws.com"
jq -er .value "$scratch/oidc.json" > "$scratch/oidc.token"
aws sts assume-role-with-web-identity --role-arn "$AWS_ROLE_ARN" --role-session-name "vault-verify-${GITHUB_RUN_ID}-${COMPONENT}" --web-identity-token "file://$scratch/oidc.token" --duration-seconds 3600 > "$scratch/credentials.json"
access_key="$(jq -er .Credentials.AccessKeyId "$scratch/credentials.json")"
secret_key="$(jq -er .Credentials.SecretAccessKey "$scratch/credentials.json")"
session_token="$(jq -er .Credentials.SessionToken "$scratch/credentials.json")"
printf '::add-mask::%s\n' "$access_key" "$secret_key" "$session_token"
export AWS_ACCESS_KEY_ID="$access_key" AWS_SECRET_ACCESS_KEY="$secret_key" AWS_SESSION_TOKEN="$session_token"
unset access_key secret_key session_token
rm -f "$scratch/oidc.conf" "$scratch/oidc.json" "$scratch/oidc.token" "$scratch/credentials.json"
registry="$(jq -er .registry .ci/vault-runtime-candidates.json)"
aws ecr get-login-password --region "$AWS_REGION" | docker login --username AWS --password-stdin "$registry"
bash scripts/ci/verify-vault-runtime-candidate.sh "$COMPONENT" "$RUNNER_TEMP/vault-runtime-evidence"
jq -n --arg repository "$GITHUB_REPOSITORY" --arg revision "$GITHUB_SHA" \
  --arg run_id "$GITHUB_RUN_ID" --arg attempt "$GITHUB_RUN_ATTEMPT" --arg component "$COMPONENT" \
  '{repository:$repository,source_revision:$revision,run_id:$run_id,run_attempt:$attempt,component:$component,ref:"refs/heads/main"}' \
  > "$RUNNER_TEMP/vault-runtime-evidence/verification-run.json"
