#!/usr/bin/env bash
# Check objective: Fetch version-bound OCI release bytes using a short-lived CI-only read role.
# Inputs: reviewed release/oci-payload-source.json, OCI_STAGING_READ_ROLE_ARN,
# GitHub OIDC runtime variables, RUNNER_TEMP. No operator deployment credentials.
# Outputs: private RUNNER_TEMP/release-oci/payload; no credentials in GITHUB_ENV.
set -euo pipefail
umask 077
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
source_config="$root/release/oci-payload-source.json"
[ -f "$source_config" ] && [ ! -L "$source_config" ] || { echo 'reviewed OCI staging descriptor is required' >&2; exit 65; }
[[ "${OCI_STAGING_READ_ROLE_ARN:-}" =~ ^arn:aws:iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_/-]+$ ]] || { echo 'OCI staging read role is required' >&2; exit 64; }
[[ "${RUNNER_TEMP:-}" = /* && -d "$RUNNER_TEMP" && ! -L "$RUNNER_TEMP" && "${ACTIONS_ID_TOKEN_REQUEST_URL:-}" = https://* && -n "${ACTIONS_ID_TOKEN_REQUEST_TOKEN:-}" ]] || { echo 'private CI OIDC context is required' >&2; exit 64; }
region="$(jq -er '.region | select(type == "string" and test("^[a-z]{2}-[a-z]+-[0-9]+$"))' "$source_config")"
workspace="$RUNNER_TEMP/release-oci"
mkdir -m 700 "$workspace"
auth="$(mktemp -d "$RUNNER_TEMP/.release-oci-auth.XXXXXX")"
trap 'rm -rf "$auth"' EXIT
# curl reads the bearer header from a private file, not a process argument.
[[ "$ACTIONS_ID_TOKEN_REQUEST_TOKEN" != *$'\n'* && "$ACTIONS_ID_TOKEN_REQUEST_TOKEN" != *$'\r'* && "$ACTIONS_ID_TOKEN_REQUEST_TOKEN" != *'"'* && "$ACTIONS_ID_TOKEN_REQUEST_TOKEN" != *'\'* ]] || exit 65
printf 'header = "Authorization: bearer %s"\n' "$ACTIONS_ID_TOKEN_REQUEST_TOKEN" > "$auth/curl.conf"
curl --fail --silent --show-error --connect-timeout 10 --max-time 30 \
  --config "$auth/curl.conf" --output "$auth/response.json" \
  "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=sts.amazonaws.com"
jq -er '.value | select(type == "string" and test("^[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+$"))' "$auth/response.json" > "$auth/token"
# SDK web identity provider obtains scoped temporary STS credentials. Only this
# child receives them; existing operator env (especially GITHUB_TOKEN) is intact.
env -u AWS_ACCESS_KEY_ID -u AWS_SECRET_ACCESS_KEY -u AWS_SESSION_TOKEN \
  -u AWS_PROFILE -u AWS_DEFAULT_PROFILE \
  AWS_CONFIG_FILE=/dev/null AWS_SHARED_CREDENTIALS_FILE=/dev/null \
  AWS_ROLE_ARN="$OCI_STAGING_READ_ROLE_ARN" AWS_WEB_IDENTITY_TOKEN_FILE="$auth/token" \
  AWS_ROLE_SESSION_NAME=release-oci-read AWS_REGION="$region" AWS_DEFAULT_REGION="$region" \
  AWS_IGNORE_CONFIGURED_ENDPOINT_URLS=true PYTHONDONTWRITEBYTECODE=1 \
  python3 -B "$root/scripts/release/release_oci_staging.py" \
    --source-config "$source_config" --output-dir "$workspace/payload"
