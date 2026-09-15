#!/usr/bin/env bash
# Check objective: Upload immutable release signer input and verify the CodeBuild signing result.
# Purpose: Submit the approved bundle to the CodeBuild signer and verify its returned signing evidence.
# Inputs: AWS_ROLE_ARN, AWS_REGION, INPUT_BUCKET, optional RELEASE_SIGNER_PROJECT, GitHub OIDC variables, GITHUB_RUN_ID, GITHUB_SHA, GITHUB_WORKSPACE, and RUNNER_TEMP/release assets.
# Outputs: Signer output extracted to RUNNER_TEMP/release/signer-output and CodeBuild metadata under RUNNER_TEMP.
# Side effects: Calls GitHub OIDC/AWS STS, writes an immutable S3 input object, starts/polls CodeBuild, and reads its S3 output.
set -euo pipefail

release_signer_project="${RELEASE_SIGNER_PROJECT:-node-operator-baseline-release-signer}"
if ! [[ "$release_signer_project" =~ ^[A-Za-z0-9][A-Za-z0-9_-]{1,254}$ ]]; then
  printf '%s\n' 'RELEASE_SIGNER_PROJECT must be a 2-255 character CodeBuild project name containing only letters, digits, hyphens, and underscores.' >&2
  exit 64
fi

test -n "$AWS_ROLE_ARN"; test -n "$INPUT_BUCKET"
token_file="$RUNNER_TEMP/oidc-token"
curl --fail --silent --show-error -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=sts.amazonaws.com" > "$token_file"
web_token="$(jq -r .value "$token_file")"
creds="$(aws sts assume-role-with-web-identity --role-arn "$AWS_ROLE_ARN" --role-session-name "release-${GITHUB_RUN_ID}" --web-identity-token "$web_token" --duration-seconds 900)"
AWS_ACCESS_KEY_ID="$(jq -r .Credentials.AccessKeyId <<<"$creds")"
AWS_SECRET_ACCESS_KEY="$(jq -r .Credentials.SecretAccessKey <<<"$creds")"
AWS_SESSION_TOKEN="$(jq -r .Credentials.SessionToken <<<"$creds")"
export AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN
source_revision="$(jq -er '.predicate.buildDefinition.resolvedDependencies[] | select(.uri == "git+node-operator") | .digest.gitCommit' "$RUNNER_TEMP/release/provenance-input.json")"
test "$source_revision" = "$GITHUB_SHA"
cp "$GITHUB_WORKSPACE/deploy/vault/buildspec-release-sign.yml" "$RUNNER_TEMP/release/buildspec-release-sign.yml"
input_archive="$RUNNER_TEMP/${GITHUB_SHA}.zip"
input_key="release-input/sha256/${GITHUB_SHA}.zip"
zip -q -j "$input_archive" \
  "$RUNNER_TEMP/release/node-operator-release-bundle.tar" \
  "$RUNNER_TEMP/release/node-operator-release-bundle.sha256" \
  "$RUNNER_TEMP/release/provenance-input.json" \
  "$RUNNER_TEMP/release/buildspec-release-sign.yml"
if ! aws s3api put-object --bucket "$INPUT_BUCKET" --key "$input_key" --body "$input_archive" --if-none-match '*' --region "$AWS_REGION" >/dev/null; then
  existing_input_dir="$(mktemp -d)"
  trap 'rm -rf "$existing_input_dir"' EXIT
  aws s3 cp "s3://${INPUT_BUCKET}/${input_key}" "$existing_input_dir/input.zip" --region "$AWS_REGION"
  test "$(unzip -Z1 "$existing_input_dir/input.zip" | sort)" = "$(printf '%s\n' buildspec-release-sign.yml node-operator-release-bundle.sha256 node-operator-release-bundle.tar provenance-input.json | sort)"
  unzip -q "$existing_input_dir/input.zip" -d "$existing_input_dir"
  cmp "$RUNNER_TEMP/release/node-operator-release-bundle.sha256" "$existing_input_dir/node-operator-release-bundle.sha256"
  cmp "$RUNNER_TEMP/release/provenance-input.json" "$existing_input_dir/provenance-input.json"
  cmp "$RUNNER_TEMP/release/buildspec-release-sign.yml" "$existing_input_dir/buildspec-release-sign.yml"
fi
input_version="$(aws s3api head-object --bucket "$INPUT_BUCKET" --key "$input_key" --query VersionId --output text --region "$AWS_REGION")"
test -n "$input_version"; test "$input_version" != "None"
aws codebuild start-build --project-name "$release_signer_project" --source-version "$input_version" --source-location-override "${INPUT_BUCKET}/${input_key}" --region "$AWS_REGION" > "$RUNNER_TEMP/codebuild.json"
build_id="$(jq -r .build.id "$RUNNER_TEMP/codebuild.json")"
for _ in $(seq 1 60); do
  status="$(aws codebuild batch-get-builds --ids "$build_id" --region "$AWS_REGION" | jq -r '.builds[0].buildStatus')"
  case "$status" in SUCCEEDED) break;; FAILED|FAULT|STOPPED|TIMED_OUT) echo "CodeBuild signer failed: $status" >&2; exit 1;; esac
  sleep 10
done
[ "$status" = SUCCEEDED ] || { echo 'CodeBuild signer timed out' >&2; exit 1; }
output_location="$(aws codebuild batch-get-builds --ids "$build_id" --region "$AWS_REGION" | jq -er '.builds[0].artifacts.location')"
case "$output_location" in
  arn:aws:s3:::*) output_key="${output_location#arn:aws:s3:::}" ;;
  *) echo "unexpected CodeBuild output location: $output_location" >&2; exit 1 ;;
esac
aws s3 cp "s3://${output_key}" "$RUNNER_TEMP/release-signer-output.zip" --region "$AWS_REGION"
signer_output="$RUNNER_TEMP/release/signer-output"
unzip -oq "$RUNNER_TEMP/release-signer-output.zip" -d "$signer_output"
test -f "$signer_output/release-verification.json"
scripts/ci/verify-release-signature.sh "$signer_output"
jq -e --arg sha "$source_revision" '.provenance.source_revision == $sha' "$signer_output/release-verification.json" >/dev/null
