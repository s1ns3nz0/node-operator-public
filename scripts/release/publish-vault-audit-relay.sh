#!/usr/bin/env bash
# Check objective: Build, scan, attest, publish, and verify the Vault audit-relay image.
# Purpose: Build, scan, sign, attest, publish, and verify the Vault audit-relay image from main.
# Inputs: GITHUB_REF, GITHUB_SHA, GITHUB_RUN_ID, GITHUB_RUN_ATTEMPT, ACCOUNT_ID, AWS_ROLE_ARN, AWS_REGION, optional DEPLOYMENT_NAME, GitHub OIDC variables, and RUNNER_TEMP.
# Outputs: Temporary release evidence under RUNNER_TEMP and verified image metadata in GITHUB_STEP_SUMMARY.
# Side effects: Calls GitHub OIDC/AWS STS, pushes to private ECR, and writes Cosign signatures and attestations.
set -euo pipefail; umask 077
test "$GITHUB_REF" = refs/heads/main
DEPLOYMENT_NAME="${DEPLOYMENT_NAME:-node-operator}"
[[ "$DEPLOYMENT_NAME" =~ ^[a-z][a-z0-9-]{1,18}[a-z0-9]$ ]] || { printf '%s\n' 'deployment context is invalid' >&2; exit 65; }
evidence="$RUNNER_TEMP/vault-audit-relay-release-evidence"; mkdir -p "$evidence"
docker_config="$(mktemp -d)"; token_file="$RUNNER_TEMP/vault-audit-relay-oidc-token"; curl_config="$RUNNER_TEMP/vault-audit-relay-oidc.conf"; response="$RUNNER_TEMP/vault-audit-relay-oidc.json"; creds="$RUNNER_TEMP/vault-audit-relay-creds.json"
cleanup() { rm -rf "$docker_config"; rm -f "$token_file" "$curl_config" "$response" "$creds"; }; trap cleanup EXIT
export DOCKER_CONFIG="$docker_config"
repository="${DEPLOYMENT_NAME}-baseline-vault-audit-relay"
identity='https://github.com/s1ns3nz0/node-operator/.github/workflows/image-publish.yml@refs/heads/main'
issuer='https://token.actions.githubusercontent.com'
input_sha="$({ sha256sum .ci/vault-audit-relay/Dockerfile go.mod cmd/vault-audit-relay/main.go cmd/vault-audit-relay/main_test.go; } | awk '{print $1}' | sha256sum | awk '{print $1}')"
local_image="$repository:local-${GITHUB_SHA}-${GITHUB_RUN_ID}"
label_format='{{ index .Config.Labels "io.node-operator.vault-audit-relay-input-sha" }}'
scripts/ci/install-validator-signing-fence-release-tools.sh "$RUNNER_TEMP/vault-audit-relay-tools"; export PATH="$RUNNER_TEMP/vault-audit-relay-tools:$PATH"
bash scripts/ci/test-release-scan-cosign-roundtrip.sh
docker build --pull=false --platform linux/amd64 --build-arg "RELAY_INPUT_SHA=$input_sha" -f .ci/vault-audit-relay/Dockerfile -t "$local_image" .
test linux/amd64 = "$(docker image inspect --format '{{.Os}}/{{.Architecture}}' "$local_image")"
test "$input_sha" = "$(docker image inspect --format "$label_format" "$local_image")"
local_digest="$(docker image inspect --format '{{.Id}}' "$local_image")"; [[ "$local_digest" =~ ^sha256:[a-f0-9]{64}$ ]]
scan() { local ref="$1" digest="$2" prefix="$3"; SYFT_CHECK_FOR_APP_UPDATE=false syft scan "$ref" --source-name "$repository" --source-version "$digest" --output "cyclonedx-json=$evidence/$prefix-sbom.json"; jq -e --arg digest "$digest" '.bomFormat == "CycloneDX" and (.specVersion|type=="string" and length>0) and .metadata.component.version == $digest and (.components|type=="array" and length>0)' "$evidence/$prefix-sbom.json" >/dev/null; GRYPE_CHECK_FOR_APP_UPDATE=false grype "sbom:$evidence/$prefix-sbom.json" --output json --file "$evidence/$prefix-grype.json"; jq -e '(.matches|type=="array") and .descriptor.name == "grype" and .descriptor.db.status.valid == true and (.descriptor.db.status.built|type=="string" and length>0) and all(.matches[]; .vulnerability.severity|type=="string") and ([.matches[]?.vulnerability.severity|ascii_downcase|select(.=="critical" or .=="high" or .=="unknown")]|length==0)' "$evidence/$prefix-grype.json" >/dev/null; scripts/ci/scan-release-sbom.sh "$evidence/$prefix-sbom.json" "$evidence/$prefix-scan-summary.json"; jq -e '.status == "passed" and .findings.critical == 0 and .findings.high == 0 and .findings.unknown == 0' "$evidence/$prefix-scan-summary.json" >/dev/null; }
scan "docker:$local_image" "$local_digest" local
# input_sha is reproducibility metadata, not a cryptographic attestation.
test -n "$ACCOUNT_ID"; test -n "$AWS_ROLE_ARN"
printf 'header = "Authorization: bearer %s"\n' "$ACTIONS_ID_TOKEN_REQUEST_TOKEN" > "$curl_config"
curl --fail --silent --show-error --config "$curl_config" --output "$response" "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=sts.amazonaws.com"
token="$(jq -er .value "$response")"; printf '%s' "$token" > "$token_file"; unset token
aws sts assume-role-with-web-identity --role-arn "$AWS_ROLE_ARN" --role-session-name "vault-audit-relay-${GITHUB_RUN_ID}" --web-identity-token "file://$token_file" --duration-seconds 900 > "$creds"; rm -f "$token_file" "$curl_config" "$response"
access_key="$(jq -er .Credentials.AccessKeyId "$creds")"; secret_key="$(jq -er .Credentials.SecretAccessKey "$creds")"; session_token="$(jq -er .Credentials.SessionToken "$creds")"; printf '::add-mask::%s\n' "$access_key" "$secret_key" "$session_token"; export AWS_ACCESS_KEY_ID="$access_key" AWS_SECRET_ACCESS_KEY="$secret_key" AWS_SESSION_TOKEN="$session_token"
registry="$ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com"; tag="relay-${GITHUB_SHA}-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}"; destination="$registry/$repository:$tag"
aws ecr get-login-password --region "$AWS_REGION" | docker login --username AWS --password-stdin "$registry"; docker tag "$local_image" "$destination"; docker push "$destination"
digest="$(aws ecr describe-images --region "$AWS_REGION" --repository-name "$repository" --image-ids "imageTag=$tag" --query 'imageDetails[0].imageDigest' --output text)"; [[ "$digest" =~ ^sha256:[a-f0-9]{64}$ ]]; subject="${destination%:*}@$digest"
scan "registry:$subject" "$digest" registry
jq -n --arg revision "$GITHUB_SHA" --arg run "$GITHUB_RUN_ID" --arg input_sha "$input_sha" '{buildDefinition:{buildType:"https://slsa.dev/container-based-build/v1",externalParameters:{reproducibility_input_sha256:$input_sha},resolvedDependencies:[{uri:"git+https://github.com/s1ns3nz0/node-operator",digest:{gitCommit:$revision}}]},runDetails:{builder:{id:"https://github.com/Attestations/GitHubHostedActions@v1"},metadata:{invocationId:$run}}}' > "$evidence/provenance.json"
cosign sign --yes "$subject"; cosign attest --yes --type slsaprovenance1 --predicate "$evidence/provenance.json" "$subject"; cosign attest --yes --type cyclonedx --predicate "$evidence/registry-sbom.json" "$subject"; cosign attest --yes --type https://github.com/s1ns3nz0/node-operator/attestations/scan-summary/v1 --predicate "$evidence/registry-scan-summary.json" "$subject"
cosign verify --certificate-identity "$identity" --certificate-oidc-issuer "$issuer" --certificate-github-workflow-sha "$GITHUB_SHA" "$subject" > "$evidence/signature-verification.json"
cosign verify-attestation --type slsaprovenance1 --certificate-identity "$identity" --certificate-oidc-issuer "$issuer" --certificate-github-workflow-sha "$GITHUB_SHA" "$subject" > "$evidence/provenance-verification.json"
cosign verify-attestation --type cyclonedx --certificate-identity "$identity" --certificate-oidc-issuer "$issuer" --certificate-github-workflow-sha "$GITHUB_SHA" "$subject" > "$evidence/sbom-verification.json"
cosign verify-attestation --type https://github.com/s1ns3nz0/node-operator/attestations/scan-summary/v1 --certificate-identity "$identity" --certificate-oidc-issuer "$issuer" --certificate-github-workflow-sha "$GITHUB_SHA" "$subject" > "$evidence/scan-verification.json"
jq -s -e --arg digest "$digest" --arg revision "$GITHUB_SHA" 'map(.payload|@base64d|fromjson)|any(.[]; .predicateType == "https://slsa.dev/provenance/v1" and (.subject|any(.digest.sha256 == ($digest|sub("^sha256:";"")))) and (.predicate.buildDefinition.resolvedDependencies|any(.digest.gitCommit == $revision)))' "$evidence/provenance-verification.json" >/dev/null
jq -s -e --arg digest "$digest" 'map(.payload|@base64d|fromjson)|any(.[]; (.subject|any(.digest.sha256 == ($digest|sub("^sha256:";"")))) and .predicate.bomFormat == "CycloneDX" and .predicate.metadata.component.version == $digest)' "$evidence/sbom-verification.json" >/dev/null
bash scripts/ci/verify-release-scan-attestation.sh "$evidence/scan-verification.json" "$digest" "$evidence/registry-scan-summary.json"
record="$evidence/vault-audit-relay-publication-record.json"
[[ "$GITHUB_SHA" =~ ^[0-9a-f]{40}$ ]] || { printf '%s\n' 'release revision is invalid' >&2; exit 65; }
[[ "$input_sha" =~ ^[0-9a-f]{64}$ ]] || { printf '%s\n' 'relay input hash is invalid' >&2; exit 65; }
[[ "$GITHUB_RUN_ID" =~ ^[0-9]+$ ]] || { printf '%s\n' 'publication run id is invalid' >&2; exit 65; }
[ ! -e "$record" ] && [ ! -L "$record" ] || { printf '%s\n' 'refusing to overwrite relay publication record' >&2; exit 65; }
record_tmp="$(mktemp "$evidence/.vault-audit-relay-publication-record.XXXXXX")"
chmod 600 "$record_tmp"
jq -n --arg revision "$GITHUB_SHA" --arg image "$subject" --arg digest "$digest" --arg input "$input_sha" --arg run "$GITHUB_RUN_ID" \
  '{schema_version:1,component:"vault-audit-relay",kind:"image",release_revision:$revision,build_revision:$revision,third_party_source_revision:null,image_ref:$image,manifest_digest:$digest,input_sha256:$input,publication:{workflow:"image-publish.yml",run_id:$run,invocation:"relay-publish"},verification:{method:"cosign-and-slsa",status:"passed"}}' > "$record_tmp"
ln "$record_tmp" "$record" || { rm -f "$record_tmp"; printf '%s\n' 'refusing to overwrite relay publication record' >&2; exit 65; }
rm -f "$record_tmp"
printf 'private_image=%s\nsource_revision=%s\nreproducibility_input_sha256=%s\nrelease_verification=PASS\n' "$subject" "$GITHUB_SHA" "$input_sha" >> "$GITHUB_STEP_SUMMARY"
