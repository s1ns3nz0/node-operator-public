#!/usr/bin/env bash
# Check objective: Publish the locked linux/amd64 Prysm mTLS candidate with verified non-secret evidence.
set -euo pipefail
umask 077

root="$(cd "$(dirname "$0")/../.." && pwd -P)"
cd "$root"
die() { printf '%s\n' "$1" >&2; exit 65; }
need() { command -v "$1" >/dev/null 2>&1 || { printf 'missing command: %s\n' "$1" >&2; exit 69; }; }

[ "${GITHUB_REF:-}" = refs/heads/main ] || die 'publication is restricted to main'
[[ "${GITHUB_SHA:-}" =~ ^[0-9a-f]{40}$ && "${GITHUB_RUN_ID:-}" =~ ^[1-9][0-9]*$ && "${GITHUB_RUN_ATTEMPT:-}" =~ ^[0-9]+$ && "${ACCOUNT_ID:-}" =~ ^[0-9]{12}$ && "${AWS_REGION:-}" =~ ^ap-northeast-[12]$ && "${AWS_ROLE_ARN:-}" =~ ^arn:aws:iam::${ACCOUNT_ID}:role/.+$ ]] || die 'release context is invalid'
[ "$(git rev-parse HEAD)" = "$GITHUB_SHA" ] || die 'checked-out source differs from selected release revision'
DEPLOYMENT_NAME="${DEPLOYMENT_NAME:-node-operator}"
[[ "$DEPLOYMENT_NAME" =~ ^[a-z][a-z0-9-]{1,18}[a-z0-9]$ && "${RUNNER_TEMP:-}" = /* && -d "$RUNNER_TEMP" && "${ACTIONS_ID_TOKEN_REQUEST_URL:-}" = https://* && -n "${ACTIONS_ID_TOKEN_REQUEST_TOKEN:-}" ]] || die 'deployment or OIDC context is invalid'
for command in aws curl docker jq python3; do need "$command"; done

lock=.ci/prysm-mtls/source.lock.json
dockerfile=.ci/prysm-mtls/Dockerfile
ignore=.ci/prysm-mtls/Dockerfile.dockerignore
patch=.ci/prysm-mtls/patches/0001-web3signer-http-mtls.patch
security=.ci/prysm-mtls/patches/0002-security-dependencies.patch
for file in "$lock" "$dockerfile" "$ignore" "$patch" "$security" .ci/prysm-mtls-applicability.json .ci/prysm-mtls-applicability/GO-2026-5932.json scripts/release/prysm_publication_record.py scripts/ci/assess-prysm-mtls-applicability.py; do [ -f "$file" ] && [ ! -L "$file" ] || die 'reviewed input is unavailable'; done
commit="$(jq -er '.commit|select(test("^[0-9a-f]{40}$"))' "$lock")"
repo_url="$(jq -er '.repository|select(.=="https://github.com/OffchainLabs/prysm.git")' "$lock")"
builder="$(jq -er '.builder_image' "$lock")"; runtime="$(jq -er '.runtime_image' "$lock")"
patch_hash="$(jq -er '.patch_sha256|select(test("^[a-f0-9]{64}$"))' "$lock")"
security_hash="$(jq -er '.security_patch_sha256|select(test("^[a-f0-9]{64}$"))' "$lock")"
[ "$(shasum -a 256 "$patch"|awk '{print $1}')" = "$patch_hash" ] && [ "$(shasum -a 256 "$security"|awk '{print $1}')" = "$security_hash" ] || die 'patch hash differs from lock'
if ! grep -Fq "FROM $builder AS build" "$dockerfile" || ! grep -Fq "FROM $runtime" "$dockerfile" || ! grep -Fq "origin $repo_url" "$dockerfile" || ! grep -Fq "origin $commit" "$dockerfile" || ! grep -Fq 'go build -mod=readonly -trimpath -buildvcs=false -o /out/validator ./cmd/validator' "$dockerfile" || ! grep -Fq "$patch_hash" "$dockerfile" || ! grep -Fq "$security_hash" "$dockerfile"; then
  die 'Dockerfile differs from lock'
fi
input_sha="$(PYTHONPATH="$root/scripts/release" python3 -c 'from pathlib import Path; from prysm_publication_record import build_input_sha256; import sys; print(build_input_sha256(Path(sys.argv[1]).resolve()))' "$root")"
[[ "$input_sha" =~ ^[0-9a-f]{64}$ ]] || die 'input hash is invalid'
# This validates the complete lock schema and both patch contents before any
# credential request or registry operation; Dockerfile grep checks below bind
# those approved identities to the image build as well.
PYTHONPATH="$root/scripts/release" python3 -c 'from pathlib import Path; from prysm_publication_record import source_identity; import sys; source_identity(Path(sys.argv[1]).resolve())' "$root" >/dev/null

tools_dir="$RUNNER_TEMP/prysm-mtls-tools"
scripts/ci/install-validator-signing-fence-release-tools.sh "$tools_dir"
export PATH="$tools_dir:$PATH"
for command in syft grype cosign; do need "$command"; done

repository="${DEPLOYMENT_NAME}-baseline-validator-prysm"
registry="${ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com"
tag="prysm-mtls-${GITHUB_SHA}-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}"
destination="$registry/$repository:$tag"
role_name="${AWS_ROLE_ARN##*/}"
scratch="$(mktemp -d "$RUNNER_TEMP/.prysm-mtls-release.XXXXXX")"
evidence="$scratch/evidence"; mkdir -m 700 "$evidence"
record_dir="$RUNNER_TEMP/prysm-publication-records"; mkdir -m 700 "$record_dir"
record="$record_dir/prysm-mtls-publication-record.json"
docker_config="$scratch/docker-config"; mkdir -m 700 "$docker_config"
token_file="$scratch/oidc-token"; creds="$scratch/aws-credentials.json"; curl_config="$scratch/oidc-curl.conf"; oidc_response="$scratch/oidc-response.json"
cleanup() { unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN DOCKER_CONFIG; rm -rf "$scratch"; }
trap cleanup EXIT
export DOCKER_CONFIG="$docker_config"
local_image="$repository:local-${GITHUB_SHA}-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}"
docker build --pull=false --platform linux/amd64 -f "$dockerfile" -t "$local_image" .
[ "$(docker image inspect --format '{{.Os}}' "$local_image")" = linux ] && [ "$(docker image inspect --format '{{.Architecture}}' "$local_image")" = amd64 ] && [ "$(docker image inspect --format '{{ index .Config.Labels "org.opencontainers.image.revision" }}' "$local_image")" = "$commit" ] && [ "$(docker image inspect --format '{{ index .Config.Labels "io.node-operator.prysm-mtls-patch-sha256" }}' "$local_image")" = "$patch_hash" ] && [ "$(docker image inspect --format '{{ index .Config.Labels "io.node-operator.prysm-security-patch-sha256" }}' "$local_image")" = "$security_hash" ] || die 'local image does not bind lock'

printf 'header = "Authorization: bearer %s"\n' "$ACTIONS_ID_TOKEN_REQUEST_TOKEN" > "$curl_config"
curl --fail --silent --show-error --connect-timeout 10 --max-time 30 --config "$curl_config" --output "$oidc_response" "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=sts.amazonaws.com"
jq -er .value "$oidc_response" > "$token_file"
aws sts assume-role-with-web-identity --role-arn "$AWS_ROLE_ARN" --role-session-name "prysm-mtls-$GITHUB_RUN_ID" --web-identity-token "file://$token_file" --duration-seconds 900 --cli-connect-timeout 10 --cli-read-timeout 20 > "$creds"
access_key="$(jq -er .Credentials.AccessKeyId "$creds")"; secret_key="$(jq -er .Credentials.SecretAccessKey "$creds")"; session_token="$(jq -er .Credentials.SessionToken "$creds")"
printf '::add-mask::%s\n' "$access_key" "$secret_key" "$session_token"
export AWS_ACCESS_KEY_ID="$access_key" AWS_SECRET_ACCESS_KEY="$secret_key" AWS_SESSION_TOKEN="$session_token"
unset access_key secret_key session_token
identity="$(aws sts get-caller-identity --cli-connect-timeout 10 --cli-read-timeout 20 --output json)"
[ "$(jq -er .Account <<<"$identity")" = "$ACCOUNT_ID" ] && [[ "$(jq -er .Arn <<<"$identity")" == "arn:aws:sts::$ACCOUNT_ID:assumed-role/$role_name/"* ]] || die 'assumed identity differs'
aws ecr get-login-password --region "$AWS_REGION" --cli-connect-timeout 10 --cli-read-timeout 20 | docker login --username AWS --password-stdin "$registry"
docker tag "$local_image" "$destination"; docker push "$destination"
tag_json="$(aws ecr describe-images --registry-id "$ACCOUNT_ID" --region "$AWS_REGION" --repository-name "$repository" --image-ids "imageTag=$tag" --cli-connect-timeout 10 --cli-read-timeout 20 --output json)"
digest="$(jq -er --arg account "$ACCOUNT_ID" --arg repo "$repository" '.imageDetails|select(type=="array" and length==1)|.[0]|select(.registryId==$account and .repositoryName==$repo)|.imageDigest|select(test("^sha256:[a-f0-9]{64}$"))' <<<"$tag_json")"
exact_json="$(aws ecr describe-images --registry-id "$ACCOUNT_ID" --region "$AWS_REGION" --repository-name "$repository" --image-ids "imageTag=$tag,imageDigest=$digest" --cli-connect-timeout 10 --cli-read-timeout 20 --output json)"
jq -e --arg account "$ACCOUNT_ID" --arg repo "$repository" --arg digest "$digest" --arg tag "$tag" '.imageDetails as $details | ($details | type == "array" and length == 1) and ($details[0] | .registryId == $account and .repositoryName == $repo and .imageDigest == $digest and (.imageTags | type == "array" and index($tag)) and (.imageManifestMediaType | type == "string" and length > 0) and (.imagePushedAt | type == "string" or type == "number"))' <<<"$exact_json" >/dev/null || die 'ECR identity is invalid'
subject="${destination%:*}@$digest"
repo_digests="$(docker image inspect --format '{{json .RepoDigests}}' "$destination")"
jq -e --arg subject "$subject" 'type == "array" and length > 0 and index($subject)' <<<"$repo_digests" >/dev/null || die 'pushed Docker image does not bind the ECR digest'
SYFT_CHECK_FOR_APP_UPDATE=false syft scan "registry:$subject" --source-name "$repository" --source-version "$digest" --output "cyclonedx-json=$evidence/sbom.json"
# Prysm-only path: preserve the raw blocked scan and prove the one exact
# advisory is not in the complete validator closure.  Generic zero-Unknown
# release gates intentionally remain unchanged.
cat > "$evidence/grype.yaml" <<'EOF'
ignore: []
exclude: []
only-fixed: false
only-notfixed: false
show-suppressed: true
db:
  validate-by-hash-on-start: true
EOF
GRYPE_CHECK_FOR_APP_UPDATE=false grype --config "$evidence/grype.yaml" "sbom:$evidence/sbom.json" --output json --file "$evidence/grype.json"
docker image inspect --format '{{json .RepoDigests}}' "$subject" > "$evidence/repo-digests.json"
jq -n --arg subject "$subject" --argjson repos "$(cat "$evidence/repo-digests.json")" --arg os "$(docker image inspect --format '{{.Os}}' "$subject")" --arg arch "$(docker image inspect --format '{{.Architecture}}' "$subject")" --arg user "$(docker image inspect --format '{{.Config.User}}' "$subject")" --argjson entrypoint "$(docker image inspect --format '{{json .Config.Entrypoint}}' "$subject")" '{subject:$subject,RepoDigests:$repos,Os:$os,Architecture:$arch,user:$user,entrypoint:$entrypoint}' > "$evidence/runtime-identity.json"
docker run --rm --pull never --platform linux/amd64 --network none --read-only --cap-drop ALL --security-opt no-new-privileges --entrypoint /bin/sh "$subject" -ec 'sha256sum /validator; cat /usr/share/validator-dependencies.txt' > "$evidence/runtime-proof.txt"
sed -n '1p' "$evidence/runtime-proof.txt" > "$evidence/binary.sha256"; sed -n '2,$p' "$evidence/runtime-proof.txt" > "$evidence/dependencies.txt"; rm -f "$evidence/runtime-proof.txt"
curl --fail --silent --show-error --connect-timeout 10 --max-time 30 --retry 2 --output "$evidence/advisory-current.json" https://vuln.go.dev/ID/GO-2026-5932.json
unknown_count="$(jq '[.matches[]?.vulnerability.severity? | select(type=="string" and ascii_downcase=="unknown")]|length' "$evidence/grype.json")"
if [ "$unknown_count" = 0 ]; then
  scripts/ci/scan-release-sbom.sh "$evidence/sbom.json" "$evidence/scan.json"
  jq -e '.status=="passed" and .findings.critical==0 and .findings.high==0 and .findings.unknown==0' "$evidence/scan.json" >/dev/null
  applicability_arg=()
else
  python3 scripts/ci/assess-prysm-mtls-applicability.py "$evidence" > "$evidence/applicability-assessment.json"
  python3 scripts/ci/assess-prysm-mtls-applicability.py "$evidence" --verify "$evidence/applicability-assessment.json" >/dev/null
  jq -e '.raw_scan_status=="blocked" and .applicability=="not_affected" and .deployment_authorized==false' "$evidence/applicability-assessment.json" >/dev/null
  jq -c '.raw_scan_summary' "$evidence/applicability-assessment.json" > "$evidence/scan.json"
  applicability_arg=(--applicability-assessment "$evidence/applicability-assessment.json")
fi

identity_name='https://github.com/s1ns3nz0/node-operator/.github/workflows/image-publish.yml@refs/heads/main'
issuer='https://token.actions.githubusercontent.com'
scan_type='https://github.com/s1ns3nz0/node-operator/attestations/scan-summary/v1'
raw_scan_type='https://github.com/s1ns3nz0/node-operator/attestations/prysm-raw-grype/v1'
applicability_type='https://github.com/s1ns3nz0/node-operator/attestations/prysm-applicability/v2'
jq -n --arg revision "$GITHUB_SHA" --arg source "$commit" --arg source_repo "$repo_url" --arg input "$input_sha" --arg patch "$patch_hash" --arg security "$security_hash" --arg run "$GITHUB_RUN_ID" \
  '{buildDefinition:{buildType:"https://slsa.dev/container-based-build/v1",externalParameters:{reproducibility_input_sha256:$input,source_commit:$source,patch_sha256:$patch,security_patch_sha256:$security},resolvedDependencies:[{uri:"git+https://github.com/s1ns3nz0/node-operator",digest:{gitCommit:$revision}},{uri:$source_repo,digest:{gitCommit:$source}}]},runDetails:{builder:{id:"https://github.com/Attestations/GitHubHostedActions@v1"},metadata:{invocationId:$run}}}' > "$evidence/provenance.json"
cosign sign --yes "$subject"
cosign attest --yes --type slsaprovenance1 --predicate "$evidence/provenance.json" "$subject"
cosign attest --yes --type cyclonedx --predicate "$evidence/sbom.json" "$subject"
cosign attest --yes --type "$scan_type" --predicate "$evidence/scan.json" "$subject"
if [ "$unknown_count" != 0 ]; then
  cosign attest --yes --type "$raw_scan_type" --predicate "$evidence/grype.json" "$subject"
  cosign attest --yes --type "$applicability_type" --predicate "$evidence/applicability-assessment.json" "$subject"
fi
cosign verify --certificate-identity "$identity_name" --certificate-oidc-issuer "$issuer" --certificate-github-workflow-sha "$GITHUB_SHA" "$subject" > "$evidence/signature.json"
cosign verify-attestation --type slsaprovenance1 --certificate-identity "$identity_name" --certificate-oidc-issuer "$issuer" --certificate-github-workflow-sha "$GITHUB_SHA" "$subject" > "$evidence/provenance-verified.json"
cosign verify-attestation --type cyclonedx --certificate-identity "$identity_name" --certificate-oidc-issuer "$issuer" --certificate-github-workflow-sha "$GITHUB_SHA" "$subject" > "$evidence/sbom-verified.json"
cosign verify-attestation --type "$scan_type" --certificate-identity "$identity_name" --certificate-oidc-issuer "$issuer" --certificate-github-workflow-sha "$GITHUB_SHA" "$subject" > "$evidence/scan-verified.json"
if [ "$unknown_count" != 0 ]; then
  cosign verify-attestation --type "$raw_scan_type" --certificate-identity "$identity_name" --certificate-oidc-issuer "$issuer" --certificate-github-workflow-sha "$GITHUB_SHA" "$subject" > "$evidence/raw-grype-verified.json"
  cosign verify-attestation --type "$applicability_type" --certificate-identity "$identity_name" --certificate-oidc-issuer "$issuer" --certificate-github-workflow-sha "$GITHUB_SHA" "$subject" > "$evidence/applicability-verified.json"
fi
jq -s -e --arg digest "$digest" --arg reference "$subject" 'def entries: if length == 1 and (.[0] | type) == "array" then .[0] else . end; entries | any(.[]; .critical.image["docker-manifest-digest"] == $digest and .critical.identity["docker-reference"] == $reference)' "$evidence/signature.json" >/dev/null
jq -s -e --arg digest "${digest#sha256:}" --arg revision "$GITHUB_SHA" --arg source "$commit" --arg source_repo "$repo_url" --arg input "$input_sha" --arg patch "$patch_hash" --arg security "$security_hash" --arg run "$GITHUB_RUN_ID" 'def statements: if length == 1 and (.[0] | type) == "array" then .[0] else . end | map(.payload | @base64d | fromjson); statements | any(.[]; (.subject | type == "array" and any(.[]; .digest.sha256 == $digest)) and .predicateType == "https://slsa.dev/provenance/v1" and .predicate.buildDefinition == {buildType:"https://slsa.dev/container-based-build/v1",externalParameters:{reproducibility_input_sha256:$input,source_commit:$source,patch_sha256:$patch,security_patch_sha256:$security},resolvedDependencies:[{uri:"git+https://github.com/s1ns3nz0/node-operator",digest:{gitCommit:$revision}},{uri:$source_repo,digest:{gitCommit:$source}}]} and .predicate.runDetails == {builder:{id:"https://github.com/Attestations/GitHubHostedActions@v1"},metadata:{invocationId:$run}})' "$evidence/provenance-verified.json" >/dev/null
# Read large SBOMs from disk, never through argv (Linux limits each argument).
jq -s -e --arg digest "${digest#sha256:}" --slurpfile expected "$evidence/sbom.json" 'def statements: if length == 1 and (.[0] | type) == "array" then .[0] else . end | map(.payload | @base64d | fromjson); if ($expected | length) != 1 or ($expected[0] | type) != "object" then error("SBOM must be one object") else statements | any(.[]; (.subject | type == "array" and any(.[]; .digest.sha256 == $digest)) and .predicateType == "https://cyclonedx.org/bom" and .predicate == $expected[0]) end' "$evidence/sbom-verified.json" >/dev/null
verify_predicate() { jq -s -e --arg digest "${digest#sha256:}" --arg name "${subject%@*}" --arg type "$1" --slurpfile expected "$2" 'def s: if length==1 and (.[0]|type)=="array" then .[0] else . end|map(.payload|@base64d|fromjson); s|any(.[]; .predicateType==$type and (.subject|any(.name==$name and .digest.sha256==$digest)) and .predicate==$expected[0])' "$3" >/dev/null; }
verify_predicate "$scan_type" "$evidence/scan.json" "$evidence/scan-verified.json"
if [ "$unknown_count" != 0 ]; then
  verify_predicate "$raw_scan_type" "$evidence/grype.json" "$evidence/raw-grype-verified.json"
  verify_predicate "$applicability_type" "$evidence/applicability-assessment.json" "$evidence/applicability-verified.json"
fi
mkdir -m 700 "$record_dir/evidence"
for artifact in sbom.json grype.json scan.json signature.json provenance.json provenance-verified.json sbom-verified.json scan-verified.json; do cp "$evidence/$artifact" "$record_dir/evidence/$artifact"; done
if [ "$unknown_count" != 0 ]; then
  for artifact in runtime-identity.json binary.sha256 dependencies.txt advisory-current.json applicability-assessment.json raw-grype-verified.json applicability-verified.json; do cp "$evidence/$artifact" "$record_dir/evidence/$artifact"; done
fi
python3 scripts/release/prysm_publication_record.py --source-root "$root" --release-revision "$GITHUB_SHA" --build-revision "$GITHUB_SHA" --input-sha256 "$input_sha" --aws-account-id "$ACCOUNT_ID" --aws-region "$AWS_REGION" --deployment-name "$DEPLOYMENT_NAME" --repository "$repository" --image-ref "$subject" --manifest-digest "$digest" --run-id "$GITHUB_RUN_ID" --invocation prysm-mtls-publish "${applicability_arg[@]+${applicability_arg[@]}}" --output "$record"
printf 'private_image=%s\nsource_revision=%s\nrelease_verification=PASS\n' "$subject" "$GITHUB_SHA" >> "${GITHUB_STEP_SUMMARY:-/dev/null}"
