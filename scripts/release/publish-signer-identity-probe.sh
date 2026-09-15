#!/usr/bin/env bash
# Check objective: Build verify and publish the signer identity probe.
# Purpose: Build, verify, and publish the first-party signer identity probe.
# Inputs: main GitHub Actions context, selected AWS deployment context, and reviewed source files.
# Outputs: one public, digest-bound publication record; private OIDC, AWS, and Docker state is removed.
set -euo pipefail
umask 077
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"; cd "$root"
die() { printf '%s\n' "$1" >&2; exit 65; }
need() { command -v "$1" >/dev/null 2>&1 || { printf 'missing command: %s\n' "$1" >&2; exit 69; }; }
[ "${GITHUB_REF:-}" = refs/heads/main ] && [ "${GITHUB_REPOSITORY:-}" = s1ns3nz0/node-operator ] || die 'publication is restricted to repository main'
[[ "${GITHUB_SHA:-}" =~ ^[0-9a-f]{40}$ && "${GITHUB_RUN_ID:-}" =~ ^[1-9][0-9]*$ && "${GITHUB_RUN_ATTEMPT:-}" =~ ^[0-9]+$ && "${ACCOUNT_ID:-}" =~ ^[0-9]{12}$ && "${AWS_REGION:-}" =~ ^ap-northeast-[12]$ && "${AWS_ROLE_ARN:-}" =~ ^arn:aws:iam::${ACCOUNT_ID}:role/.+$ ]] || die 'release context is invalid'
[ "$(git rev-parse HEAD)" = "$GITHUB_SHA" ] || die 'checked-out source differs from selected release revision'
DEPLOYMENT_NAME="${DEPLOYMENT_NAME:-node-operator}"
[[ "$DEPLOYMENT_NAME" =~ ^[a-z][a-z0-9-]{1,18}[a-z0-9]$ && "${RUNNER_TEMP:-}" = /* && -d "$RUNNER_TEMP" && "${ACTIONS_ID_TOKEN_REQUEST_URL:-}" = https://* && -n "${ACTIONS_ID_TOKEN_REQUEST_TOKEN:-}" ]] || die 'deployment or OIDC context is invalid'
for command in aws curl docker jq python3 git; do need "$command"; done
dockerfile=.ci/validator-signer-identity-probe/Dockerfile
source_files=(go.mod "$dockerfile" .ci/validator-signer-identity-probe/Dockerfile.dockerignore cmd/validator-signer-identity-probe/main.go cmd/validator-signer-identity-probe/main_test.go scripts/release/signer_probe_build_inputs.py scripts/release/signer_probe_publication_record.py scripts/release/fence_build_inputs.py scripts/release/publish-signer-identity-probe.sh scripts/ci/install-validator-signing-fence-release-tools.sh scripts/ci/scan-release-sbom.sh scripts/ci/verify-release-scan-attestation.sh scripts/ci/lib/common.sh .github/workflows/image-publish.yml)
for file in "${source_files[@]}"; do [ -f "$file" ] && [ ! -L "$file" ] || die 'reviewed input is unavailable'; done
git ls-files --error-unmatch -- "${source_files[@]}" >/dev/null && git diff --quiet HEAD -- "${source_files[@]}" && git diff --cached --quiet -- "${source_files[@]}" || die 'reviewed publisher inputs differ from selected release revision'
input_sha="$(python3 "$root/scripts/release/signer_probe_build_inputs.py" --root "$root")"; [[ "$input_sha" =~ ^[a-f0-9]{64}$ ]] || die 'input hash is invalid'
record_dir="$RUNNER_TEMP/signer-probe-publication-records"; record="$record_dir/signer-identity-probe-publication-record.json"
[ ! -e "$record_dir" ] && [ ! -L "$record_dir" ] || die 'publication record output already exists'
mkdir -m 700 "$record_dir"
tools="$RUNNER_TEMP/signer-probe-tools"; scripts/ci/install-validator-signing-fence-release-tools.sh "$tools"; export PATH="$tools:$PATH"
for command in syft grype cosign; do need "$command"; done
repository="${DEPLOYMENT_NAME}-baseline-validator-signer-identity-probe"; registry="${ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com"; tag="signer-identity-probe-${GITHUB_SHA}-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}"; destination="$registry/$repository:$tag"
scratch="$(mktemp -d "$RUNNER_TEMP/.signer-probe-release.XXXXXX")"
cleanup() { unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN DOCKER_CONFIG; rm -rf "${scratch:-}"; }
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
evidence="$scratch/evidence"; mkdir -m 700 "$evidence"; docker_config="$scratch/docker-config"; mkdir -m 700 "$docker_config"; token_file="$scratch/oidc-token"; creds="$scratch/aws-credentials.json"; curl_config="$scratch/oidc-curl.conf"; oidc_response="$scratch/oidc-response.json"
export DOCKER_CONFIG="$docker_config"; local_image="$repository:local-${GITHUB_SHA}-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}"
# Build locally before requesting cloud credentials.  The embedded label binds
# the exact five reviewed source inputs to the local linux/amd64 image.
docker build --pull=false --platform linux/amd64 --build-arg "SIGNER_PROBE_INPUT_SHA=$input_sha" -f "$dockerfile" -t "$local_image" .
[ "$(docker image inspect --format '{{.Os}}/{{.Architecture}}' "$local_image")" = linux/amd64 ] && [ "$(docker image inspect --format '{{ index .Config.Labels "io.node-operator.signer-probe-input-sha" }}' "$local_image")" = "$input_sha" ] || die 'local image does not bind signer probe inputs'
printf 'header = "Authorization: bearer %s"\n' "$ACTIONS_ID_TOKEN_REQUEST_TOKEN" > "$curl_config"
# OIDC and short-lived role credentials are requested only after the local
# source-bound build has passed; all credential-bearing files live in scratch.
curl --fail --silent --show-error --connect-timeout 10 --max-time 30 --config "$curl_config" --output "$oidc_response" "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=sts.amazonaws.com"
jq -er .value "$oidc_response" > "$token_file"
aws sts assume-role-with-web-identity --role-arn "$AWS_ROLE_ARN" --role-session-name "signer-probe-$GITHUB_RUN_ID" --web-identity-token "file://$token_file" --duration-seconds 900 --cli-connect-timeout 10 --cli-read-timeout 20 > "$creds"
access_key="$(jq -er .Credentials.AccessKeyId "$creds")"; secret_key="$(jq -er .Credentials.SecretAccessKey "$creds")"; session_token="$(jq -er .Credentials.SessionToken "$creds")"; printf '::add-mask::%s\n' "$access_key" "$secret_key" "$session_token"; export AWS_ACCESS_KEY_ID="$access_key" AWS_SECRET_ACCESS_KEY="$secret_key" AWS_SESSION_TOKEN="$session_token"; unset access_key secret_key session_token
role_name="${AWS_ROLE_ARN##*/}"; identity="$(aws sts get-caller-identity --cli-connect-timeout 10 --cli-read-timeout 20 --output json)"; [ "$(jq -er .Account <<<"$identity")" = "$ACCOUNT_ID" ] && [[ "$(jq -er .Arn <<<"$identity")" == "arn:aws:sts::$ACCOUNT_ID:assumed-role/$role_name/"* ]] || die 'assumed identity differs'
aws ecr get-login-password --region "$AWS_REGION" --cli-connect-timeout 10 --cli-read-timeout 20 | docker login --username AWS --password-stdin "$registry"
# The registry tag and the locally observed pushed digest must agree before
# evidence or signatures can be created for this immutable subject.
docker tag "$local_image" "$destination"; docker push "$destination"
tag_json="$(aws ecr describe-images --registry-id "$ACCOUNT_ID" --region "$AWS_REGION" --repository-name "$repository" --image-ids "imageTag=$tag" --cli-connect-timeout 10 --cli-read-timeout 20 --output json)"; digest="$(jq -er --arg account "$ACCOUNT_ID" --arg repo "$repository" '.imageDetails|select(type=="array" and length==1)|.[0]|select(.registryId==$account and .repositoryName==$repo)|.imageDigest|select(test("^sha256:[a-f0-9]{64}$"))' <<<"$tag_json")"
exact_json="$(aws ecr describe-images --registry-id "$ACCOUNT_ID" --region "$AWS_REGION" --repository-name "$repository" --image-ids "imageTag=$tag,imageDigest=$digest" --cli-connect-timeout 10 --cli-read-timeout 20 --output json)"; jq -e --arg account "$ACCOUNT_ID" --arg repo "$repository" --arg digest "$digest" --arg tag "$tag" '.imageDetails as $x|($x|type=="array" and length==1) and ($x[0]|.registryId==$account and .repositoryName==$repo and .imageDigest==$digest and (.imageTags|type=="array" and index($tag)) and (.imageManifestMediaType|type=="string" and length>0))' <<<"$exact_json" >/dev/null || die 'ECR identity is invalid'
subject="${destination%:*}@$digest"; jq -e --arg subject "$subject" 'type=="array" and index($subject)' <<<"$(docker image inspect --format '{{json .RepoDigests}}' "$destination")" >/dev/null || die 'pushed Docker image does not bind the ECR digest'
SYFT_CHECK_FOR_APP_UPDATE=false syft scan "registry:$subject" --source-name "$repository" --source-version "$digest" --output "cyclonedx-json=$evidence/sbom.json"; scripts/ci/scan-release-sbom.sh "$evidence/sbom.json" "$evidence/scan.json"; jq -e --arg digest "$digest" '.metadata.component.version==$digest' "$evidence/sbom.json" >/dev/null; jq -e '.status=="passed" and .findings.critical==0 and .findings.high==0 and .findings.unknown==0' "$evidence/scan.json" >/dev/null
identity_name='https://github.com/s1ns3nz0/node-operator/.github/workflows/image-publish.yml@refs/heads/main'; issuer='https://token.actions.githubusercontent.com'; scan_type='https://github.com/s1ns3nz0/node-operator/attestations/scan-summary/v1'
# Sign, attest, then independently re-read each signature/statement and bind
# its subject name, digest, first-party revision, run, and raw scanner output.
jq -n --arg revision "$GITHUB_SHA" --arg input "$input_sha" --arg run "$GITHUB_RUN_ID" '{buildDefinition:{buildType:"https://slsa.dev/container-based-build/v1",externalParameters:{signer_probe_input_sha256:$input},resolvedDependencies:[{uri:"git+https://github.com/s1ns3nz0/node-operator",digest:{gitCommit:$revision}}]},runDetails:{builder:{id:"https://github.com/Attestations/GitHubHostedActions@v1"},metadata:{invocationId:$run}}}' > "$evidence/provenance.json"
cosign sign --yes "$subject"; cosign attest --yes --type slsaprovenance1 --predicate "$evidence/provenance.json" "$subject"; cosign attest --yes --type cyclonedx --predicate "$evidence/sbom.json" "$subject"; cosign attest --yes --type "$scan_type" --predicate "$evidence/scan.json" "$subject"
cosign verify --certificate-identity "$identity_name" --certificate-oidc-issuer "$issuer" --certificate-github-workflow-sha "$GITHUB_SHA" "$subject" > "$evidence/signature.json"; cosign verify-attestation --type slsaprovenance1 --certificate-identity "$identity_name" --certificate-oidc-issuer "$issuer" --certificate-github-workflow-sha "$GITHUB_SHA" "$subject" > "$evidence/provenance-verified.json"; cosign verify-attestation --type cyclonedx --certificate-identity "$identity_name" --certificate-oidc-issuer "$issuer" --certificate-github-workflow-sha "$GITHUB_SHA" "$subject" > "$evidence/sbom-verified.json"; cosign verify-attestation --type "$scan_type" --certificate-identity "$identity_name" --certificate-oidc-issuer "$issuer" --certificate-github-workflow-sha "$GITHUB_SHA" "$subject" > "$evidence/scan-verified.json"
# Cosign v3 reports the signature Docker reference as the immutable subject,
# including its manifest digest.  Attestation subjects below remain repository-only.
jq -s -e --arg digest "$digest" --arg reference "$subject" 'def a: if length==1 and (.[0]|type)=="array" then .[0] else . end; a|any(.[];.critical.image["docker-manifest-digest"]==$digest and .critical.identity["docker-reference"]==$reference)' "$evidence/signature.json" >/dev/null
jq -s -e --arg name "${subject%@*}" --arg digest "${digest#sha256:}" --arg revision "$GITHUB_SHA" --arg input "$input_sha" --arg run "$GITHUB_RUN_ID" 'def a: if length==1 and (.[0]|type)=="array" then .[0] else . end|map(.payload|@base64d|fromjson); a|any(.[];(.subject|type=="array" and any(.[];.name==$name and .digest.sha256==$digest)) and .predicateType=="https://slsa.dev/provenance/v1" and .predicate.buildDefinition=={buildType:"https://slsa.dev/container-based-build/v1",externalParameters:{signer_probe_input_sha256:$input},resolvedDependencies:[{uri:"git+https://github.com/s1ns3nz0/node-operator",digest:{gitCommit:$revision}}]} and .predicate.runDetails=={builder:{id:"https://github.com/Attestations/GitHubHostedActions@v1"},metadata:{invocationId:$run}})' "$evidence/provenance-verified.json" >/dev/null
expected_sbom="$(jq -s -c -e 'if length==1 and (.[0]|type)=="object" then .[0] else error("sbom") end' "$evidence/sbom.json")"; jq -s -e --arg name "${subject%@*}" --arg digest "${digest#sha256:}" --argjson expected "$expected_sbom" 'def a: if length==1 and (.[0]|type)=="array" then .[0] else . end|map(.payload|@base64d|fromjson); a|any(.[];(.subject|type=="array" and any(.[];.name==$name and .digest.sha256==$digest)) and .predicateType=="https://cyclonedx.org/bom" and .predicate==$expected)' "$evidence/sbom-verified.json" >/dev/null
bash scripts/ci/verify-release-scan-attestation.sh "$evidence/scan-verified.json" "$digest" "$evidence/scan.json"
PYTHONPATH="$root/scripts/release" python3 -B - "$root" "$record" "$GITHUB_SHA" "$input_sha" "$ACCOUNT_ID" "$AWS_REGION" "$DEPLOYMENT_NAME" "$repository" "$subject" "$digest" "$GITHUB_RUN_ID" <<'PY'
import json, sys
from pathlib import Path
from signer_probe_publication_record import create_record
root, output, revision, input_sha, account, region, deployment, repository, image_ref, digest, run = sys.argv[1:]
value = create_record(Path(root), release_revision=revision, build_revision=revision, input_sha256=input_sha,
                      aws_account_id=account, aws_region=region, deployment_name=deployment,
                      repository=repository, image_ref=image_ref, manifest_digest=digest, run_id=run)
import os
payload = (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()
temporary = output + ".tmp." + str(os.getpid())
try:
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        offset = 0
        while offset < len(payload):
            written = os.write(fd, payload[offset:])
            if written <= 0: raise OSError("record write was incomplete")
            offset += written
        os.fsync(fd)
    finally:
        os.close(fd)
    os.link(temporary, output)
    directory = os.open(str(Path(output).parent), os.O_RDONLY)
    try: os.fsync(directory)
    finally: os.close(directory)
finally:
    try: os.unlink(temporary)
    except FileNotFoundError: pass
PY
printf 'private_image=%s\nsource_revision=%s\nrelease_verification=PASS\n' "$subject" "$GITHUB_SHA" >> "${GITHUB_STEP_SUMMARY:-/dev/null}"
