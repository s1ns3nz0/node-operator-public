#!/usr/bin/env bash
# One-time, explicitly authorized publication of PR144's exact manual candidates.
set -euo pipefail
set +x
umask 077
test "$#" = 1 && test "$1" = --publish-reviewed-grpc-candidates || {
  echo 'Requires explicit task authorization: --publish-reviewed-grpc-candidates' >&2; exit 64;
}
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
build=/private/tmp/hoodi-vault-grpc-build.WSyrpd
registry=123456789012.dkr.ecr.ap-northeast-2.amazonaws.com
tag=manual-grpc-1.83.2-9cd8d84fe177
toolbox=ghcr.io/s1ns3nz0/node-operator/terraform-validation@sha256:1f2ac75ec09b43b4a79eaaae94eca8f8f1655315a5aa81e7c80d3a8a14ac189a
evidence="$(mktemp -d /private/tmp/hoodi-vault-grpc-publication.XXXXXX)"
auth="$(mktemp -d /private/tmp/hoodi-vault-grpc-publication-auth.XXXXXX)"
cleanup() { test ! -f "$auth/config.json" || unlink "$auth/config.json"; rmdir "$auth"; }
trap cleanup EXIT
printf 'Publication evidence: %s\n' "$evidence"
test "$(aws sts get-caller-identity --query Arn --output text)" = arn:aws:iam::123456789012:user/jsyang
git -C "$root" merge-base --is-ancestor 9cd8d84fe177235db33d6761b3ac570d7ab846d7 HEAD
python3 "$root/scripts/ops/prepare-vault-runtime-publication.py" "$build" > "$evidence/preflight.json"
# Verify both destinations before any publication or login.
for component in server agent; do
  repository="node-operator-baseline-vault-runtime-$component"
  digest="$(jq -er --arg c "$component" '.targets[]|select(.component==$c)|.local_image_id' "$evidence/preflight.json")"
  docker image inspect "$digest" | jq -e --arg d "$digest" '.[0].Descriptor.digest==$d and .[0].Descriptor.mediaType=="application/vnd.oci.image.index.v1+json"' >/dev/null
  aws ecr describe-repositories --region ap-northeast-2 --repository-names "$repository" | jq -e '.repositories|length==1 and all(.[];.imageTagMutability=="IMMUTABLE" and .imageScanningConfiguration.scanOnPush==true and .encryptionConfiguration.encryptionType=="KMS" and .encryptionConfiguration.kmsKey=="arn:aws:kms:ap-northeast-2:123456789012:key/23253df4-8b2a-431c-990a-54c4913fc8c3")' >/dev/null
  existing="$(aws ecr list-images --region ap-northeast-2 --repository-name "$repository" --filter tagStatus=TAGGED --query "imageIds[?imageTag=='$tag'].imageDigest" --output text)"
  test -z "$existing" || test "$existing" = "$digest"
done
# Avoid Docker Desktop implicitly selecting macOS keychain helpers: the Linux
# scanner needs a portable registry-only credential. Never put it in argv/logs.
{ printf 'AWS:'; aws ecr get-login-password --region ap-northeast-2 | tr -d '\n'; } \
  | base64 | tr -d '\n' \
  | jq -Rs --arg registry "$registry" '{auths:{($registry):{auth:.}}}' > "$auth/config.json"
for component in server agent; do
  repository="node-operator-baseline-vault-runtime-$component"
  digest="$(jq -er --arg c "$component" '.targets[]|select(.component==$c)|.local_image_id' "$evidence/preflight.json")"
  subject="$registry/$repository@$digest"
  out="$evidence/$component"; mkdir -p "$out"
  existing="$(aws ecr list-images --region ap-northeast-2 --repository-name "$repository" --filter tagStatus=TAGGED --query "imageIds[?imageTag=='$tag'].imageDigest" --output text)"
  if test -n "$existing"; then
    test "$existing" = "$digest"
  else
    docker --config "$auth" tag "$digest" "$registry/$repository:$tag"
    docker --config "$auth" push "$registry/$repository:$tag" > "$out/push.log" 2>&1
  fi
  test "$(aws ecr describe-images --region ap-northeast-2 --repository-name "$repository" --image-ids "imageTag=$tag" --query 'imageDetails[0].imageDigest' --output text)" = "$digest"
  docker --config "$auth" pull --platform linux/amd64 "$subject" > "$out/pull.log" 2>&1
  docker image inspect "$subject" | jq --arg subject "$subject" '.[0]|{subject:$subject,Id,RepoDigests,Os,Architecture,user:.Config.User,entrypoint:.Config.Entrypoint}' > "$out/runtime-identity.json"
  jq -e --arg s "$subject" '.RepoDigests|index($s)!=null' "$out/runtime-identity.json" >/dev/null
  binary=/bin/vault; test "$component" = server || binary=/usr/local/bin/vault
  run=(docker run --rm --pull never --platform linux/amd64 --network none --read-only --cap-drop ALL --security-opt no-new-privileges --pids-limit 64 --memory 512m --cpus 1 --entrypoint /bin/sh "$subject")
  # Only public binary/build metadata, no credentials/config passed to candidate.
  "${run[@]}" -ec 'sha256sum "$1"' metadata "$binary" > "$out/binary.sha256"
  expected="$(jq -er --arg c "$component" '.targets[]|select(.component==$c)|.binary_sha256' "$evidence/preflight.json")"
  test "$(awk '{print $1}' "$out/binary.sha256")" = "$expected"
  if test "$component" = server; then
    "${run[@]}" -ec 'cat /usr/share/vault/dependencies.txt' > "$out/dependencies.txt"
  else
    cp "$build/agent-dependency-evidence/dependencies.txt" "$out/dependencies.txt"
  fi
  expected="$(jq -er --arg c "$component" '.[$c].dependency_sha256' "$root/plans/2026-09-09-vault-grpc-security-patch/evidence.json")"
  test "$(shasum -a 256 "$out/dependencies.txt" | awk '{print $1}')" = "$expected"
  # Pinned trusted scanner gets registry-only auth, never AWS or host Docker socket.
  docker run --rm --platform linux/amd64 --entrypoint bash \
    -v "$auth:/auth:ro" -v "$build/tools:/tools:ro" -v "$out:/out" -v "$root/.ci/vault-server-hardened/grype.yaml:/grype.yaml:ro" \
    -e DOCKER_CONFIG=/auth -e SUBJECT="$subject" -e DIGEST="$digest" -e REPOSITORY="$repository" \
    -e GRYPE_CHECK_FOR_APP_UPDATE=false -e SYFT_CHECK_FOR_APP_UPDATE=false \
    "$toolbox" -euo pipefail -c '
      /tools/syft scan "registry:$SUBJECT" --source-name "$REPOSITORY" --source-version "$DIGEST" --output cyclonedx-json=/out/sbom.json
      /tools/grype sbom:/out/sbom.json --config /grype.yaml --output json --file /out/grype.json
    '
  python3 "$root/scripts/ci/summarize-vault-runtime-scan.py" "$out/sbom.json" "$out/grype.json" "$digest" > "$out/scan-summary.json"
  jq -e '.scanner.version=="0.118.0" and .findings.critical==0 and .findings.high==0' "$out/scan-summary.json" >/dev/null
  jq -e '[.components[]|select(.name=="google.golang.org/grpc")]|length==1 and .[0].version=="v1.83.2"' "$out/sbom.json" >/dev/null
  curl --fail --silent --show-error --connect-timeout 10 --max-time 30 --retry 2 --output "$out/advisory-current.json" https://vuln.go.dev/ID/GO-2026-5932.json
  python3 "$root/scripts/ci/assess-vault-runtime-applicability.py" "$component" "$out" > "$out/applicability-decision.json"
  jq -e '.status=="passed" and .deployment_authorized==false' "$out/applicability-decision.json" >/dev/null
  jq -n --arg subject "$subject" '{subject:$subject,published:true,registry_digest_verified:true,critical_high_zero:true,applicability_passed:true,ci_build_attested:false,deployed:false}' > "$out/result.json"
  printf 'PASS %s candidate publication, registry C/H=0 and separate applicability assessment; release gates remain.\n' "$component"
done
