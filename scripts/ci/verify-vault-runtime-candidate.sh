#!/usr/bin/env bash
# Check objective: Verify Vault runtime candidate evidence matches the approved component digest and allowlist.
set -euo pipefail
test "$#" = 2 || { echo 'usage: verify-vault-runtime-candidate.sh COMPONENT EVIDENCE_DIRECTORY' >&2; exit 64; }
component="$1"; evidence="$2"
case "$component" in server|agent|injector) ;; *) echo 'unreviewed component' >&2; exit 64;; esac
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
allowlist="$root/.ci/vault-runtime-candidates.json"
registry="$(jq -er .registry "$allowlist")"
repository="$(jq -er --arg c "$component" '.candidates[$c].repository' "$allowlist")"
digest="$(jq -er --arg c "$component" '.candidates[$c].digest' "$allowlist")"
entrypoint="$(jq -er --arg c "$component" '.candidates[$c].entrypoint' "$allowlist")"
version_argument="$(jq -er --arg c "$component" '.candidates[$c].version_argument' "$allowlist")"
version_pattern="$(jq -er --arg c "$component" '.candidates[$c].version_pattern' "$allowlist")"
expected_user="$(jq -er --arg c "$component" '.candidates[$c].user' "$allowlist")"
[[ "$digest" =~ ^sha256:[a-f0-9]{64}$ ]]
test "$repository" = "node-operator-baseline-vault-runtime-$component"
test "$registry" = '123456789012.dkr.ecr.ap-northeast-2.amazonaws.com'
subject="$registry/$repository@$digest"
mkdir -p "$evidence"
test "$(aws ecr describe-images --region ap-northeast-2 --repository-name "$repository" --image-ids "imageDigest=$digest" --query 'imageDetails[0].imageDigest' --output text)" = "$digest"
unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AWS_PROFILE AWS_DEFAULT_PROFILE
unset ACTIONS_ID_TOKEN_REQUEST_TOKEN ACTIONS_ID_TOKEN_REQUEST_URL
docker pull --platform linux/amd64 "$subject"
docker image inspect "$subject" | jq --arg subject "$subject" \
  '.[0] | {subject:$subject,Id,RepoDigests,Os,Architecture,user:.Config.User,entrypoint:.Config.Entrypoint}' > "$evidence/runtime-identity.json"
jq -e --arg subject "$subject" --arg user "$expected_user" --arg entrypoint "$entrypoint" \
  '.Os == "linux" and .Architecture == "amd64" and .user == $user and (.RepoDigests | index($subject) != null) and .entrypoint == [$entrypoint]' "$evidence/runtime-identity.json" >/dev/null
# No live config, mounts, AWS environment or credentials are passed to the image.
timeout 60 docker run --rm --platform linux/amd64 --network none --read-only \
  --cap-drop ALL --security-opt no-new-privileges --pids-limit 64 --memory 512m --cpus 1 \
  --entrypoint "$entrypoint" "$subject" "$version_argument" > "$evidence/version.txt" 2>&1
grep -Fq "$version_pattern" "$evidence/version.txt"
SYFT_CHECK_FOR_APP_UPDATE=false syft scan "registry:$subject" --source-name "$repository" \
  --source-version "$digest" --output "cyclonedx-json=$evidence/sbom.json"
GRYPE_CHECK_FOR_APP_UPDATE=false grype "sbom:$evidence/sbom.json" \
  --config "$root/.ci/vault-server-hardened/grype.yaml" --output json --file "$evidence/grype.json"
python3 "$root/scripts/ci/summarize-vault-runtime-scan.py" \
  "$evidence/sbom.json" "$evidence/grype.json" "$digest" > "$evidence/scan-summary.json"
# Preserve the raw blocked summary. A separate, expiring exact-candidate
# assessment may establish package non-applicability, never deployment approval.
bash "$root/scripts/ci/collect-vault-runtime-applicability.sh" "$component" "$subject" "$evidence"
python3 "$root/scripts/ci/assess-vault-runtime-applicability.py" "$component" "$evidence" > "$evidence/applicability-decision.json"
jq -e '.status == "passed"' "$evidence/applicability-decision.json" >/dev/null
printf 'PASS: frozen %s scan/applicability verification; build provenance and deployment still require separate gates.\n' "$component"
