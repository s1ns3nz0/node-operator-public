#!/usr/bin/env bash
set -euo pipefail

usage() { printf '%s\n' "Usage: ${0##*/} --validator-set <hoodi-id> --validator-public-key <0x-key> --aws-account-id <12-digit-id> [--aws-region <aws-region>] --prysm-validator-image <private-ecr@sha256> --signing-fence-image <private-ecr@sha256> --kubernetes-api-cidr <ipv4/32> --output <absolute-yaml>" >&2; exit 64; }
validator_set=''; public_key=''; aws_account_id=''; aws_region='ap-northeast-2'; image=''; fence_image=''; kubernetes_api_cidr=''; output=''
deployment_identity=''; release_identity=''
while [ "$#" -gt 0 ]; do
  case "$1" in
    --validator-set) validator_set="${2:-}"; shift 2 ;;
    --validator-public-key) public_key="${2:-}"; shift 2 ;;
    --aws-account-id) aws_account_id="${2:-}"; shift 2 ;;
    --aws-region) aws_region="${2:-}"; shift 2 ;;
    --prysm-validator-image) image="${2:-}"; shift 2 ;;
    --signing-fence-image) fence_image="${2:-}"; shift 2 ;;
    --kubernetes-api-cidr) kubernetes_api_cidr="${2:-}"; shift 2 ;;
    --output) output="${2:-}"; shift 2 ;;
    --deployment-name) deployment_identity="${2:-}"; shift 2 ;;
    --release-revision) release_identity="${2:-}"; shift 2 ;;
    *) usage ;;
  esac
done
case "$validator_set" in hoodi-[a-z0-9][a-z0-9-]*) ;; *) usage ;; esac
case "$public_key" in 0x????????????????????????????????????????????????????????????????????????????????????????????????) ;; *) usage ;; esac
case "$aws_account_id" in [0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]) ;; *) usage ;; esac
[[ "$aws_region" =~ ^[a-z]{2}-[a-z0-9-]+-[0-9]+$ ]] || usage
case "$output" in /*) ;; *) usage ;; esac
identity_sed=(-e '/REPLACE_WITH_DEPLOYMENT_IDENTITY/d' -e '/REPLACE_WITH_RELEASE_IDENTITY/d')
if [ -n "$deployment_identity$release_identity" ]; then
  [[ "$deployment_identity" =~ ^[a-z][a-z0-9-]{1,38}[a-z0-9]$ ]] && [[ "$release_identity" =~ ^[0-9a-f]{40}$ ]] || usage
  identity_sed=(-e "s|REPLACE_WITH_DEPLOYMENT_IDENTITY|${deployment_identity}|g" -e "s|REPLACE_WITH_RELEASE_IDENTITY|${release_identity}|g")
fi
printf '%s\n' "$image" | grep -Eq "^${aws_account_id}\\.dkr\\.ecr\\.${aws_region}\\.amazonaws\\.com/[a-z0-9][a-z0-9._/-]*@sha256:[a-f0-9]{64}$" || { printf '%s\n' 'image must be an approved same-account private ECR digest in aws_region' >&2; exit 65; }
printf '%s\n' "$fence_image" | grep -Eq "^${aws_account_id}\\.dkr\\.ecr\\.${aws_region}\\.amazonaws\\.com/[a-z0-9][a-z0-9-]*-baseline-validator-fence@sha256:[a-f0-9]{64}$" || { printf '%s\n' 'fence image must be the protected type-separated private ECR digest in aws_region' >&2; exit 65; }
selected_prysm_repository="${image#*/}"; selected_prysm_repository="${selected_prysm_repository%@*}"
if [[ "$selected_prysm_repository" =~ ^([a-z0-9][a-z0-9-]*)-baseline-validator-prysm$ ]]; then
  selected_deployment="${BASH_REMATCH[1]}"
else
  printf '%s\n' 'Prysm image must use a protected deployment baseline repository' >&2; exit 65
fi
selected_fence_repository="${fence_image#*/}"; selected_fence_repository="${selected_fence_repository%@*}"
[ "$selected_fence_repository" = "${selected_deployment}-baseline-validator-fence" ] || { printf '%s\n' 'Prysm and fence images must use the same protected deployment prefix' >&2; exit 65; }
printf '%s\n' "$kubernetes_api_cidr" | grep -Eq '^([0-9]{1,3}\.){3}[0-9]{1,3}/32$' || { printf '%s\n' 'Kubernetes API CIDR must be one explicit IPv4 /32' >&2; exit 65; }
for command in sed mkdir mktemp mv grep dirname unlink jq; do command -v "$command" >/dev/null 2>&1 || { printf 'missing command: %s\n' "$command" >&2; exit 69; }; done
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"; template="$root/deploy/validator/client-template.yaml"; fence_template="$root/deploy/validator/client-lease-fence-template.yaml"
bundle_root="$(cd "$root/.." && pwd -P)"
prysm_auth="$root/release/prysm-publication-authorization.json"; fence_auth="$root/release/fence-publication-authorization.json"
if [ -e "$prysm_auth" ] || [ -L "$prysm_auth" ] || [ -e "$fence_auth" ] || [ -L "$fence_auth" ] || [ -e "$bundle_root/rendered/prysm-mtls-publication-record.json" ] || [ -L "$bundle_root/rendered/prysm-mtls-publication-record.json" ] || [ -e "$bundle_root/rendered/fence-release-verification.json" ] || [ -L "$bundle_root/rendered/fence-release-verification.json" ]; then
  expected="$(PYTHONPATH="$root/scripts/release" python3 -B - "$bundle_root" <<'PY'
import json
from pathlib import Path
import sys
from prysm_release_authorization import validate_release_authorization as prysm
from fence_release_authorization import validate_release_authorization as fence
b=Path(sys.argv[1])
release = json.loads((b/'bundle-manifest.json').read_text())['source_revision']
p=prysm(b, release, 'stage')
f=fence(b, release, 'stage')
pd=p['record']['target']['manifest_digest']; fd=f['record']['artifact_digest']
print(pd)
print(fd)
PY
)" || { printf '%s\n' 'release authorization is invalid or orphaned' >&2; exit 65; }
  authorized_prysm_digest="$(printf '%s\n' "$expected" | sed -n '1p')"
  authorized_fence_digest="$(printf '%s\n' "$expected" | sed -n '2p')"
  expected_prysm="${aws_account_id}.dkr.ecr.${aws_region}.amazonaws.com/${selected_prysm_repository}@${authorized_prysm_digest}"
  expected_fence="${aws_account_id}.dkr.ecr.${aws_region}.amazonaws.com/${selected_fence_repository}@${authorized_fence_digest}"
  [ "$image" = "$expected_prysm" ] && [ "$fence_image" = "$expected_fence" ] || { printf '%s\n' 'selected images differ from release-authorized protected destinations' >&2; exit 65; }
else
printf '%s\n' "$image" | grep -Eq "^${aws_account_id}\\.dkr\\.ecr\\.${aws_region}\\.amazonaws\\.com/[a-z0-9][a-z0-9-]*-baseline-validator-prysm@sha256:[a-f0-9]{64}$" || { printf '%s\n' 'Prysm image must use a protected deployment baseline repository' >&2; exit 65; }
jq -e --arg image "$image" --arg account "$aws_account_id" --arg region "$aws_region" '
  ($image | split("@")[1]) as $digest |
  .schema_version == 2 and any(.images[];
    (.private_image | split("@")[1]) == $digest and
    ($image | startswith($account + ".dkr.ecr." + $region + ".amazonaws.com/")) and
    .stage_approved == true and (.release_channel == "upstream-mirror" or .release_channel == "manual-native-mtls"))
' "$root/.ci/validator/approved-client-images.json" >/dev/null || { printf '%s\n' 'private Prysm digest is not stage-approved for this release' >&2; exit 65; }
fi
mkdir -p "$(dirname "$output")"; temporary="$(mktemp "${output}.tmp.XXXXXX")"
cleanup() { set +e; [ -z "${temporary:-}" ] || [ ! -e "$temporary" ] || unlink "$temporary" 2>/dev/null || true; }; trap cleanup EXIT INT TERM
sed "${identity_sed[@]}" -e "s|REPLACE_WITH_VALIDATOR_SET|${validator_set}|g" -e "s|REPLACE_WITH_SIGNING_FENCE_IMAGE|${fence_image}|g" -e "s|REPLACE_WITH_KUBERNETES_API_CIDR|${kubernetes_api_cidr}|g" "$fence_template" > "$temporary"
printf '%s\n' '---' >> "$temporary"
sed "${identity_sed[@]}" -e "s|REPLACE_WITH_VALIDATOR_SET|${validator_set}|g" -e "s|REPLACE_WITH_VALIDATOR_PUBLIC_KEY|${public_key}|g" -e "s|REPLACE_WITH_PRYSM_VALIDATOR_IMAGE|${image}|g" "$template" >> "$temporary"
grep -q 'REPLACE_WITH_' "$temporary" && { printf '%s\n' 'unresolved client placeholder' >&2; exit 65; }
mv "$temporary" "$output"; temporary=''
printf 'PASS: zero-replica validator client manifest rendered to %s.\n' "$output"
