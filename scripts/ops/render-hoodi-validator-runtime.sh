#!/usr/bin/env bash
set -euo pipefail

# Produces a non-secret runtime manifest. Image inputs must be reviewed,
# same-account immutable ECR digests; key material remains solely in Vault.
usage() { printf '%s\n' "Usage: ${0##*/} --validator-set <hoodi-id> --aws-account-id <12-digit-id> [--aws-region <aws-region>] --web3signer-image <private-ecr@sha256> --postgres-image <private-ecr@sha256> --output <absolute-yaml>" >&2; exit 64; }
validator_set=''; aws_account_id=''; aws_region='ap-northeast-2'; web3signer_image=''; postgres_image=''; output=''
deployment_identity=''; release_identity=''
while [ "$#" -gt 0 ]; do
  case "$1" in
    --validator-set) validator_set="${2:-}"; shift 2 ;;
    --aws-account-id) aws_account_id="${2:-}"; shift 2 ;;
    --aws-region) aws_region="${2:-}"; shift 2 ;;
    --web3signer-image) web3signer_image="${2:-}"; shift 2 ;;
    --postgres-image) postgres_image="${2:-}"; shift 2 ;;
    --output) output="${2:-}"; shift 2 ;;
    --deployment-name) deployment_identity="${2:-}"; shift 2 ;;
    --release-revision) release_identity="${2:-}"; shift 2 ;;
    *) usage ;;
  esac
done
case "$validator_set" in hoodi-[a-z0-9][a-z0-9-]*) ;; *) usage ;; esac
case "$aws_account_id" in [0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]) ;; *) usage ;; esac
[[ "$aws_region" =~ ^[a-z]{2}-[a-z0-9-]+-[0-9]+$ ]] || usage
case "$output" in /*) ;; *) usage ;; esac
# Legacy direct rendering has no invented release identity. The installer
# supplies both values from its selected deployment and verified manifest.
identity_sed=(-e '/REPLACE_WITH_DEPLOYMENT_IDENTITY/d' -e '/REPLACE_WITH_RELEASE_IDENTITY/d')
if [ -n "$deployment_identity$release_identity" ]; then
  [[ "$deployment_identity" =~ ^[a-z][a-z0-9-]{1,38}[a-z0-9]$ ]] && [[ "$release_identity" =~ ^[0-9a-f]{40}$ ]] || usage
  identity_sed=(-e "s|REPLACE_WITH_DEPLOYMENT_IDENTITY|${deployment_identity}|g" -e "s|REPLACE_WITH_RELEASE_IDENTITY|${release_identity}|g")
fi
for image in "$web3signer_image" "$postgres_image"; do
  printf '%s\n' "$image" | grep -Eq "^${aws_account_id}\\.dkr\\.ecr\\.${aws_region}\\.amazonaws\\.com/[a-z0-9][a-z0-9._/-]*@sha256:[a-f0-9]{64}$" || { printf '%s\n' 'image must be an approved same-account private ECR digest in aws_region' >&2; exit 65; }
done
for command in sed mkdir mktemp mv grep dirname unlink; do command -v "$command" >/dev/null 2>&1 || { printf 'missing command: %s\n' "$command" >&2; exit 69; }; done

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
template="$root/deploy/validator/runtime-template.yaml"
[ -r "$template" ] || { printf '%s\n' 'runtime template missing' >&2; exit 66; }
mkdir -p "$(dirname "$output")"
temporary="$(mktemp "${output}.tmp.XXXXXX")"
cleanup() { set +e; [ -z "${temporary:-}" ] || [ ! -e "$temporary" ] || unlink "$temporary" 2>/dev/null || true; }
trap cleanup EXIT INT TERM
sed "${identity_sed[@]}" -e "s|REPLACE_WITH_VALIDATOR_SET|${validator_set}|g" -e "s|REPLACE_WITH_WEB3SIGNER_IMAGE|${web3signer_image}|g" -e "s|REPLACE_WITH_POSTGRES_IMAGE|${postgres_image}|g" "$template" > "$temporary"
if grep -q 'REPLACE_WITH_' "$temporary"; then printf '%s\n' 'unresolved runtime placeholder' >&2; exit 65; fi
mv "$temporary" "$output"; temporary=''
printf 'PASS: non-secret Hoodi signer runtime manifest rendered to %s. Apply only after all runtime-contract gates pass.\n' "$output"
