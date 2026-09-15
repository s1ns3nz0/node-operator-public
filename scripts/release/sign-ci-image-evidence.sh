#!/usr/bin/env bash
# Sign and verify a just-published immutable CI image before promoting its main tag.
# This helper is intentionally not a claim of real cryptographic proof in local tests.
set -euo pipefail
umask 077

if [ "$#" -ne 5 ]; then
  printf 'usage: %s IMAGE LOCAL_CONFIG_DIGEST SBOM_PATH RECEIPT_PATH NEW_EVIDENCE_DIR\n' "$0" >&2
  exit 64
fi
image="$1"; local_config_digest="$2"; sbom="$3"; receipt="$4"; evidence_dir="$5"
repository="${GITHUB_REPOSITORY:-}"; revision="${GITHUB_SHA:-}"; ref="${GITHUB_REF:-}"; run_id="${GITHUB_RUN_ID:-}"
[[ "$repository" == s1ns3nz0/node-operator && "$ref" == refs/heads/main && "$revision" =~ ^[0-9a-f]{40}$ && "$run_id" =~ ^[0-9]+$ ]] || { printf '%s\n' 'CI image signing is restricted to the node-operator main branch' >&2; exit 65; }
[[ "$local_config_digest" =~ ^sha256:[0-9a-f]{64}$ ]] || { printf '%s\n' 'local config digest is invalid' >&2; exit 65; }
case "$image" in
  ghcr.io/s1ns3nz0/node-operator/security-scanners|ghcr.io/s1ns3nz0/node-operator/terraform-validation|ghcr.io/s1ns3nz0/node-operator/release-build|ghcr.io/s1ns3nz0/node-operator/vault-release-signer|ghcr.io/s1ns3nz0/node-operator/gitops-oci-mirror|ghcr.io/s1ns3nz0/node-operator/argocd-bootstrap|ghcr.io/s1ns3nz0/node-operator/vault-bootstrap) ;;
  *) printf '%s\n' 'image is not an allowed CI image repository' >&2; exit 65 ;;
esac
for required in docker cosign python3; do command -v "$required" >/dev/null || { printf '%s is required\n' "$required" >&2; exit 69; }; done
[ -f "$sbom" ] && [ ! -L "$sbom" ] && [ -f "$receipt" ] && [ ! -L "$receipt" ] || { printf '%s\n' 'SBOM and receipt must be regular files' >&2; exit 65; }
[ ! -e "$evidence_dir" ] && [ ! -L "$evidence_dir" ] || { printf '%s\n' 'evidence output directory must be new' >&2; exit 65; }

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
helper="$root/scripts/ci/ci_image_attestation.py"
scratch="$(mktemp -d "${TMPDIR:-/tmp}/node-operator-ci-image-evidence.XXXXXX")"
trap 'rm -rf "$scratch"' EXIT

docker buildx imagetools inspect --raw "$image:$revision" > "$scratch/manifest.json"
manifest_digest="$(python3 "$helper" manifest "$scratch/manifest.json" "$local_config_digest")"
docker buildx imagetools inspect --raw "$image@$manifest_digest" > "$scratch/pinned-manifest.json"
cmp -s "$scratch/manifest.json" "$scratch/pinned-manifest.json" || { printf '%s\n' 'digest-pinned manifest changed or does not match SHA tag' >&2; exit 65; }
python3 "$helper" local "$sbom" "$receipt" "$revision" "$local_config_digest"

subject="$image@$manifest_digest"
identity='https://github.com/s1ns3nz0/node-operator/.github/workflows/image-publish.yml@refs/heads/main'
issuer='https://token.actions.githubusercontent.com'
receipt_type='https://github.com/s1ns3nz0/node-operator/attestations/image-build-receipt/v1'
cosign sign --yes "$subject"
cosign attest --yes --type cyclonedx --predicate "$sbom" "$subject"
cosign attest --yes --type "$receipt_type" --predicate "$receipt" "$subject"
verify_args=(--output json --certificate-identity "$identity" --certificate-oidc-issuer "$issuer" --certificate-github-workflow-sha "$revision")
cosign verify "${verify_args[@]}" "$subject" > "$scratch/signature-verified.json"
cosign verify-attestation --type cyclonedx "${verify_args[@]}" "$subject" > "$scratch/sbom-attestation-verified.json"
cosign verify-attestation --type "$receipt_type" "${verify_args[@]}" "$subject" > "$scratch/receipt-attestation-verified.json"
python3 "$helper" verify "$scratch/signature-verified.json" "$scratch/sbom-attestation-verified.json" "$scratch/receipt-attestation-verified.json" "$sbom" "$receipt" "$image" "$manifest_digest"
python3 "$helper" copy "$evidence_dir" "$subject" "$scratch/manifest.json" "$sbom" "$receipt" "$scratch/signature-verified.json" "$scratch/sbom-attestation-verified.json" "$scratch/receipt-attestation-verified.json"
