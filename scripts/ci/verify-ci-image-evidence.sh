#!/usr/bin/env bash
# Verify producer-signed CI image evidence before a caller pulls or runs an image.
set -euo pipefail
umask 077

if [ "$#" -ne 4 ]; then
  printf 'usage: %s IMAGE@sha256:DIGEST APPROVED_SOURCE_SHA SBOM_PATH RECEIPT_PATH\n' "$0" >&2
  exit 64
fi
subject="$1"; revision="$2"; sbom="$3"; receipt="$4"
[[ "$subject" =~ ^(.+)@sha256:([0-9a-f]{64})$ && "$revision" =~ ^[0-9a-f]{40}$ ]] || { printf '%s\n' 'image must be a digest-pinned reference and source SHA must be approved-format' >&2; exit 65; }
image="${subject%@sha256:*}"; digest="sha256:${subject##*@sha256:}"
case "$image" in
  ghcr.io/s1ns3nz0/node-operator/security-scanners|ghcr.io/s1ns3nz0/node-operator/terraform-validation|ghcr.io/s1ns3nz0/node-operator/release-build|ghcr.io/s1ns3nz0/node-operator/vault-release-signer|ghcr.io/s1ns3nz0/node-operator/gitops-oci-mirror|ghcr.io/s1ns3nz0/node-operator/argocd-bootstrap|ghcr.io/s1ns3nz0/node-operator/vault-bootstrap) ;;
  *) printf '%s\n' 'image is not an allowed CI image repository' >&2; exit 65 ;;
esac
command -v cosign >/dev/null || { printf '%s\n' 'cosign is required' >&2; exit 69; }
command -v python3 >/dev/null || { printf '%s\n' 'python3 is required' >&2; exit 69; }
# Cosign's version output contains several metadata fields. Only its exact
# GitVersion line is the tool version; incidental dependency text is not trust.
cosign version 2>&1 | grep -Eq '^[[:space:]]*GitVersion:[[:space:]]*v?3\.1\.2[[:space:]]*$' || { printf '%s\n' 'installed cosign must be pinned version 3.1.2' >&2; exit 69; }
[ -f "$sbom" ] && [ ! -L "$sbom" ] && [ -f "$receipt" ] && [ ! -L "$receipt" ] || { printf '%s\n' 'SBOM and receipt must be regular files' >&2; exit 65; }

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
helper="$root/scripts/ci/ci_image_attestation.py"
scratch="$(mktemp -d "${TMPDIR:-/tmp}/node-operator-ci-image-consumer.XXXXXX")"
trap 'rm -rf "$scratch"' EXIT
identity='https://github.com/s1ns3nz0/node-operator/.github/workflows/image-publish.yml@refs/heads/main'
issuer='https://token.actions.githubusercontent.com'
receipt_type='https://github.com/s1ns3nz0/node-operator/attestations/image-build-receipt/v1'
verify_args=(--output json --certificate-identity "$identity" --certificate-oidc-issuer "$issuer" --certificate-github-workflow-sha "$revision")
cosign verify "${verify_args[@]}" "$subject" > "$scratch/signature-verified.json"
cosign verify-attestation --type cyclonedx "${verify_args[@]}" "$subject" > "$scratch/sbom-attestation-verified.json"
cosign verify-attestation --type "$receipt_type" "${verify_args[@]}" "$subject" > "$scratch/receipt-attestation-verified.json"
python3 "$helper" consumer "$scratch/signature-verified.json" "$scratch/sbom-attestation-verified.json" "$scratch/receipt-attestation-verified.json" "$sbom" "$receipt" "$image" "$digest" "$revision"
printf 'PASS verified producer CI image evidence for %s; this does not authorize execution.\n' "$subject"
