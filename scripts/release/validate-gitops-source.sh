#!/usr/bin/env bash
# Check objective: Validate approved digest input.
# Purpose: Validate one requested GitOps artifact against the reviewed OCI allowlist.
# Inputs: SOURCE, DESTINATION, GITHUB_ENV, and .ci/gitops/approved-oci-artifacts.json.
# Outputs: The approved ECR_TAG appended to GITHUB_ENV.
# Side effects: Writes one workflow environment variable; does not contact a registry.
set -euo pipefail

[[ "$SOURCE" =~ ^[^[:space:]@]+@sha256:[a-f0-9]{64}$ ]] || { echo 'source must be an OCI reference pinned to a 64-character sha256 digest' >&2; exit 1; }
case "$DESTINATION" in argocd|charts|nodes|vault|cert-manager) ;; *) exit 1;; esac
ecr_tag="$(jq -er --arg source "$SOURCE" --arg destination "$DESTINATION" '
  select(.version == 1) | .artifacts[] | select(.source == $source and .destination == $destination) | .ecrTag
' .ci/gitops/approved-oci-artifacts.json)" || {
  echo 'source digest is not in the reviewed GitOps artifact allowlist' >&2
  exit 1
}
[[ "$ecr_tag" =~ ^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$ ]] || { echo 'approved ECR tag is invalid' >&2; exit 1; }
echo "ECR_TAG=$ecr_tag" >> "$GITHUB_ENV"
