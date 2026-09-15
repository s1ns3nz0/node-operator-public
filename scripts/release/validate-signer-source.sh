#!/usr/bin/env bash
# Check objective: Validate approved signer source.
# Purpose: Validate the release-signer source reference is the approved pinned GHCR repository.
# Inputs: SOURCE and GITHUB_ENV.
# Outputs: SOURCE_DIGEST appended to GITHUB_ENV.
# Side effects: Writes one workflow environment variable; does not contact a registry.
set -euo pipefail

[[ "$SOURCE" =~ ^ghcr\.io/s1ns3nz0/node-operator/vault-release-signer@sha256:[a-f0-9]{64}$ ]] || {
  echo 'source must be the approved Vault signer GHCR repository pinned by a sha256 digest' >&2
  exit 1
}
echo "SOURCE_DIGEST=${SOURCE##*@}" >> "$GITHUB_ENV"
