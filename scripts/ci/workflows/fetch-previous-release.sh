#!/usr/bin/env bash
# Check objective: Fetch previous approved release when available.
# Purpose: Obtain comparison inputs from the latest non-draft, non-prerelease GitHub release.
# Inputs: GH_TOKEN, GITHUB_REPOSITORY, and RUNNER_TEMP.
# Outputs: Previous release files plus available=true|false in GITHUB_OUTPUT.
# Side effects: Read-only GitHub release list/download calls and local temporary writes.
set -euo pipefail

mkdir -p "$RUNNER_TEMP/previous"
tag="$(gh release list --limit 1 --json tagName,isDraft,isPrerelease --jq '.[] | select(.isDraft == false and .isPrerelease == false) | .tagName' | head -n 1)"
if [ -z "$tag" ]; then
  echo "available=false" >> "$GITHUB_OUTPUT"
  exit 0
fi
gh release download "$tag" --repo "$GITHUB_REPOSITORY" \
  --pattern 'manifest.json' --pattern 'sbom.cyclonedx.json' --pattern 'provenance-input.json' \
  --dir "$RUNNER_TEMP/previous"
test -f "$RUNNER_TEMP/previous/manifest.json"
test -f "$RUNNER_TEMP/previous/sbom.cyclonedx.json"
test -f "$RUNNER_TEMP/previous/provenance-input.json"
echo "available=true" >> "$GITHUB_OUTPUT"
