#!/usr/bin/env bash
# Check objective: Collect commit-bound security evidence using the image's trusted collector before exposing reports to the artifact uploader.
set -euo pipefail

if [ "$#" -ne 3 ]; then
  printf 'usage: %s EVIDENCE_DIRECTORY COMMIT_SHA BASE_SHA\n' "$0" >&2
  exit 64
fi

evidence_directory="$1"
commit_sha="$2"
base_sha="$3"
scanner_script_directory="${SCANNER_SCRIPT_DIRECTORY:-/opt/node-operator-scanner/scripts}"

[ -x "$scanner_script_directory/collect-security-evidence.sh" ] || {
  printf 'trusted scanner collector is unavailable in the image\n' >&2
  exit 1
}

mkdir -p "$evidence_directory"
git config --global --add safe.directory /workspace
"$scanner_script_directory/collect-security-evidence.sh" \
  "$evidence_directory" "$commit_sha" /workspace "$base_sha"

# The collector writes root-owned files with umask 077. The mounted evidence
# directory is the sole declared output, so make it readable only after a
# successful collection for the non-sensitive artifact uploader.
chmod -R a+rX "$evidence_directory"
