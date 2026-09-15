#!/usr/bin/env bash
# Objective: Inventory the exact built Docker archive, not its Dockerfile or a mutable registry tag.
# Outputs: CycloneDX SBOM and a local hash-bound receipt. This is not a signature or vulnerability verdict.
set -euo pipefail
umask 077
if [ "$#" -ne 5 ]; then
  printf 'usage: %s ARCHIVE NEW_OUTPUT_DIR SUBJECT REVISION IMAGE_CONFIG_DIGEST\n' "$0" >&2
  exit 64
fi
archive="$1"; output="$2"; subject="$3"; revision="$4"; config_digest="$5"
[[ "$revision" =~ ^[0-9a-f]{40}$ ]] || exit 64
[[ "$config_digest" =~ ^sha256:[0-9a-f]{64}$ ]] || exit 64
[[ "$subject" =~ ^[a-z0-9][a-z0-9-]{0,62}$ ]] || exit 64
[ -f "$archive" ] && [ ! -L "$archive" ] || exit 65
[ ! -e "$output" ] && [ ! -L "$output" ] || exit 65
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
archive="$(cd "$(dirname "$archive")" && pwd -P)/$(basename "$archive")"
mkdir -m 700 "$output"
output="$(cd "$output" && pwd -P)"
archive_digest="sha256:$(shasum -a 256 "$archive" | awk '{print $1}')"
# Reuse the release pipeline's existing immutable Syft toolchain. No Docker
# socket, source tree, AWS/GitHub credentials or external network enter the scan.
tool_image='ghcr.io/s1ns3nz0/node-operator/release-build@sha256:f6b2550a3bf8a5b2e8bbdbb301120136d01bc38963d1a70d0d7ff3008acb70be'
docker pull "$tool_image"
docker run --rm --network none --read-only --cap-drop ALL \
  --security-opt no-new-privileges --user "$(id -u):$(id -g)" --tmpfs /tmp \
  --mount "type=bind,src=$archive,dst=/input/image.tar,readonly" \
  --mount "type=bind,src=$output,dst=/output" \
  --env SYFT_CHECK_FOR_APP_UPDATE=false --entrypoint syft "$tool_image" \
  scan docker-archive:/input/image.tar --source-name "$subject" \
  --source-version "$archive_digest" --output cyclonedx-json=/output/sbom.cyclonedx.json --quiet
# Syft 1.37.0 inventories some final regular files without a component hash
# (including zero-byte keyring placeholders). Resolve only those paths from
# the same Docker archive; reject anything not a final unambiguous zero-byte regular file.
python3 "$script_dir/image_sbom_evidence.py" hydrate \
  --archive "$archive" --sbom "$output/sbom.cyclonedx.json"
python3 "$script_dir/image_sbom_evidence.py" create \
  --archive "$archive" --sbom "$output/sbom.cyclonedx.json" \
  --subject "$subject" --revision "$revision" --image-config-digest "$config_digest" \
  --output "$output/receipt.json"
