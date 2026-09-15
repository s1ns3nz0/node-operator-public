#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
image="${1:?Usage: verify-prysm-beacon-image.sh sha256:LOCAL_IMAGE_ID SCAN_JSON}"
scan="${2:?Specify a new scan JSON output path}"
test "$#" = 2
test ! -e "$scan" || { echo 'Refusing to overwrite scan evidence' >&2; exit 64; }
for tool in docker grype jq; do command -v "$tool" >/dev/null; done
[[ "$image" =~ ^sha256:[a-f0-9]{64}$ ]] || { echo 'An immutable local image ID is required, not a tag' >&2; exit 64; }
image_id="$(docker image inspect --format '{{.Id}}' "$image")"
[[ "$image_id" =~ ^sha256:[a-f0-9]{64}$ ]] || exit 65
test "$image_id" = "$image" || { echo 'Resolved image differs from expected identity' >&2; exit 65; }
run=(docker run --rm --platform linux/amd64 --network none --read-only --cap-drop ALL --security-opt no-new-privileges)
# Evaluate identity and checks inside the isolated container, not the host.
# shellcheck disable=SC2016
"${run[@]}" --entrypoint /bin/sh "$image_id" -ec '
  test "$(id -u)" = 1000
  test -s /usr/share/beacon-chain-dependencies.txt
  test -s /usr/share/beacon-chain-buildinfo.txt
  ! grep -Eq "^golang.org/x/crypto/openpgp(/|$)" /usr/share/beacon-chain-dependencies.txt
  grep -Fq "github.com/OffchainLabs/prysm/v7/cmd/beacon-chain" /usr/share/beacon-chain-buildinfo.txt
  /beacon-chain --version | grep -F "v7.1.8"
  /beacon-chain --help >/dev/null
'
GRYPE_CHECK_FOR_APP_UPDATE=false grype --config "$root/.ci/prysm-beacon-runtime/grype.yaml" "docker:$image_id" --platform linux/amd64 -o json > "$scan"
jq -e --arg image "$image_id" '.source.target.userInput==$image
  and .descriptor.name=="grype" and .descriptor.db.status.valid==true
  and .descriptor.configuration["only-fixed"]==false
  and .descriptor.configuration["only-notfixed"]==false
  and .descriptor.configuration["show-suppressed"]==true
  and .descriptor.configuration.exclude==[]
  and (.matches|type)=="array"
  and (.ignoredMatches|length)==0
  and all((.matches + [.ignoredMatches[]?.match])[];
    (.vulnerability.severity|type)=="string" and
    (.vulnerability.severity|ascii_downcase|IN("critical","high")|not))' "$scan" >/dev/null
printf 'PASS: frozen Beacon image runtime/dependency checks and Critical/High=0.\nImage: %s\nScan: %s\nUnknown findings still require separate applicability review.\n' "$image_id" "$scan"
