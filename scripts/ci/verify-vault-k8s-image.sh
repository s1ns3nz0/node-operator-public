#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
image="${1:?Usage: verify-vault-k8s-image.sh sha256:LOCAL_IMAGE_ID NEW_SCAN_JSON}"
scan="${2:?Specify a new scan JSON path}"
test "$#" = 2
test ! -e "$scan" || { echo 'Refusing to overwrite scan evidence' >&2; exit 64; }
[[ "$image" =~ ^sha256:[a-f0-9]{64}$ ]] || exit 64
for tool in docker grype jq; do command -v "$tool" >/dev/null; done
test "$(docker image inspect --format '{{.Id}}' "$image")" = "$image"
docker image inspect "$image" | jq -e '.[0] | .Architecture=="amd64" and .Os=="linux" and .Config.User=="1000:1000" and .Config.Entrypoint==["/bin/vault-k8s"]' >/dev/null
run=(docker run --rm --platform linux/amd64 --network none --read-only --cap-drop ALL --security-opt no-new-privileges)
"${run[@]}" "$image" version | grep -F 'v1.7.6'
"${run[@]}" "$image" agent-inject -help >/dev/null 2>&1
# The identity and ownership checks execute inside the isolated container.
# shellcheck disable=SC2016
"${run[@]}" --entrypoint /bin/sh "$image" -ec '
 test "$(id -u)" = 1000
 test ! -w /bin/vault-k8s
 test -s /usr/share/vault-k8s/dependencies.txt
 test -s /usr/share/vault-k8s/modules.json
 test -s /usr/share/vault-k8s/LICENSE
 grep -Fq "go1.26.6" /usr/share/vault-k8s/buildinfo.txt
 grep -Fq "golang.org/x/crypto v0.56.0" /usr/share/vault-k8s/go.mod
 ! grep -Eq "^golang.org/x/crypto/openpgp(/|$)" /usr/share/vault-k8s/dependencies.txt
 echo "523d4663f46016c0913a5965b5b3c73a3e5778ca3361bcdd3dfe889f299ef860  /usr/share/vault-k8s/go.mod" | sha256sum -c -
 echo "db40b881228158570efbbde9e291d1a45c4abf2c0fc970d036d3f5d7bcd566e4  /usr/share/vault-k8s/go.sum" | sha256sum -c -
'
GRYPE_CHECK_FOR_APP_UPDATE=false grype --config "$root/.ci/prysm-beacon-runtime/grype.yaml" "docker:$image" --platform linux/amd64 -o json > "$scan"
jq -e --arg image "$image" '.source.target.userInput==$image and .descriptor.name=="grype" and .descriptor.db.status.valid==true
 and .descriptor.configuration.exclude==[] and .descriptor.configuration["only-fixed"]==false and .descriptor.configuration["only-notfixed"]==false
 and .descriptor.configuration["show-suppressed"]==true
 and (.matches|type)=="array" and (.ignoredMatches|length)==0
 and all(.matches[]; (.vulnerability.severity|type)=="string" and (.vulnerability.severity|ascii_downcase|IN("critical","high")|not))' "$scan" >/dev/null
printf 'PASS: immutable injector runtime checks and C/H=0 scan: %s\nUnknown findings still need separate assessment.\n' "$image"
