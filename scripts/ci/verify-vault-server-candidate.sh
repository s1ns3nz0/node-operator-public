#!/usr/bin/env bash
set -euo pipefail
image='sha256:5463f9d70fe71b897b165e019dbc1e85aeaa8271130572bd060729dc124ff51f'
scan="${1:?Usage: verify-vault-server-candidate.sh EXISTING_EXACT_IMAGE_GRYPE_JSON}"
test "$#" = 1
test "$(shasum -a 256 "$scan" | awk '{print $1}')" = '49f7409358311427b2b1193af70fc37ce87d893581e79a6c875ee7d3f8b44e33'
test "$(docker image inspect --format '{{.Id}}' "$image")" = "$image"
jq -e --arg image "$image" '
 .source.target.userInput==$image and .descriptor.name=="grype" and
 .descriptor.db.status.valid==true and .descriptor.configuration.exclude==[] and
 .descriptor.configuration["only-fixed"]==false and .descriptor.configuration["only-notfixed"]==false and
 .descriptor.configuration["show-suppressed"]==true and
 (.matches|type)=="array" and
 (.ignoredMatches|length)==0 and
 ([.matches[]|select(.vulnerability.id=="GO-2026-5932" and
 .vulnerability.severity=="Unknown" and .artifact.name=="golang.org/x/crypto" and
 .artifact.version=="v0.56.0")]|length)==1 and all(.matches[];
 (.vulnerability.severity|ascii_downcase|IN("critical","high")|not))
' "$scan" >/dev/null
# The scanner finding is retained, not suppressed. This checks the package-level
# scope in https://vuln.go.dev/ID/GO-2026-5932.json against the frozen build closure.
# shellcheck disable=SC2016
docker run --rm --platform linux/amd64 --network none --read-only --cap-drop ALL \
 --security-opt no-new-privileges --entrypoint /bin/sh "$image" -ec '
 test "$(id -u)" = 100
 test ! -w /bin/vault
 test -s /usr/share/vault/LICENSE
 grep -Fq "go1.26.6" /usr/share/vault/buildinfo.txt
 echo "b53b65e6b7b8dc7945222418e6d0484757de722caae6c6fd1be98f040d6629e7  /usr/share/vault/go.mod" | sha256sum -c -
 echo "cd83ac5e32c2f260930f9d3ee0f9daa07093c08ce2411974ed10752b5ab899c6  /usr/share/vault/go.sum" | sha256sum -c -
 test "$(wc -l < /usr/share/vault/dependencies.txt)" -gt 100
 ! grep -Eq "^golang.org/x/crypto/openpgp(/|$)" /usr/share/vault/dependencies.txt
 grep -Fxq "github.com/ProtonMail/go-crypto/openpgp" /usr/share/vault/dependencies.txt
 echo "6e810e887ea958c6e1d711696afe9de28a5c1c0b9b0c26d9be1626ae5ae59029  /usr/share/vault/dependencies.txt" | sha256sum -c -
 '
printf '%s\n' 'PASS: frozen Vault server C/H=0; GO-2026-5932 affected package absent from build closure. No finding suppressed; not a live deployment approval.'
