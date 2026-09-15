#!/usr/bin/env bash
set -euo pipefail
# Exact-candidate applicability proof, not a generic exception or rollout gate.
test "$#" = 2 || { echo 'Usage: verify-vault-agent-candidate.sh GRYPE_JSON DEPENDENCY_EXPORT' >&2; exit 2; }
scan="$1"
evidence="$2"
image='sha256:33458e87c790b140717f2f4c688d31327292f67677ba004d32838deed8b8f30a'
binary='ce1ea8a97b2a565cc9cbd65004b21300d6beee9b1fdcf758c4adc76f068a2647'
check_hash() {
  test "$(shasum -a 256 "$1" | awk '{print $1}')" = "$2"
}
check_hash "$scan" cbe6c51221624eab14dbb268c0daa2624c4c97c512db1c312f75a57db23d97ff
check_hash "$evidence/dependencies.txt" 386770b26b88aa34397b273497a955a6ecb782fc5d66f32f5302072dd13f9d63
check_hash "$evidence/go.mod" b53b65e6b7b8dc7945222418e6d0484757de722caae6c6fd1be98f040d6629e7
check_hash "$evidence/go.sum" cd83ac5e32c2f260930f9d3ee0f9daa07093c08ce2411974ed10752b5ab899c6
check_hash "$evidence/agent-main.go" 730bf733a96841552019c28d971068d43a8f2cca4300daa8ea2217e1f01b16e8
test "$(cat "$evidence/binary.sha256")" = "$binary  /out/vault"
test "$(wc -l < "$evidence/dependencies.txt" | tr -d ' ')" = 1973
if grep -Eq '^golang.org/x/crypto/openpgp(/|$)' "$evidence/dependencies.txt"; then
  echo 'Affected OpenPGP package present; reassessment required.' >&2
  exit 1
fi
grep -Fxq 'github.com/ProtonMail/go-crypto/openpgp' "$evidence/dependencies.txt"
test "$(docker image inspect --format '{{.Id}}' "$image")" = "$image"
jq -e --arg image "$image" '
 .source.target.userInput==$image and .descriptor.name=="grype" and
 .descriptor.db.status.valid==true and .descriptor.configuration.exclude==[] and
 .descriptor.configuration["only-fixed"]==false and .descriptor.configuration["only-notfixed"]==false and
 .descriptor.configuration["show-suppressed"]==true and
 (.matches|type)=="array" and (.ignoredMatches|length)==0 and
 ([.matches[]|select(.vulnerability.id=="GO-2026-5932" and
 .vulnerability.severity=="Unknown" and .artifact.name=="golang.org/x/crypto" and
 .artifact.version=="v0.56.0")]|length)==1 and all(.matches[];
 (.vulnerability.severity|ascii_downcase|IN("critical","high")|not))
' "$scan" >/dev/null
actual="$(docker run --rm --platform linux/amd64 --network none --read-only --cap-drop ALL \
 --security-opt no-new-privileges --entrypoint /bin/sh "$image" -ec \
 'test "$(id -u)" = 100; sha256sum /usr/local/bin/vault')"
test "$actual" = "$binary  /usr/local/bin/vault"
printf '%s\n' 'PASS: frozen Agent binary matches the exported package closure; C/H=0 and GO-2026-5932 affected packages absent. Raw finding retained; no live deployment approval.'
