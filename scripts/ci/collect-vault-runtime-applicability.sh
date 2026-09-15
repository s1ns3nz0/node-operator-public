#!/usr/bin/env bash
set -euo pipefail
test "$#" = 3 || { echo 'usage: collect-vault-runtime-applicability.sh COMPONENT EXACT_SUBJECT EVIDENCE_DIRECTORY' >&2; exit 64; }
component="$1"; subject="$2"; evidence="$3"
case "$component" in
  server) binary=/bin/vault; dependencies=/usr/share/vault/dependencies.txt;;
  agent) binary=/usr/local/bin/vault; dependencies=;;
  injector) binary=/bin/vault-k8s; dependencies=/usr/share/vault-k8s/dependencies.txt;;
  *) echo 'unreviewed component' >&2; exit 64;;
esac
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
expected="$(jq -er --arg c "$component" '.registry + "/" + .candidates[$c].repository + "@" + .candidates[$c].digest' "$root/.ci/vault-runtime-candidates.json")"
test "$subject" = "$expected"
unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AWS_PROFILE AWS_DEFAULT_PROFILE
unset ACTIONS_ID_TOKEN_REQUEST_TOKEN ACTIONS_ID_TOKEN_REQUEST_URL
mkdir -p "$evidence"
# Read only public build metadata from the exact image already pulled by CI.
# Never mount a credential, host directory, socket, or live Vault config.
run=(timeout 60 docker run --rm --pull never --platform linux/amd64 --network none --read-only
  --cap-drop ALL --security-opt no-new-privileges --pids-limit 64 --memory 512m --cpus 1
  --entrypoint /bin/sh "$subject")
# shellcheck disable=SC2016
"${run[@]}" -ec 'sha256sum "$1"' metadata "$binary" > "$evidence/binary.sha256"
if test "$component" = agent; then
  cp "$root/.ci/vault-runtime-applicability/agent-dependencies.txt" "$evidence/dependencies.txt"
else
  # shellcheck disable=SC2016
  "${run[@]}" -ec 'cat "$1"' metadata "$dependencies" > "$evidence/dependencies.txt"
fi
# Advisory content drift or unavailability must never silently reuse stale scope.
curl --fail --silent --show-error --connect-timeout 10 --max-time 30 --retry 2 \
  --output "$evidence/advisory-current.json" https://vuln.go.dev/ID/GO-2026-5932.json
