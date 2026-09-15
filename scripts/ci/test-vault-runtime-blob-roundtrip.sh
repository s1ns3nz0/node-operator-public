#!/usr/bin/env bash
# Check objective: Verify synthetic Vault runtime evidence can complete an offline Cosign blob round trip.
# Synthetic offline key only. These options are forbidden in the real verifier.
set -euo pipefail
cosign="${COSIGN_BIN:-cosign}"
scratch="$(mktemp -d)"
trap 'rm -rf -- "$scratch"' EXIT
export COSIGN_PASSWORD=''
printf '%s\n' '{"predicateType":"synthetic/runtime-verification","deployment_authorized":false}' > "$scratch/statement.json"
printf '%s\n' '{"mediaType":"application/vnd.dev.sigstore.signingconfig.v0.2+json","caUrls":[],"oidcUrls":[],"rekorTlogUrls":[],"tsaUrls":[]}' > "$scratch/offline.json"
"$cosign" generate-key-pair --output-key-prefix "$scratch/synthetic" >/dev/null 2>&1
"$cosign" sign-blob --yes --signing-config "$scratch/offline.json" --key "$scratch/synthetic.key" --bundle "$scratch/bundle.json" "$scratch/statement.json" >/dev/null
"$cosign" verify-blob --insecure-ignore-tlog --key "$scratch/synthetic.pub" --bundle "$scratch/bundle.json" "$scratch/statement.json" >/dev/null
printf '%s\n' '{"predicateType":"synthetic/runtime-verification","deployment_authorized":true}' > "$scratch/statement.json"
if "$cosign" verify-blob --insecure-ignore-tlog --key "$scratch/synthetic.pub" --bundle "$scratch/bundle.json" "$scratch/statement.json" >/dev/null 2>&1; then
  echo 'tampered statement accepted' >&2; exit 1
fi
printf 'PASS: real offline Cosign blob roundtrip and tamper rejection; not GitHub OIDC proof.\n'
