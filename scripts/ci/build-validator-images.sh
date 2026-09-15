#!/usr/bin/env bash
set -euo pipefail

# Docker-first local build/test entry point. Never publishes or deploys.
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
target="${1:-all}"
case "$target" in prysm|beacon|fence|web3signer|identity-probe|audit-relay|nethermind|all) ;; *) echo 'Usage: build-validator-images.sh [prysm|beacon|fence|web3signer|identity-probe|audit-relay|nethermind|all]' >&2; exit 64 ;; esac
[ "$#" -le 1 ] || exit 64
command -v docker >/dev/null || { echo 'Docker with Buildx is required.' >&2; exit 69; }
docker buildx version >/dev/null
build_one() {
  local component="$1" dockerfile tag input_sha image_id
  local -a build_args=()
  case "$component" in
    prysm) dockerfile=.ci/prysm-mtls/Dockerfile; tag=node-operator-prysm-mtls:local ;;
    beacon) dockerfile=.ci/prysm-beacon-runtime/Dockerfile; tag=node-operator-prysm-beacon:hardened-local ;;
    fence) dockerfile=.ci/validator-signing-fence/Dockerfile; tag=node-operator-validator-fence:local ;;
    web3signer) dockerfile=.ci/web3signer-hardened/Dockerfile; tag=node-operator-web3signer-hardened:local ;;
    identity-probe) dockerfile=.ci/validator-signer-identity-probe/Dockerfile; tag=node-operator-signer-identity-probe:local ;;
    audit-relay) dockerfile=.ci/vault-audit-relay/Dockerfile; tag=node-operator-vault-audit-relay:hardened-local ;;
    nethermind) dockerfile=.ci/nethermind-runtime/Dockerfile; tag=node-operator-nethermind:runtime-10.0.11 ;;
  esac
  if [ "$component" = fence ]; then
    input_sha="$(python3 "$root/scripts/release/fence_build_inputs.py" --root "$root")"
    [[ "$input_sha" =~ ^[a-f0-9]{64}$ ]] || exit 65
    build_args=(--build-arg "FENCE_INPUT_SHA=$input_sha")
  elif [ "$component" = identity-probe ]; then
    input_sha="$(python3 "$root/scripts/release/signer_probe_build_inputs.py" --root "$root")"
    [[ "$input_sha" =~ ^[a-f0-9]{64}$ ]] || exit 65
    build_args=(--build-arg "SIGNER_PROBE_INPUT_SHA=$input_sha")
  elif [ "$component" = audit-relay ]; then
    input_sha="$(cd "$root"; shasum -a 256 .ci/vault-audit-relay/Dockerfile go.mod cmd/vault-audit-relay/main.go cmd/vault-audit-relay/main_test.go | awk '{print $1}' | shasum -a 256 | awk '{print $1}')"
    [[ "$input_sha" =~ ^[a-f0-9]{64}$ ]] || exit 65
    build_args=(--build-arg "RELAY_INPUT_SHA=$input_sha")
  fi
  docker buildx build --platform linux/amd64 --load --progress plain \
    ${build_args[@]+"${build_args[@]}"} --file "$root/$dockerfile" --tag "$tag" "$root"
  image_id="$(docker image inspect --format '{{.Id}}' "$tag")"
  [[ "$image_id" =~ ^sha256:[a-f0-9]{64}$ ]] || exit 65
  printf 'Docker image build completed (embedded tests run where defined): %s\nScan this immutable local image ID: %s\n' "$tag" "$image_id"
}
if [ "$target" = all ]; then
  build_one prysm
  build_one beacon
  build_one fence
  build_one web3signer
  build_one identity-probe
  build_one audit-relay
  build_one nethermind
else
  build_one "$target"
fi
echo 'Build only: scan the exact image before publication. Unresolved Prysm findings require documented, scoped risk acceptance; see docs/operations/prysm-risk-acceptance.md.'
