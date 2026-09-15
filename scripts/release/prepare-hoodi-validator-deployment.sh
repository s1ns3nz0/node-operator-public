#!/usr/bin/env bash
set -euo pipefail

# Render only non-secret, initially fenced workload manifests. Vault recovery
# material, keystore files, mnemonic, and wallet access remain outside this command.
usage() {
  printf '%s\n' "Usage: ${0##*/} --validator-set <hoodi-id> --validator-public-key <0x-key> --withdrawal-address <0x-address> --aws-account-id <12-digit-id> [--aws-region <aws-region>] --web3signer-image <private-ecr@sha256> --postgres-image <private-ecr@sha256> --prysm-validator-image <private-ecr@sha256> --signing-fence-image <private-ecr@sha256> --kubernetes-api-cidr <ipv4/32> --output-dir <new-absolute-dir>" >&2
  exit 64
}

validator_set=''; validator_public_key=''; withdrawal_address=''; aws_account_id=''; aws_region='ap-northeast-2'; web3signer_image=''; postgres_image=''; prysm_image=''; fence_image=''; kubernetes_api_cidr=''; output_dir=''
deployment_identity=''; release_identity=''
while [ "$#" -gt 0 ]; do
  case "$1" in
    --validator-set) validator_set="${2:-}"; shift 2 ;;
    --validator-public-key) validator_public_key="${2:-}"; shift 2 ;;
    --withdrawal-address) withdrawal_address="${2:-}"; shift 2 ;;
    --aws-account-id) aws_account_id="${2:-}"; shift 2 ;;
    --aws-region) aws_region="${2:-}"; shift 2 ;;
    --web3signer-image) web3signer_image="${2:-}"; shift 2 ;;
    --postgres-image) postgres_image="${2:-}"; shift 2 ;;
    --prysm-validator-image) prysm_image="${2:-}"; shift 2 ;;
    --signing-fence-image) fence_image="${2:-}"; shift 2 ;;
    --kubernetes-api-cidr) kubernetes_api_cidr="${2:-}"; shift 2 ;;
    --output-dir) output_dir="${2:-}"; shift 2 ;;
    --deployment-name) deployment_identity="${2:-}"; shift 2 ;;
    --release-revision) release_identity="${2:-}"; shift 2 ;;
    *) usage ;;
  esac
done

case "$validator_set" in hoodi-[a-z0-9][a-z0-9-]*) ;; *) usage ;; esac
case "$validator_public_key" in 0x????????????????????????????????????????????????????????????????????????????????????????????????) ;; *) usage ;; esac
case "$withdrawal_address" in 0x????????????????????????????????????????) ;; *) usage ;; esac
case "$aws_account_id" in [0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]) ;; *) usage ;; esac
[[ "$aws_region" =~ ^[a-z]{2}-[a-z0-9-]+-[0-9]+$ ]] || usage
case "$output_dir" in /*) ;; *) usage ;; esac
set --
if [ -n "$deployment_identity$release_identity" ]; then
  [[ "$deployment_identity" =~ ^[a-z][a-z0-9-]{1,38}[a-z0-9]$ ]] && [[ "$release_identity" =~ ^[0-9a-f]{40}$ ]] || usage
  set -- --deployment-name "$deployment_identity" --release-revision "$release_identity"
fi
for command in jq mkdir mktemp mv chmod dirname rm tr; do
  command -v "$command" >/dev/null 2>&1 || { printf 'missing command: %s\n' "$command" >&2; exit 69; }
done

# Refuse existing paths, including symlinks, to avoid replacing prior evidence
# or writing through an operator-controlled link.
[ ! -e "$output_dir" ] && [ ! -L "$output_dir" ] || { printf '%s\n' 'output directory already exists or is a symlink; choose a new controlled directory' >&2; exit 65; }
mkdir -m 700 "$output_dir"
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
runtime="$output_dir/runtime.yaml"
client="$output_dir/client-and-fence.yaml"
handoff="$output_dir/validator-deployment-handoff.json"
temporary=''
cleanup() { set +e; [ -z "$temporary" ] || [ ! -e "$temporary" ] || rm -f "$temporary"; }
trap cleanup EXIT INT TERM

"$root/scripts/ops/render-hoodi-validator-runtime.sh" --validator-set "$validator_set" --aws-account-id "$aws_account_id" --aws-region "$aws_region" --web3signer-image "$web3signer_image" --postgres-image "$postgres_image" --output "$runtime" "$@"
"$root/scripts/ops/render-hoodi-validator-client.sh" --validator-set "$validator_set" --validator-public-key "$validator_public_key" --aws-account-id "$aws_account_id" --aws-region "$aws_region" --prysm-validator-image "$prysm_image" --signing-fence-image "$fence_image" --kubernetes-api-cidr "$kubernetes_api_cidr" --output "$client" "$@"

temporary="$(mktemp "$output_dir/.handoff.XXXXXX")"
jq -n \
  --arg validator_set "$validator_set" \
  --arg aws_account_id "$aws_account_id" \
  --arg aws_region "$aws_region" \
  --arg validator_public_key "$(printf '%s' "$validator_public_key" | tr '[:upper:]' '[:lower:]')" \
  --arg withdrawal_address "$(printf '%s' "$withdrawal_address" | tr '[:upper:]' '[:lower:]')" \
  --arg runtime_manifest "$runtime" \
  --arg client_manifest "$client" \
  '{schema_version: 1, network: "hoodi", validator_set: $validator_set, aws_account_id: $aws_account_id, aws_region: $aws_region, validator_public_key: $validator_public_key, withdrawal_address: $withdrawal_address, runtime_manifest: $runtime_manifest, client_manifest: $client_manifest, staged_client_replicas: 0, staged_fence_replicas: 0, next_steps: ["Apply the two non-secret manifests through scripts/ops/with-private-eks.sh only after the private cluster is healthy.", "Run recover-and-bootstrap-hoodi-validator-runtime-vault.sh interactively; recovery shares never belong in this handoff.", "Run recover-and-onboard-hoodi-validator-keystore.sh from the custody workstation; the keystore directory and password never belong in this handoff.", "Validate the public Hoodi deposit and collect fresh UC-3 private-beacon and signer evidence before activation.", "Use activate-hoodi-validator-client.sh only with the required matching evidence; it is the only scale-up path."]}' > "$temporary"
chmod 600 "$temporary"
mv "$temporary" "$handoff"; temporary=''
printf 'PASS: staged Hoodi validator deployment prepared in %s. Runtime, client, and fence remain non-secret and client/fence replicas remain zero.\n' "$output_dir"
