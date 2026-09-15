#!/usr/bin/env bash
set +x
set -euo pipefail
umask 077

# Creates the isolated KV v2 and PKI engines, then installs only the Hoodi
# workload policies/roles. It deliberately does not accept a validator key,
# mnemonic, password, or any custody payload.
dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
usage() {
  printf 'Usage: %s --validator-set <hoodi-id> [--recovery-output-dir <private-absolute-dir>] [--prepare-existing --output-dir <new-absolute-dir> | --activate-existing --preparation-evidence <absolute-json> --output-dir <new-absolute-dir>]\n' "${0##*/}" >&2
  printf '%s\n' 'Read-only completed initialization check: --validator-set <hoodi-id> --recovery-output-dir <private-absolute-dir> --verify-initialization-completion' >&2
  exit 64
}
validator_set=''; prepare_existing=false; activate_existing=false; preparation=''; output=''; recovery_output=''
verify_initialization_completion=false
while [ "$#" -gt 0 ]; do case "$1" in
  --validator-set) validator_set="${2:-}"; shift 2 ;;
  --prepare-existing) prepare_existing=true; shift ;;
  --activate-existing) activate_existing=true; shift ;;
  --preparation-evidence) preparation="${2:-}"; shift 2 ;;
  --output-dir) output="${2:-}"; shift 2 ;;
  --recovery-output-dir) recovery_output="${2:-}"; shift 2 ;;
  --verify-initialization-completion) verify_initialization_completion=true; shift ;;
  *) usage ;;
esac; done
[[ "$validator_set" =~ ^hoodi-[a-z0-9][a-z0-9-]{0,35}$ ]] || usage
args=(--validator-set "$validator_set")
[ -z "$recovery_output" ] || args+=(--recovery-output-dir "$recovery_output")
if [ "$verify_initialization_completion" = true ]; then
  [ "$prepare_existing" = false ] && [ "$activate_existing" = false ] && [ -z "$output$preparation" ] && [[ "$recovery_output" = /* ]] || usage
  args+=(--verify-initialization-completion)
fi
if [ "$activate_existing" = true ]; then
  [ "$prepare_existing" = false ] || usage
  [[ "$preparation" = /* ]] && [ -f "$preparation" ] && [ ! -L "$preparation" ] || usage
  [[ "$output" = /* ]] && [ ! -e "$output" ] && [ ! -L "$output" ] || usage
  args+=(--activate-existing --preparation-evidence "$preparation" --output-dir "$output")
elif [ "$prepare_existing" = true ]; then
  [ -z "$preparation" ] || usage
  [[ "$output" = /* ]] && [ ! -e "$output" ] && [ ! -L "$output" ] || usage
  args+=(--prepare-existing --output-dir "$output")
elif [ -n "$output" ] || [ -n "$preparation" ]; then usage; fi

if [ "${PRIVATE_VAULT_SESSION:-}" != 1 ]; then
  exec "$dir/with-private-vault.sh" -- env PRIVATE_VAULT_TARGET=pod/vault-0 PRIVATE_VAULT_SESSION=1 "$0" "${args[@]}"
fi
for command in vault jq seq; do command -v "$command" >/dev/null 2>&1 || { printf 'missing command: %s\n' "$command" >&2; exit 69; }; done

started=false; complete=false; root=''; bootstrap_complete=false; init_response=''; checkpoint_path=''
cleanup() {
  local rc=$?
  trap - EXIT
  set +e
  if [ -n "$root" ] && ! VAULT_TOKEN="$root" vault token revoke -self >/dev/null 2>&1; then
    printf '%s\n' 'CRITICAL: generated root token revocation could not be confirmed.' >&2
    rc=70
  fi
  if [ "$started" = true ] && [ "$complete" != true ]; then
    vault operator generate-root -cancel >/dev/null 2>&1 || rc=70
  fi
  unset root VAULT_TOKEN
  if [ "$rc" -eq 0 ] && [ "$bootstrap_complete" = true ] && [ -n "$init_response" ]; then
    if ! rm -f "$init_response"; then
      printf 'CRITICAL: private initialization response could not be removed: %s\n' "$init_response" >&2
      rc=70
    fi
  fi
  if [ "$rc" -eq 0 ] && [ "$bootstrap_complete" = true ] && [ -n "$checkpoint_path" ] && [ -f "$checkpoint_path" ] && [ ! -L "$checkpoint_path" ]; then
    checkpoint_temporary="$(mktemp "$(dirname "$checkpoint_path")/.vault-initialization-checkpoint.XXXXXX")" || rc=70
    if [ "$rc" -eq 0 ]; then
      chmod 600 "$checkpoint_temporary"
      jq '.status="configured" | .root_revoked=true' "$checkpoint_path" > "$checkpoint_temporary" && mv -f "$checkpoint_temporary" "$checkpoint_path" || rc=70
    fi
  fi
  if [ "$rc" -eq 0 ] && [ "$bootstrap_complete" = true ]; then
    if [ "$activate_existing" = true ]; then
      if ! jq -n --arg set "$validator_set" --arg now "$(date -u +%FT%TZ)" \
        '{schema_version:1,operation:"activate-existing-hoodi-vault-v2",validator_set:$set,
          collected_at_utc:$now,runtime_mount:"node-operator-runtime",custody_preserved:true,
          transport_verified:true,engine_jwt_verified:true,generated_root_revoked:true,
          live_roles_installed:true,public_trust_config_updated:true,client_and_fence_quiesced:true,live_workloads_changed:false,
          source_secrets_retained:true,secret_values_emitted:false}' > "$output/activation.json"; then exit 74; fi
      printf 'PASS: Vault v2 roles activated for %s; generated root token revoked. Workload cutover remains required.\n' "$validator_set"
    elif [ "$prepare_existing" = true ]; then
      if ! jq -n --arg set "$validator_set" --arg now "$(date -u +%FT%TZ)" \
        '{schema_version:1,operation:"prepare-existing-hoodi-vault-v2",validator_set:$set,
          collected_at_utc:$now,runtime_mount:"node-operator-runtime",custody_preserved:true,
          transport_verified:true,engine_jwt_verified:true,generated_root_revoked:true,
          live_policies_changed:false,live_workloads_changed:false,secret_values_emitted:false}' \
        > "$output/preparation.json"; then exit 74; fi
      printf 'PASS: existing custody and Vault v2 transport/JWT prepared for %s; generated root token revoked. Live cutover remains required.\n' "$validator_set"
    else
    printf 'PASS: Hoodi Vault v2 runtime boundary is ready for %s; generated root token revoked. Custody onboarding is still required.\n' "$validator_set"
    fi
  fi
  exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

# shellcheck source=scripts/ops/lib/vault-recovery-auth.sh
source "$dir/lib/vault-recovery-auth.sh"
vault_status_json="$(vault status -format=json 2>/dev/null || true)"
initialized="$(jq -er 'if (.initialized | type) == "boolean" then (.initialized | tostring) else error end' <<<"$vault_status_json" 2>/dev/null)" || { printf '%s\n' 'Vault status did not return a boolean initialized field' >&2; exit 65; }
if [ -n "$recovery_output" ]; then
  [[ "$recovery_output" = /* ]] || { printf '%s\n' 'recovery output directory must be absolute' >&2; exit 64; }
  output_parent="$(dirname "$recovery_output")"
  [ -d "$output_parent" ] || { printf '%s\n' 'recovery output parent must exist' >&2; exit 65; }
  [ ! -L "$output_parent" ] || { printf '%s\n' 'recovery output parent must not be a symlink' >&2; exit 65; }
  recovery_output="$(cd "$output_parent" && pwd -P)/$(basename "$recovery_output")"
  ancestor="$recovery_output"
  while [ "$ancestor" != / ]; do
    [ ! -L "$ancestor" ] || { printf '%s\n' 'recovery output ancestry must not contain symlinks' >&2; exit 65; }
    ancestor="$(dirname "$ancestor")"
  done
  checkout_root="$(cd "$dir/../.." && pwd -P)"
  output_canonical="$(cd "$output_parent" && pwd -P)/$(basename "$recovery_output")"
  case "$output_canonical" in "$checkout_root"|"$checkout_root"/*) printf '%s\n' 'recovery output directory must be outside the checkout' >&2; exit 65 ;; esac
fi
# A crash after successful cleanup may leave only the outer phase uncommitted.
# This read-only mode proves the recorded initialization completion belongs to
# the reachable Vault. It does not reconfigure policies or assert their current
# contents, and never opens recovery shares or starts a generate-root ceremony.
if [ "$verify_initialization_completion" = true ]; then
  checkpoint="$recovery_output/vault-initialization-checkpoint.json"
  [ -d "$recovery_output" ] && [ ! -L "$recovery_output" ] && [ -f "$checkpoint" ] && [ ! -L "$checkpoint" ] || exit 75
  [ "$(stat -c '%a' "$recovery_output" 2>/dev/null || stat -f '%Lp' "$recovery_output")" = 700 ] || exit 65
  [ "$(stat -c '%a' "$checkpoint" 2>/dev/null || stat -f '%Lp' "$checkpoint")" = 600 ] || exit 65
  actual_cluster="$(jq -er 'select(.initialized == true and .sealed == false) | .cluster_id | strings | select(length > 0)' <<<"$vault_status_json")" || exit 75
  jq -e --arg cluster "$actual_cluster" --arg set "$validator_set" '.schema_version == 1 and .status == "configured" and .cluster_id == $cluster and .validator_set == $set and .shares == 5 and .threshold == 3 and .root_revoked == true' "$checkpoint" >/dev/null || exit 75
  printf '%s\n' 'PASS: recorded initialization completion matches the reachable unsealed Vault; no administrator ceremony was replayed.'
  exit 0
fi
if [ "$initialized" = true ] && [ -n "$recovery_output" ] && [ -e "$recovery_output/vault-initialization-checkpoint.json" ]; then
  checkpoint="$recovery_output/vault-initialization-checkpoint.json"
  [ -d "$recovery_output" ] && [ ! -L "$recovery_output" ] && [ -f "$checkpoint" ] && [ ! -L "$checkpoint" ] || { printf '%s\n' 'Vault recovery output is unsafe' >&2; exit 65; }
  actual_cluster="$(jq -er '.cluster_id | strings | select(length > 0)' <<<"$vault_status_json")" || { printf '%s\n' 'initialized Vault status lacks a cluster identity' >&2; exit 65; }
  [ "$(stat -c '%a' "$recovery_output" 2>/dev/null || stat -f '%Lp' "$recovery_output")" = 700 ] || { printf '%s\n' 'Vault recovery directory must have mode 0700' >&2; exit 65; }
  [ "$(stat -c '%a' "$checkpoint" 2>/dev/null || stat -f '%Lp' "$checkpoint")" = 600 ] || { printf '%s\n' 'Vault recovery checkpoint must have mode 0600' >&2; exit 65; }
  if jq -e --arg cluster "$actual_cluster" --arg set "$validator_set" '.schema_version == 1 and .status == "configured" and .cluster_id == $cluster and .validator_set == $set and .shares == 5 and .threshold == 3 and .root_revoked == true' "$checkpoint" >/dev/null; then
    # The raw initialization response and shares may already be stored outside
    # this directory.  Metadata only binds this initialized cluster; the
    # authenticated generate-root path below still revalidates/reconfigures it.
    checkpoint_path="$checkpoint"
  else
    jq -e --arg cluster "$actual_cluster" --arg set "$validator_set" '.schema_version == 1 and .status == "backup-pending" and .cluster_id == $cluster and .validator_set == $set and .shares == 5 and .threshold == 3' "$checkpoint" >/dev/null || { printf '%s\n' 'Vault recovery checkpoint does not match this initialized Vault' >&2; exit 65; }
    [ "$(find "$recovery_output" -maxdepth 1 -type f -name 'recovery-share-*.txt' | wc -l | tr -d '[:space:]')" = 5 ] || { printf '%s\n' 'backup-pending recovery directory must contain exactly five share files' >&2; exit 65; }
    for number in 01 02 03 04 05; do
      share_path="$recovery_output/recovery-share-$number.txt"
      [ -f "$share_path" ] && [ ! -L "$share_path" ] && [ "$(stat -c '%a' "$share_path" 2>/dev/null || stat -f '%Lp' "$share_path")" = 600 ] || { printf 'backup-pending recovery share is unsafe: %s\n' "$share_path" >&2; exit 65; }
    done
    raw_name="$(jq -er '.raw_response | strings | select(test("^vault-init-response\\.[A-Za-z0-9]+$"))' "$checkpoint")" || { printf '%s\n' 'backup-pending checkpoint has no valid owned raw response name' >&2; exit 65; }
    init_response="$recovery_output/$raw_name"
    [ -f "$init_response" ] && [ ! -L "$init_response" ] && [ "$(stat -c '%a' "$init_response" 2>/dev/null || stat -f '%Lp' "$init_response")" = 600 ] || { printf '%s\n' 'backup-pending raw response is unsafe' >&2; exit 65; }
    for number in 01 02 03 04 05; do
      expected_share="$(jq -er ".recovery_keys_b64[$((10#$number-1))] | strings" "$init_response")" || { printf '%s\n' 'backup-pending raw response is malformed' >&2; exit 65; }
      actual_share="$(cat "$recovery_output/recovery-share-$number.txt")"
      [ "$expected_share" = "$actual_share" ] || { printf '%s\n' 'backup-pending raw response does not match owned share files' >&2; exit 65; }
    done
    checkpoint_path="$checkpoint"
    printf 'Vault initialization is backup-pending; verify the separately stored recovery-share files, then type BACKED_UP or EXIT: ' >&2
    IFS= read -r stored_confirmation || stored_confirmation=''
    [ "$stored_confirmation" = BACKED_UP ] || { printf '%s\n' 'Leaving Vault initialized and backup-pending; initialization will not be repeated.' >&2; exit 75; }
  fi
fi
if [ "$initialized" = false ]; then
  [[ "$recovery_output" = /* ]] || { printf '%s\n' 'new Vault initialization requires --recovery-output-dir outside the checkout' >&2; exit 64; }
  [ ! -L "$recovery_output" ] || { printf '%s\n' 'recovery output directory must not be a symlink' >&2; exit 65; }
  if [ ! -e "$recovery_output" ]; then mkdir -m 700 "$recovery_output"; fi
  [ -d "$recovery_output" ] && [ ! -L "$recovery_output" ] || { printf '%s\n' 'recovery output directory must be a regular directory' >&2; exit 65; }
  [ "$(stat -c '%a' "$recovery_output" 2>/dev/null || stat -f '%Lp' "$recovery_output")" = 700 ] || { printf '%s\n' 'recovery output directory must have mode 0700' >&2; exit 65; }
  for name in vault-init-response.json vault-initialization-checkpoint.json recovery-share-01.txt recovery-share-02.txt recovery-share-03.txt recovery-share-04.txt recovery-share-05.txt; do
    [ ! -e "$recovery_output/$name" ] && [ ! -L "$recovery_output/$name" ] || { printf 'refusing to overwrite recovery output: %s\n' "$name" >&2; exit 65; }
  done
  printf '\n%s\n' 'Vault is reachable but uninitialized. A first-run initialization ceremony is required.' >&2
  printf '%s\n' 'Recovery policy: 5 shares will be generated; any 3 shares are required for recovery.' >&2
  printf '%s\n' 'This will generate recovery shares and a temporary root token retained only in private recovery files and process memory.' >&2
  printf 'Type INIT to begin, or EXIT to leave Vault untouched: ' >&2
  IFS= read -r init_action || init_action=''
  case "$init_action" in
    INIT) ;;
    EXIT|'') printf '%s\n' 'Vault initialization cancelled; no changes were made.' >&2; exit 75 ;;
    *) printf '%s\n' 'Invalid action; Vault initialization cancelled.' >&2; exit 64 ;;
  esac
  init_response="$(mktemp "$recovery_output/vault-init-response.XXXXXX")"
  chmod 600 "$init_response"
  if ! vault operator init -recovery-shares=5 -recovery-threshold=3 -format=json > "$init_response"; then
    printf 'Vault initialization command failed; any received private response remains at %s.\n' "$init_response" >&2
    exit 70
  fi
  init_json="$(<"$init_response")"
  root="$(jq -er '.root_token' <<<"$init_json")" || { printf 'Vault initialization response is malformed; manual recovery is required from the private response file at %s.\n' "$init_response" >&2; exit 70; }
  recovery_keys_json="$(jq -cer '.recovery_keys_b64 | if type == "array" and length == 5 then . else error end' <<<"$init_json")" || { printf 'Vault initialization response is incomplete; manual recovery is required from the private response file at %s.\n' "$init_response" >&2; exit 70; }
  recovery_count="$(jq -er 'length' <<<"$recovery_keys_json")"
  printf '\n%s\n' 'Recovery shares were delivered to private files. The initial root token is not displayed and will be revoked.' >&2
  printf 'Recovery policy in effect: %s shares generated; 3 shares required.\n' "$recovery_count" >&2
  number=0
  while IFS= read -r share; do
    number=$((number + 1))
    share_path="$recovery_output/recovery-share-$(printf '%02d' "$number").txt"
    share_temporary="$(mktemp "$recovery_output/.recovery-share.XXXXXX")"; chmod 600 "$share_temporary"
    printf '%s\n' "$share" > "$share_temporary"; ln "$share_temporary" "$share_path"; rm -f "$share_temporary"
    printf 'Recovery share %s/%s: %s\n' "$number" "$recovery_count" "$share_path" >&2
  done < <(jq -er '.[]' <<<"$recovery_keys_json")
  cluster_id="$(vault status -format=json | jq -er '.cluster_id | strings | select(length > 0)')" || { printf '%s\n' 'Vault initialized but cluster identity could not be recorded; recovery response remains private in the selected output directory.' >&2; exit 70; }
  checkpoint_path="$recovery_output/vault-initialization-checkpoint.json"
  checkpoint_temporary="$(mktemp "$recovery_output/.vault-initialization-checkpoint.XXXXXX")"; chmod 600 "$checkpoint_temporary"
  jq -n --arg cluster "$cluster_id" --arg set "$validator_set" --arg raw "$(basename "$init_response")" '{schema_version:1,status:"backup-pending",cluster_id:$cluster,validator_set:$set,shares:5,threshold:3,raw_response:$raw}' > "$checkpoint_temporary"
  ln "$checkpoint_temporary" "$checkpoint_path"; rm -f "$checkpoint_temporary"
  unset init_json recovery_keys_json share
  printf 'Type BACKED_UP after separate secure backup, or EXIT to stop: ' >&2
  IFS= read -r stored_confirmation || stored_confirmation=''
  [ "$stored_confirmation" = BACKED_UP ] || { printf 'Vault initialization remains backup-pending; recovery file paths are under %s.\n' "$recovery_output" >&2; exit 75; }
  printf '%s\n' 'Secure backup acknowledged; configuring Vault v2 and Hoodi runtime policies.' >&2
  VAULT_TOKEN="$root" "$dir/bootstrap-node-operator-vault-v2.sh" >/dev/null
  VAULT_TOKEN="$root" "$dir/configure-hoodi-vault-kubernetes-auth.sh" >/dev/null
  VAULT_TOKEN="$root" "$dir/bootstrap-hoodi-engine-api-vault.sh" >/dev/null
  VAULT_TOKEN="$root" "$dir/bootstrap-hoodi-validator-runtime-vault.sh" --validator-set "$validator_set" >/dev/null
  bootstrap_complete=true
else
  [ "$initialized" = true ] || { printf '%s\n' 'Vault status did not return a valid initialized field' >&2; exit 65; }
  vault_recovery_auth_preflight
fi
if [ "$activate_existing" = true ]; then
  "$dir/assert-hoodi-validator-quiesced.sh" --validator-set "$validator_set" >/dev/null
  mkdir -m 700 "$output"
fi
if [ "$bootstrap_complete" = true ]; then
  # The fresh-init branch already configured Vault with its initial root token.
  # The cleanup trap will revoke it after the bootstrap commands complete.
  exit 0
fi
status="$(vault operator generate-root -status -format=json)"
if [ "$(jq -r .started <<<"$status")" = true ]; then
  progress="$(jq -er '.progress // 0' <<<"$status")"
  required_existing="$(jq -er '.required // 0' <<<"$status")"
  printf '\n%s\n' 'A Vault root-token ceremony is already in progress.' >&2
  printf 'Current progress: %s/%s recovery shares.\n' "$progress" "$required_existing" >&2
  printf '%s\n' 'The original ceremony OTP is not recoverable by this script.' >&2
  printf '%s\n' 'Type CANCEL to discard that ceremony and start a new interactive one, or EXIT to leave it untouched.' >&2
  printf 'Action [CANCEL/EXIT]: ' >&2
  IFS= read -r ceremony_action || ceremony_action=''
  case "$ceremony_action" in
    CANCEL)
      vault operator generate-root -cancel >/dev/null
      status="$(vault operator generate-root -status -format=json)"
      [ "$(jq -r .started <<<"$status")" = false ] || { printf '%s\n' 'existing root-token ceremony could not be cancelled' >&2; exit 75; }
      printf '%s\n' 'Existing root-token ceremony cancelled by operator request.' >&2
      ;;
    EXIT|'')
      printf '%s\n' 'Leaving the existing root-token ceremony untouched.' >&2
      exit 75
      ;;
    *)
      printf '%s\n' 'Invalid action; leaving the existing root-token ceremony untouched.' >&2
      exit 64
      ;;
  esac
fi
init="$(vault operator generate-root -init -format=json)"; started=true
nonce="$(jq -er .nonce <<<"$init")"; otp="$(jq -er .otp <<<"$init")"; required="$(jq -er .required <<<"$init")"
for number in $(seq 1 "$required"); do
  printf 'Recovery key share %s of %s: ' "$number" "$required" >&2
  IFS= read -r -s share; printf '\n' >&2
  reply="$(printf %s "$share" | vault operator generate-root -nonce="$nonce" -format=json -)"; unset share
  if [ "$(jq -r .complete <<<"$reply")" = true ]; then
    complete=true; encoded="$(jq -er .encoded_token <<<"$reply")"; break
  fi
done
[ "$complete" = true ] || { printf '%s\n' 'recovery quorum was not reached' >&2; exit 77; }
root="$(vault_recovery_decode_generated_root "$encoded" "$otp")"; unset encoded otp nonce init reply status
[ -n "$root" ] || { printf '%s\n' 'generated root token is empty' >&2; exit 65; }

if [ "$activate_existing" = true ]; then
VAULT_TOKEN="$root" "$dir/activate-hoodi-vault-v2-roles.sh" --validator-set "$validator_set" --preparation-evidence "$preparation" >/dev/null
elif [ "$prepare_existing" = true ]; then
VAULT_TOKEN="$root" "$dir/copy-hoodi-custody-to-runtime-v2.sh" --validator-set "$validator_set" >/dev/null
VAULT_TOKEN="$root" "$dir/bootstrap-hoodi-engine-api-vault.sh" --prepare-only >/dev/null
VAULT_TOKEN="$root" "$dir/prepare-hoodi-vault-v2-transport.sh" --validator-set "$validator_set" --output-dir "$output" >/dev/null
else
VAULT_TOKEN="$root" "$dir/bootstrap-node-operator-vault-v2.sh" >/dev/null
VAULT_TOKEN="$root" "$dir/configure-hoodi-vault-kubernetes-auth.sh" >/dev/null
VAULT_TOKEN="$root" "$dir/bootstrap-hoodi-engine-api-vault.sh" >/dev/null
VAULT_TOKEN="$root" "$dir/bootstrap-hoodi-validator-runtime-vault.sh" --validator-set "$validator_set" >/dev/null
fi
bootstrap_complete=true
