#!/usr/bin/env bash
set -euo pipefail
umask 077

# One-time live migration. It preserves the exact existing Engine JWT and
# validator mTLS material, so an OnDelete/rolling workload restart cannot
# introduce an authentication mismatch. Secret values never reach stdout,
# command-line arguments, Git, or the evidence record.
dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
usage() { printf 'Usage: %s --validator-set <hoodi-id> --evidence-output <new-absolute-json>\n' "${0##*/}" >&2; exit 64; }
validator_set=''; evidence=''
while [ "$#" -gt 0 ]; do
  case "$1" in
    --validator-set) validator_set="${2:-}"; shift 2 ;;
    --evidence-output) evidence="${2:-}"; shift 2 ;;
    *) usage ;;
  esac
done
case "$validator_set:$evidence" in hoodi-[a-z0-9][a-z0-9-]*:/*) ;; *) usage ;; esac
[ ! -e "$evidence" ] && [ ! -L "$evidence" ] || { printf '%s\n' 'evidence output must be a new regular path' >&2; exit 65; }

if [ "${PRIVATE_VAULT_SESSION:-}" != 1 ]; then
  exec "$dir/with-private-vault.sh" -- env PRIVATE_VAULT_SESSION=1 "$0" --validator-set "$validator_set" --evidence-output "$evidence"
fi
if [ "${PRIVATE_EKS_SESSION:-}" != 1 ]; then
  exec "$dir/with-private-eks.sh" -- env PRIVATE_VAULT_SESSION=1 PRIVATE_EKS_SESSION=1 "$0" --validator-set "$validator_set" --evidence-output "$evidence"
fi
for command in vault kubectl jq openssl shasum mktemp find mkdir install seq cut grep python3; do command -v "$command" >/dev/null 2>&1 || { printf 'missing command: %s\n' "$command" >&2; exit 69; }; done

namespace='validator-operations'
engine_namespace='node-operator'
engine_path='kv/nodes/hoodi/engine-api-jwt'
base="kv/validators/hoodi/${validator_set}/runtime"
scratch="$(mktemp -d /private/tmp/node-operator-live-vault-migration.XXXXXX)"
chmod 700 "$scratch"
started=false; complete=false; root_token=''
cleanup() {
  status=$?; trap - EXIT; set +e
  [ -z "$root_token" ] || VAULT_TOKEN="$root_token" vault token revoke -self >/dev/null 2>&1
  [ "$started" = true ] && [ "$complete" != true ] && vault operator generate-root -cancel >/dev/null 2>&1
  find "$scratch" -type f -exec sh -c 'chmod 600 "$1" 2>/dev/null; : > "$1"; rm -f "$1"' sh {} \; 2>/dev/null
  rmdir "$scratch" 2>/dev/null || true
  unset VAULT_TOKEN root_token
  exit "$status"
}
trap cleanup EXIT INT TERM

# Reject partial source state before a recovery ceremony or a Vault write.
engine_json="$(kubectl -n "$engine_namespace" get secret engine-api-jwt -o json)"
signer_json="$(kubectl -n "$namespace" get secret "validator-${validator_set}-signer-tls" -o json)"
client_json="$(kubectl -n "$namespace" get secret "validator-${validator_set}-client-tls" -o json)"
known_json="$(kubectl -n "$namespace" get configmap "validator-${validator_set}-known-clients" -o json)"
jq -e '.data.jwt | type == "string" and test("^[A-Za-z0-9+/=]+$")' <<<"$engine_json" >/dev/null
jq -e '(.data["tls.p12"] | type == "string") and (.data["tls-password.txt"] | type == "string")' <<<"$signer_json" >/dev/null
jq -e '(.data["tls.crt"] | type == "string") and (.data["tls.key"] | type == "string") and (.data["ca.crt"] | type == "string")' <<<"$client_json" >/dev/null
jq -e '.data["known-clients"] | type == "string" and length > 0' <<<"$known_json" >/dev/null

jwt="$(jq -r '.data.jwt | @base64d' <<<"$engine_json")"
[[ "$jwt" =~ ^[0-9a-f]{64}$ ]] || { printf '%s\n' 'existing Engine JWT has an invalid format' >&2; exit 65; }
signer_p12_b64="$(jq -r '.data["tls.p12"]' <<<"$signer_json")"
signer_password="$(jq -r '.data["tls-password.txt"] | @base64d' <<<"$signer_json")"
client_crt_b64="$(jq -r '.data["tls.crt"]' <<<"$client_json")"
client_key_b64="$(jq -r '.data["tls.key"]' <<<"$client_json")"
client_ca_b64="$(jq -r '.data["ca.crt"]' <<<"$client_json")"

# Validate key/certificate relationships without emitting material.
jq -r '.data["tls.crt"] | @base64d' <<<"$client_json" > "$scratch/client.crt"
jq -r '.data["ca.crt"] | @base64d' <<<"$client_json" > "$scratch/ca.crt"
printf '%s' "$signer_password" > "$scratch/signer-password"
jq -r '.data["tls.p12"] | @base64d' <<<"$signer_json" > "$scratch/signer.p12"
openssl verify -CAfile "$scratch/ca.crt" -purpose sslclient "$scratch/client.crt" >/dev/null
openssl pkcs12 -in "$scratch/signer.p12" -passin "file:$scratch/signer-password" -nokeys -noout >/dev/null 2>&1
client_fingerprint="$(openssl x509 -in "$scratch/client.crt" -noout -fingerprint -sha256 | cut -d= -f2)"
known_clients="$(jq -r '.data["known-clients"]' <<<"$known_json")"
grep -Fq "$client_fingerprint" <<<"$known_clients" || { printf '%s\n' 'known-clients ConfigMap does not trust the current client certificate' >&2; exit 65; }

# shellcheck source=scripts/ops/lib/vault-recovery-auth.sh
source "$dir/lib/vault-recovery-auth.sh"
vault_recovery_auth_preflight
status="$(vault operator generate-root -status -format=json)"
[ "$(jq -r .started <<<"$status")" = false ] || { printf '%s\n' 'root-token ceremony already in progress' >&2; exit 75; }
initial="$(vault operator generate-root -init -format=json)"; started=true
nonce="$(jq -er .nonce <<<"$initial")"; otp="$(jq -er .otp <<<"$initial")"; required="$(jq -er .required <<<"$initial")"
for number in $(seq 1 "$required"); do
  printf 'Recovery key share %s of %s: ' "$number" "$required" >&2
  IFS= read -r -s share; printf '\n' >&2
  reply="$(printf %s "$share" | vault operator generate-root -nonce="$nonce" -format=json -)"; unset share
  if [ "$(jq -r .complete <<<"$reply")" = true ]; then complete=true; encoded="$(jq -er .encoded_token <<<"$reply")"; break; fi
done
[ "$complete" = true ] || { printf '%s\n' 'recovery quorum was not reached' >&2; exit 77; }
root_token="$(vault_recovery_decode_generated_root "$encoded" "$otp")"
unset encoded otp nonce initial reply status

# Every deployed Vault Agent template and every least-privilege policy in this
# repository uses KV v2's `/data/` API.  Do not paper over a v1 mount while
# importing credentials: that would make this ceremony appear successful but
# leave the next workload restart unable to read its injected files.
#
# Versioning changes the API for an entire mount.  Before upgrading an older
# mount, reject any policy which still grants a non-v2 `kv/` path.  This makes
# an unknown consumer a visible, fail-closed condition rather than silently
# breaking it during a validator cutover.
kv_mounts="$(VAULT_TOKEN="$root_token" vault secrets list -format=json)"
kv_mount="$(jq -cer '."kv/" // empty' <<<"$kv_mounts")" || { printf '%s\n' 'Vault KV mount kv/ is not enabled' >&2; exit 65; }
jq -e '(.type == "kv") and ((.options.version // "1") | tostring | test("^[12]$"))' <<<"$kv_mount" >/dev/null || {
  printf '%s\n' 'Vault kv/ mount has an unsupported type or version' >&2
  exit 65
}
kv_version="$(jq -r '(.options.version // "1") | tostring' <<<"$kv_mount")"
legacy_kv_policies=()
while IFS= read -r policy_name; do
  [ -n "$policy_name" ] || continue
  policy_rules="$(VAULT_TOKEN="$root_token" vault policy read "$policy_name" 2>/dev/null || true)"
  while IFS= read -r policy_path; do
    case "$policy_path" in
      kv/data/*|kv/metadata/*) ;;
      kv/*) legacy_kv_policies+=("$policy_name"); break ;;
    esac
  done < <(sed -nE 's/^[[:space:]]*path[[:space:]]+"([^"]+)".*/\1/p' <<<"$policy_rules")
done < <(VAULT_TOKEN="$root_token" vault policy list -format=json | jq -er '.[]')

if [ "${#legacy_kv_policies[@]}" -gt 0 ]; then
  printf 'Vault kv/ v1 compatibility policies require review before conversion: %s\n' "$(IFS=,; printf '%s' "${legacy_kv_policies[*]}")" >&2
  exit 65
fi
kv_v1_upgraded=false
if [ "$kv_version" = 1 ]; then
  VAULT_TOKEN="$root_token" vault kv enable-versioning kv/ >/dev/null
  kv_mounts="$(VAULT_TOKEN="$root_token" vault secrets list -format=json)"
  kv_version="$(jq -er '."kv/" | select(.type == "kv") | (.options.version // "1") | tostring | select(. == "2")' <<<"$kv_mounts")" || {
    printf '%s\n' 'Vault kv/ versioning upgrade did not produce KV v2' >&2
    exit 70
  }
  kv_v1_upgraded=true
fi
[ "$kv_version" = 2 ] || { printf '%s\n' 'Vault kv/ must be version 2 for runtime credential injection' >&2; exit 65; }
# The Vault KV convenience read/write wrapper infers a mount version from
# metadata. Do not use it for the import: a partially upgraded legacy mount
# can make that inference disagree with the actual response envelope.
# The v2 configuration endpoint and explicit `/data/` paths are authoritative.
kv_v2_config="$(VAULT_TOKEN="$root_token" vault read -format=json kv/config 2>/dev/null)" || {
  printf '%s\n' 'Vault kv/ does not accept the KV v2 configuration API after versioning' >&2
  exit 70
}
jq -e '.data.max_versions | tonumber? | select(. >= 1)' <<<"$kv_v2_config" >/dev/null || {
  printf '%s\n' 'Vault kv/ KV v2 configuration response is invalid' >&2
  exit 70
}

repaired_records=()
kv_v2_path() {
  case "$1" in
    kv/*) printf 'kv/data/%s' "${1#kv/}" ;;
    *) printf '%s\n' 'invalid KV source path' >&2; exit 65 ;;
  esac
}
put_v2_record() {
  local path="$1" incoming="$2" expected_version="$3" record="$4" api_path payload
  api_path="$(kv_v2_path "$path")"
  payload="$scratch/$record-write.json"
  jq -n --argjson data "$incoming" --argjson version "$expected_version" '{options:{cas:$version},data:$data}' > "$payload"
  VAULT_TOKEN="$root_token" vault write "$api_path" @"$payload" >/dev/null
  : > "$payload"
}
put_or_match() {
  local path="$1" incoming="$2" record="$3" api_path existing existing_data existing_version decoded
  api_path="$(kv_v2_path "$path")"
  if existing="$(VAULT_TOKEN="$root_token" vault read -format=json "$api_path" 2>/dev/null)"; then
    existing_data="$(jq -cer '.data.data' <<<"$existing")"
    existing_version="$(jq -er '.data.metadata.version | select(type == "number" and . >= 1 and floor == .)' <<<"$existing")"
    if [ "$(jq -r 'type' <<<"$existing_data")" = object ]; then
      [ "$(jq -cS . <<<"$existing_data")" = "$(jq -cS . <<<"$incoming")" ] || { printf 'Vault record differs: %s\n' "$record" >&2; exit 65; }
    else
      # A prior partial migration stored the JSON document as a KV string.
      # Repair only when parsing that string proves it is semantically the
      # same source record; divergent values remain fail-closed.
      decoded="$(jq -cer 'if type == "string" then (try fromjson catch null) else null end' <<<"$existing_data")"
      [ "$(jq -cS . <<<"$decoded")" = "$(jq -cS . <<<"$incoming")" ] || { printf 'Vault record differs: %s\n' "$record" >&2; exit 65; }
      put_v2_record "$path" "$incoming" "$existing_version" "$record"
      repaired_records+=("$record")
    fi
  else
    put_v2_record "$path" "$incoming" 0 "$record"
  fi
}

engine_record="$(jq -cn --arg jwt "$jwt" '{jwt:$jwt}')"
signer_record="$(jq -cn --arg pkcs12_b64 "$signer_p12_b64" --arg password "$signer_password" '{pkcs12_b64:$pkcs12_b64,password:$password}')"
client_record="$(jq -cn --arg tls_crt_b64 "$client_crt_b64" --arg tls_key_b64 "$client_key_b64" --arg ca_crt_b64 "$client_ca_b64" '{tls_crt_b64:$tls_crt_b64,tls_key_b64:$tls_key_b64,ca_crt_b64:$ca_crt_b64}')"
put_or_match "$engine_path" "$engine_record" engine
put_or_match "$base/signer-tls" "$signer_record" signer
put_or_match "$base/client-tls" "$client_record" client

# Configure roles only after all records are present, so a newly admitted Pod
# can never observe a missing credential.
VAULT_TOKEN="$root_token" PRIVATE_VAULT_SESSION=1 "$dir/bootstrap-hoodi-engine-api-vault.sh" >/dev/null
VAULT_TOKEN="$root_token" PRIVATE_VAULT_SESSION=1 "$dir/bootstrap-hoodi-validator-runtime-vault.sh" --validator-set "$validator_set" >/dev/null

mkdir -p "$(dirname "$evidence")"
engine_sha="$(printf '%s' "$jwt" | shasum -a 256 | awk '{print $1}')"
signer_sha="$(printf '%s' "$signer_p12_b64" | shasum -a 256 | awk '{print $1}')"
client_sha="$(printf '%s' "$client_crt_b64" | shasum -a 256 | awk '{print $1}')"
evidence_args=(--args)
if [ "${#repaired_records[@]}" -gt 0 ]; then evidence_args+=("${repaired_records[@]}"); fi
jq -n --arg set "$validator_set" --arg engine "$engine_sha" --arg signer "$signer_sha" --arg client "$client_sha" --arg fingerprint "$client_fingerprint" --argjson upgraded "$kv_v1_upgraded" "${evidence_args[@]}" \
  '{schema_version:1,operation:"live-runtime-secret-migration",validator_set:$set,engine_jwt_sha256:$engine,signer_pkcs12_b64_sha256:$signer,client_certificate_b64_sha256:$client,client_fingerprint_sha256:$fingerprint,kv_mount_version:2,kv_v1_upgraded:$upgraded,repaired_legacy_vault_records:$ARGS.positional,secret_values_emitted:false,source_secrets_retained:true}' > "$evidence"
chmod 600 "$evidence"
unset jwt signer_p12_b64 signer_password client_crt_b64 client_key_b64 client_ca_b64 engine_record signer_record client_record known_clients
printf 'PASS: existing Engine JWT and validator transport records now match Vault; Kubernetes source Secrets remain for staged cutover. Evidence: %s\n' "$evidence"
