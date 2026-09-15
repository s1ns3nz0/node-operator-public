#!/usr/bin/env bash
set -euo pipefail
set +x
umask 077
# Recovery-key, one-time custody ceremony. No secret is printed or retained.
dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
usage(){ printf 'Usage: %s --validator-set <hoodi-id> --keystore-dir <absolute-dir> --signer-ca-output <absolute-pem> --known-clients-output <absolute-file> [--expected-public-key 0x<96-hex>] [--result-output <absolute-file> --operation-id <32-lower-hex>] [--refresh-auth-only]\n' "${0##*/}" >&2; exit 64; }
set_id=''; key_dir=''; ca_out=''; known_out=''; expected_public_key=''; result_output=''; operation_id=''; refresh_auth_only=false
while [ "$#" -gt 0 ]; do case "$1" in --validator-set) set_id="${2:-}"; shift 2;; --keystore-dir) key_dir="${2:-}"; shift 2;; --signer-ca-output) ca_out="${2:-}"; shift 2;; --known-clients-output) known_out="${2:-}"; shift 2;; --expected-public-key) expected_public_key="${2:-}"; shift 2;; --result-output) result_output="${2:-}"; shift 2;; --operation-id) operation_id="${2:-}"; shift 2;; --refresh-auth-only) refresh_auth_only=true; shift;; *) usage;; esac; done
case "$set_id" in hoodi-[a-z0-9][a-z0-9-]*) ;; *) usage;; esac; case "$key_dir:$ca_out:$known_out" in /*:/*:/*) ;; *) usage;; esac
if [ -n "$result_output$operation_id" ]; then
  case "$result_output" in /*) ;; *) usage;; esac
  [[ "$operation_id" =~ ^[0-9a-f]{32}$ ]] || usage
  [ "$refresh_auth_only" = false ] || usage
  result_name="${result_output##*/}"; case "$result_name" in ''|.|..) usage;; esac
  result_parent="${result_output%/*}"; [ -n "$result_parent" ] || result_parent=/
  result_parent="$(cd "$result_parent" && pwd -P)" || { printf '%s\n' 'custody completion receipt parent is unavailable or unsafe' >&2; exit 64; }
  [ "$(find "$result_parent" -prune -type d -perm 700 -print)" = "$result_parent" ] || { printf '%s\n' 'custody completion receipt parent is unavailable or unsafe' >&2; exit 64; }
  result_output="$result_parent/$result_name"
  [ ! -e "$result_output" ] && [ ! -L "$result_output" ] || { printf '%s\n' 'custody completion receipt target already exists or is unsafe' >&2; exit 64; }
else
  result_parent=''
fi
if [ "${PRIVATE_VAULT_SESSION:-}" != 1 ]; then
  retry_args=(--validator-set "$set_id" --keystore-dir "$key_dir" --signer-ca-output "$ca_out" --known-clients-output "$known_out")
  [ -z "$expected_public_key" ] || retry_args+=(--expected-public-key "$expected_public_key")
  [ -z "$result_output" ] || retry_args+=(--result-output "$result_output" --operation-id "$operation_id")
  [ "$refresh_auth_only" = false ] || retry_args+=(--refresh-auth-only)
  exec "$dir/with-private-vault.sh" -- env PRIVATE_VAULT_SESSION=1 "$0" "${retry_args[@]}"
fi
for x in vault jq openssl base64 find mktemp; do command -v "$x" >/dev/null || { printf 'missing command: %s\n' "$x" >&2; exit 69; }; done
keys=(); while IFS= read -r key; do keys+=("$key"); done < <(find "$key_dir" -maxdepth 1 -type f -name 'keystore-*.json' -print); [ "${#keys[@]}" = 1 ] || { printf 'expected exactly one keystore JSON\n' >&2; exit 64; }
if [ "$refresh_auth_only" = false ]; then
  [[ "$expected_public_key" =~ ^0x[0-9a-fA-F]{96}$ ]] || { printf '%s\n' 'validated expected validator public key is required for custody convergence' >&2; exit 64; }
  expected_public_key="$(printf '%s' "$expected_public_key" | tr '[:upper:]' '[:lower:]')"
  verifier_python="${CUSTODY_VERIFIER_PYTHON:-}"; verifier_upstream="${CUSTODY_VERIFIER_UPSTREAM_ROOT:-}"
  [ -n "$verifier_python" ] && [ -x "$verifier_python" ] && [ "${verifier_python#/}" != "$verifier_python" ] || { printf '%s\n' 'custody crypto verifier runtime is unavailable; complete the custody preflight before starting the recovery ceremony' >&2; exit 69; }
  [ -n "$verifier_upstream" ] && [ -d "$verifier_upstream" ] && [ ! -L "$verifier_upstream" ] && [ "${verifier_upstream#/}" != "$verifier_upstream" ] || { printf '%s\n' 'custody crypto verifier source context is unavailable; complete the custody preflight before starting the recovery ceremony' >&2; exit 69; }
  secret_verifier="$dir/verify-custody-keystore-secret.py"
  transport_verifier="$dir/verify-hoodi-vault-v2-transport-records.sh"
  [ -x "$secret_verifier" ] && [ -x "$transport_verifier" ] || { printf '%s\n' 'release bundle lacks required custody verification helpers; complete the custody preflight before starting the recovery ceremony' >&2; exit 69; }
fi
tmp_parent="${TMPDIR:-/tmp}"
case "$tmp_parent" in /*) ;; *) printf '%s\n' 'temporary directory must be absolute' >&2; exit 64;; esac
[ -d "$tmp_parent" ] || { printf '%s\n' 'temporary directory is unavailable' >&2; exit 69; }
tmp="$(mktemp -d "$tmp_parent/node-operator-hoodi-onboard.XXXXXX")"; chmod 700 "$tmp"
tmp_files=("$tmp/tls.key" "$tmp/server.crt" "$tmp/server.key" "$tmp/server.p12" "$tmp/ca.crt" "$tmp/client.key" "$tmp/client.crt" "$tmp/tls.p12" "$tmp/keystore-password" "$tmp/slashing-db-password" "$tmp/tls.json" "$tmp/client-tls.json" "$tmp/candidate-keystore" "$tmp/candidate-password" "$tmp/new-key-password" "$tmp/new-tls-password" "$tmp/signer-pkcs12.b64" "$tmp/client-crt.b64" "$tmp/client-key.b64" "$tmp/client-ca.b64" "$tmp/cert-public" "$tmp/key-public" "$tmp/password")
for temporary_record in keystore password slashing-db-password signer-tls client-tls; do tmp_files+=("$tmp/$temporary_record.raw" "$tmp/$temporary_record.read-error" "$tmp/$temporary_record.json"); done
tmp_dirs=("$tmp/candidate-public" "$tmp/winner-public" "$tmp/verified-public")
for temporary_dir in "${tmp_dirs[@]}"; do tmp_files+=("$temporary_dir/signer-ca.crt" "$temporary_dir/known-clients.txt"); done
started=false; complete=false; root=''; child=''; operation_complete=false; success_message=''
write_completion_receipt(){
  [ -n "$result_output" ] || return 0
  local result_tmp='' signer_ca_sha256='' known_clients_sha256='' digest=''
  for output in "$ca_out" "$known_out"; do
    [ -f "$output" ] && [ ! -L "$output" ] || return 1
  done
  digest="$(openssl dgst -sha256 -r "$ca_out")" || return 1
  signer_ca_sha256="${digest%% *}"
  digest="$(openssl dgst -sha256 -r "$known_out")" || return 1
  known_clients_sha256="${digest%% *}"
  [[ "$signer_ca_sha256" =~ ^[0-9a-f]{64}$ && "$known_clients_sha256" =~ ^[0-9a-f]{64}$ ]] || return 1
  result_tmp="$(mktemp "$result_parent/.hoodi-custody-completion.XXXXXX")" || return 1
  chmod 600 "$result_tmp" || { unlink "$result_tmp" || true; return 1; }
  printf '{"expected_public_key":"%s","operation_id":"%s","public_outputs":{"known_clients_sha256":"%s","signer_ca_sha256":"%s"},"result":"onboarding-complete","schema_version":1,"validator_set":"%s"}\n' "$expected_public_key" "$operation_id" "$known_clients_sha256" "$signer_ca_sha256" "$set_id" > "$result_tmp" || { unlink "$result_tmp" || true; return 1; }
  if ln "$result_tmp" "$result_output"; then
    unlink "$result_tmp" || return 1
    return 0
  fi
  unlink "$result_tmp" || true
  return 1
}
cleanup(){
  local rc=$?
  trap - EXIT INT TERM HUP
  set +e
  if [ -n "$child" ] && ! VAULT_TOKEN="$root" vault token revoke "$child" >/dev/null 2>&1; then
    printf '%s\n' 'CRITICAL: temporary onboarding token revocation could not be confirmed.' >&2
    [ "$rc" -ne 0 ] || rc=70
  fi
  if [ -n "$root" ] && ! VAULT_TOKEN="$root" vault token revoke -self >/dev/null 2>&1; then
    printf '%s\n' 'CRITICAL: generated root token revocation could not be confirmed.' >&2
    [ "$rc" -ne 0 ] || rc=70
  fi
  if [ "$started" = true ] && [ "$complete" != true ]; then
    printf '%s\n' 'The generated root-token ceremony remains pending; review it and explicitly CANCEL it before starting a new ceremony.' >&2
  fi
  for temporary_file in "${tmp_files[@]}"; do
    [ ! -e "$temporary_file" ] && [ ! -L "$temporary_file" ] && continue
    if ! unlink "$temporary_file"; then
      printf '%s\n' 'CRITICAL: private ceremony scratch cleanup could not be confirmed.' >&2
      [ "$rc" -ne 0 ] || rc=70
    fi
  done
  for temporary_dir in "${tmp_dirs[@]}"; do
    [ ! -e "$temporary_dir" ] && [ ! -L "$temporary_dir" ] && continue
    if ! rmdir "$temporary_dir"; then
      printf '%s\n' 'CRITICAL: private ceremony scratch directory cleanup could not be confirmed.' >&2
      [ "$rc" -ne 0 ] || rc=70
    fi
  done
  if ! rmdir "$tmp"; then
    printf '%s\n' 'CRITICAL: private ceremony scratch directory cleanup could not be confirmed.' >&2
    [ "$rc" -ne 0 ] || rc=70
  fi
  if [ "$rc" -eq 0 ] && [ "$operation_complete" = true ] && ! write_completion_receipt; then
    printf '%s\n' 'CRITICAL: custody completion receipt could not be safely published.' >&2
    rc=70
  fi
  unset root child VAULT_TOKEN
  if [ "$rc" -eq 0 ] && [ "$operation_complete" = true ]; then
    printf '%s\n' "$success_message"
  fi
  exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP
# shellcheck source=scripts/ops/lib/vault-recovery-auth.sh
source "$dir/lib/vault-recovery-auth.sh"
vault_recovery_auth_preflight
status="$(vault operator generate-root -status -format=json)"
if [ "$(jq -r .started <<<"$status")" = true ]; then
  progress="$(jq -er '.progress // 0' <<<"$status")"
  required_existing="$(jq -er '.required // 0' <<<"$status")"
  printf '\n╭────────────────────────────────────────────────────────────╮\n' >&2
  printf '│ 🔁 EXISTING ROOT-TOKEN CEREMONY DETECTED                  │\n' >&2
  printf '╰────────────────────────────────────────────────────────────╯\n' >&2
  printf '%s\n' 'This is not Vault first-run initialization; a previous generate-root ceremony is pending.' >&2
  printf 'Current progress: %s/%s recovery shares.\n' "$progress" "$required_existing" >&2
  printf '%s\n' 'Type CANCEL to discard it and start a new interactive ceremony, or EXIT to leave it untouched.' >&2
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
printf '\n╭────────────────────────────────────────────────────────────╮\n' >&2
printf '│ 🔐 VAULT ADMIN RECOVERY CEREMONY                          │\n' >&2
printf '╰────────────────────────────────────────────────────────────╯\n' >&2
printf '%s\n' 'This ceremony creates a temporary administrator token from recovery shares.' >&2
printf '%s\n' 'It does not initialize Vault and does not produce unseal keys.' >&2
printf '%s\n' 'Each share is requested once and never echoed.' >&2
if ! init="$(vault operator generate-root -init -format=json)"; then
  pending_status="$(vault operator generate-root -status -format=json 2>/dev/null || true)"
  if jq -e '.started == true' <<<"$pending_status" >/dev/null 2>&1; then
    printf '%s\n' 'Root-token ceremony status is pending after an initialization error; leaving it untouched.' >&2
    exit 75
  fi
  printf '%s\n' 'Could not start a root-token ceremony.' >&2
  exit 70
fi
started=true
nonce="$(jq -er .nonce <<<"$init")"; otp="$(jq -er .otp <<<"$init")"; required="$(jq -er .required <<<"$init")"
printf 'Recovery policy: %s shares required for this ceremony.\n' "$required" >&2
for n in $(seq 1 "$required"); do
  printf 'Recovery key share %s of %s: ' "$n" "$required" >&2
  if ! IFS= read -r -s share; then
    printf '\n%s\n' 'Recovery share input ended; leaving the generated root-token ceremony pending.' >&2
    exit 75
  fi
  printf '\n' >&2
  [ -n "$share" ] || { unset share; printf '%s\n' 'Empty recovery share; leaving the generated root-token ceremony pending.' >&2; exit 75; }
  reply="$(printf %s "$share" | vault operator generate-root -nonce="$nonce" -format=json -)"
  unset share
  if [ "$(jq -r .complete <<<"$reply")" = true ]; then complete=true; encoded="$(jq -er .encoded_token <<<"$reply")"; break; fi
done
[ "$complete" = true ] || { printf 'recovery quorum was not reached\n' >&2; exit 77; }
root="$(vault_recovery_decode_generated_root "$encoded" "$otp")"; unset encoded otp nonce init reply status
[ -n "$root" ] || { printf '%s\n' 'generated root token is empty' >&2; exit 65; }

# Delegate to the one canonical server-local reviewer configuration. Existing
# mounts that contain an explicit CA or reviewer token fail closed there and
# require a reviewed migration; this custody ceremony never repoints them.
auth_helper="$dir/configure-hoodi-vault-kubernetes-auth.sh"
[ -x "$auth_helper" ] || { printf '%s\n' 'missing canonical Vault Kubernetes auth configurator' >&2; exit 69; }
VAULT_TOKEN="$root" "$auth_helper"
printf '%s\n' 'Kubernetes Auth server-local reviewer configuration was verified without a stored reviewer token.' >&2
if [ "$refresh_auth_only" = true ]; then
  operation_complete=true
  success_message='PASS: Kubernetes Auth refresh-only ceremony completed; no custody records were changed.'
  exit 0
fi
base="node-operator-runtime/validators/hoodi/$set_id/runtime"
physical_base="${base%%/*}/data/${base#*/}"
records=(keystore password slashing-db-password signer-tls client-tls)

# Read each record once as data, treating only Vault's documented missing-value
# response as absence. Authorization, transport and decoding failures are never
# permission to generate a replacement.
read_record() {
  local record="$1"
  local path="$base/$record"
  local physical_path="$physical_base/$record"
  local error="$tmp/$record.read-error"
  local status
  [ ! -e "$tmp/$record.json" ] && [ ! -L "$tmp/$record.json" ] || unlink "$tmp/$record.json" || { printf 'private custody scratch cleanup could not be confirmed\n' >&2; exit 70; }
  if VAULT_TOKEN="$root" vault kv get -format=json "$path" > "$tmp/$record.raw" 2>"$error"; then
    jq -e '.data.data | select(type == "object")' "$tmp/$record.raw" > "$tmp/$record.json" || { printf 'stored custody record is malformed: %s\n' "$record" >&2; exit 65; }
    eval "present_${record//-/_}=true"
    return 0
  else
    status=$?
  fi
  [ "$status" -eq 2 ] && [ "$(<"$error")" = "No value found at $physical_path" ] || { printf 'stored custody record could not be read: %s\n' "$record" >&2; exit 69; }
  eval "present_${record//-/_}=false"
}
read_all_records() { for record in "${records[@]}"; do read_record "$record"; done; }
record_present() { local name="present_${1//-/_}"; eval "printf '%s' \"\${$name}\""; }
require_all_records() { for record in "${records[@]}"; do [ "$(record_present "$record")" = true ] || { printf 'custody record is missing after reconciliation: %s\n' "$record" >&2; exit 69; }; done; }

candidate_keystore_file="$tmp/candidate-keystore"; candidate_password_file="$tmp/candidate-password"
validate_candidate() {
  local public_dir="$1"
  jq -e 'type == "object" and (keys | sort == ["keystore"]) and (.keystore | type == "string" and length > 0)' "$tmp/keystore.json" >/dev/null || { printf '%s\n' 'stored keystore record is malformed' >&2; exit 65; }
  jq -e 'type == "object" and (keys | sort == ["password"]) and (.password | type == "string" and length > 0)' "$tmp/password.json" >/dev/null || { printf '%s\n' 'stored keystore password record is malformed' >&2; exit 65; }
  jq -e 'type == "object" and (keys | sort == ["password"]) and (.password | type == "string" and length > 0)' "$tmp/slashing-db-password.json" >/dev/null || { printf '%s\n' 'stored slashing database password record is malformed' >&2; exit 65; }
  jq -jr '.keystore' "$tmp/keystore.json" > "$candidate_keystore_file"
  jq -jr '.password' "$tmp/password.json" > "$candidate_password_file"
  chmod 600 "$candidate_keystore_file" "$candidate_password_file"
  "$verifier_python" -I "$secret_verifier" --upstream-root "$verifier_upstream" --keystore-file "$candidate_keystore_file" --password-file "$candidate_password_file" --expected-public-key "$expected_public_key" >/dev/null || { printf '%s\n' 'stored custody keystore/password does not match the selected validator public key' >&2; exit 65; }
  "$transport_verifier" --validator-set "$set_id" --signer-record "$tmp/signer-tls.json" --client-record "$tmp/client-tls.json" --scratch-dir "$tmp" --output-dir "$public_dir"
}

read_all_records
all_present=true
for record in "${records[@]}"; do [ "$(record_present "$record")" = true ] || all_present=false; done
if [ "$all_present" = true ]; then
  validate_candidate "$tmp/verified-public"
  install -d -m 700 "$(dirname "$ca_out")" "$(dirname "$known_out")"
  install -m 644 "$tmp/verified-public/signer-ca.crt" "$ca_out"
  install -m 644 "$tmp/verified-public/known-clients.txt" "$known_out"
  operation_complete=true
  success_message="PASS: existing Hoodi custody records were coherently verified for $set_id; public CA reconstructed at $ca_out."
  exit 0
fi

VAULT_TOKEN="$root" "$dir/bootstrap-node-operator-vault-v2.sh" >/dev/null
VAULT_TOKEN="$root" "$dir/bootstrap-hoodi-validator-runtime-vault.sh" --validator-set "$set_id" >/dev/null

if [ "$(record_present keystore)" = false ]; then jq -n --rawfile keystore "${keys[0]}" '{keystore:$keystore}' > "$tmp/keystore.json"; fi
if [ "$(record_present password)" = false ]; then
  printf 'Keystore password: ' >&2; IFS= read -r -s key_password; printf '\n' >&2
  [ -n "$key_password" ] || { printf 'empty keystore password is not allowed\n' >&2; exit 64; }
  printf %s "$key_password" > "$tmp/new-key-password"; unset key_password
  jq -n --rawfile password "$tmp/new-key-password" '{password:$password}' > "$tmp/password.json"
fi
if [ "$(record_present slashing-db-password)" = false ]; then openssl rand -base64 48 | tr -d '\n' | jq -R '{password:.}' > "$tmp/slashing-db-password.json"; fi
if [ "$(record_present signer-tls)" = false ] || [ "$(record_present client-tls)" = false ]; then
  openssl rand -base64 48 | tr -d '\n' > "$tmp/new-tls-password"; service="validator-$set_id-remote-signer"
  if [ "$(record_present signer-tls)" = false ]; then
    server_issue="$(VAULT_TOKEN="$root" vault write -format=json node-operator-pki/issue/validator-mtls common_name="$service.validator-operations.svc" alt_names="$service.validator-operations.svc,$service.validator-operations.svc.cluster.local" ttl=720h)"
    jq -er '.data.private_key' <<<"$server_issue" > "$tmp/tls.key"; jq -er '.data.certificate' <<<"$server_issue" > "$tmp/server.crt"; jq -er '(.data.ca_chain[0] // .data.issuing_ca)' <<<"$server_issue" > "$tmp/ca.crt"
    openssl pkcs12 -export -out "$tmp/tls.p12" -inkey "$tmp/tls.key" -in "$tmp/server.crt" -certfile "$tmp/ca.crt" -passout "file:$tmp/new-tls-password" >/dev/null 2>&1
    base64 < "$tmp/tls.p12" | tr -d '\n' > "$tmp/signer-pkcs12.b64"
    jq -n --rawfile p12 "$tmp/signer-pkcs12.b64" --rawfile password "$tmp/new-tls-password" '{pkcs12_b64:$p12,password:$password}' > "$tmp/signer-tls.json"
  fi
  if [ "$(record_present client-tls)" = false ]; then
    client_issue="$(VAULT_TOKEN="$root" vault write -format=json node-operator-pki/issue/validator-mtls common_name="validator-$set_id-client.validator-operations.svc" ttl=720h)"
    jq -er '.data.private_key' <<<"$client_issue" > "$tmp/client.key"; jq -er '.data.certificate' <<<"$client_issue" > "$tmp/client.crt"
    [ -s "$tmp/ca.crt" ] || jq -er '(.data.ca_chain[0] // .data.issuing_ca)' <<<"$client_issue" > "$tmp/ca.crt"
    jq -n --rawfile cert <(base64 < "$tmp/client.crt" | tr -d '\n') --rawfile key <(base64 < "$tmp/client.key" | tr -d '\n') --rawfile ca <(base64 < "$tmp/ca.crt" | tr -d '\n') '{tls_crt_b64:$cert,tls_key_b64:$key,ca_crt_b64:$ca}' > "$tmp/client-tls.json"
  fi
  unset server_issue client_issue
fi

# Before create-only writes, validate the composed candidate. Existing values
# remain untouched; no ciphertext equality with the local source is required.
validate_candidate "$tmp/candidate-public"
child="$(VAULT_TOKEN="$root" vault token create -orphan -no-default-policy -policy="hoodi-$set_id-onboarding" -ttl=10m -field=token)"
put_if_absent() {
  local record="$1" path="$base/$record"
  [ "$(record_present "$record")" = false ] || return 0
  if ! VAULT_TOKEN="$child" vault kv put -cas=0 "$path" @"$tmp/$record.json" >/dev/null 2>&1; then
    VAULT_TOKEN="$root" vault kv get -format=json "$path" >/dev/null 2>&1 || { printf 'custody record create race could not be reconciled: %s\n' "$record" >&2; exit 69; }
  fi
}
for record in "${records[@]}"; do put_if_absent "$record"; done

# Always re-read and validate the complete winner after CAS=0 writes/races.
read_all_records
require_all_records
validate_candidate "$tmp/winner-public"
install -d -m 700 "$(dirname "$ca_out")" "$(dirname "$known_out")"
install -m 644 "$tmp/winner-public/signer-ca.crt" "$ca_out"
install -m 644 "$tmp/winner-public/known-clients.txt" "$known_out"
operation_complete=true
success_message="PASS: Hoodi custody records were coherently reconciled for $set_id; public CA reconstructed at $ca_out."
