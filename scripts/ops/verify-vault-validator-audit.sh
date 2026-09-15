#!/usr/bin/env bash
set -euo pipefail

# Read-only, fail-closed verification of the post-initialization Vault audit
# ceremony. VAULT_TOKEN is supplied by the approved operator environment and
# is never read from arguments or printed by this script.
for command in vault jq kubectl; do
  command -v "$command" >/dev/null 2>&1 || { printf 'missing command: %s\n' "$command" >&2; exit 69; }
done
: "${VAULT_ADDR:?VAULT_ADDR must target the private Vault endpoint}"
: "${VAULT_TOKEN:?VAULT_TOKEN must be supplied by the approved Vault administrator environment}"

vault_namespace="${VAULT_NAMESPACE:-vault}"
statefulset="$(kubectl -n "$vault_namespace" get statefulset vault -o json)"
replicas="$(jq -er '.spec.replicas // 1' <<<"$statefulset")"

jq -e '
  any(.spec.volumeClaimTemplates[]?; .metadata.name == "audit") and
  any(.spec.template.spec.containers[]? | select(.name == "vault").volumeMounts[]?; .name == "audit" and .mountPath == "/vault/audit")
' <<<"$statefulset" >/dev/null || {
  printf 'FAIL: Vault lacks the required separate audit PVC/mount; do not enable validator duties.\n' >&2
  exit 65
}

for ordinal in $(seq 0 $((replicas - 1))); do
  claim="audit-vault-${ordinal}"
  kubectl -n "$vault_namespace" get pvc "$claim" -o json |
    jq -e '.status.phase == "Bound" and .spec.storageClassName == "gp3-encrypted"' >/dev/null || {
      printf 'FAIL: required encrypted audit PVC is not Bound: %s\n' "$claim" >&2
      exit 65
    }
done

audit_devices="$(vault audit list -format=json)"
jq -e '
  .["validator-file/"]?.type == "file" and
  .["validator-socket/"]?.type == "socket" and
  .["validator-file/"].options.log_raw != "true" and
  .["validator-socket/"].options.log_raw != "true" and
  .["validator-file/"].options.elide_list_responses == "true" and
  .["validator-socket/"].options.elide_list_responses == "true" and
  .["validator-file/"].options.file_path == "/vault/audit/validator-audit.json" and
  .["validator-socket/"].options.address == "/vault/audit/validator-audit.sock" and
  .["validator-socket/"].options.socket_type == "unix"
' <<<"$audit_devices" >/dev/null || {
  printf 'FAIL: required Vault validator audit devices/options are missing or unsafe; do not enable validator duties.\n' >&2
  exit 65
}
printf 'PASS: encrypted Vault audit PVCs and file/local-socket audit devices are configured with raw logging disabled.\n'
