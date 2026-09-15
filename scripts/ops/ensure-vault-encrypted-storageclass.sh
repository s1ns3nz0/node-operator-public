#!/usr/bin/env bash
# Create only an absent, exact Vault EBS CSI StorageClass.  Existing classes
# and PVCs are verification-only: this helper never adopts, replaces, deletes,
# or migrates storage.
set -euo pipefail

usage() {
  printf '%s\n' 'usage: ensure-vault-encrypted-storageclass.sh --template ABSOLUTE_FILE --kms-key-arn ARN' >&2
  exit 64
}

template=''
kms_key_arn=''
while [ "$#" -gt 0 ]; do
  case "$1" in
    --template) template="${2:-}"; shift 2 ;;
    --kms-key-arn) kms_key_arn="${2:-}"; shift 2 ;;
    *) usage ;;
  esac
done

case "$template" in /*) ;; *) usage ;; esac
case "$kms_key_arn" in arn:aws:kms:[a-z0-9-]*:[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]:key/*) ;; *) usage ;; esac
[ -f "$template" ] && [ ! -L "$template" ] || { printf '%s\n' 'StorageClass template must be a regular non-symlink file' >&2; exit 65; }
command -v kubectl >/dev/null || { printf '%s\n' 'missing command: kubectl' >&2; exit 69; }

expected="ebs.csi.aws.com|true|$kms_key_arn|gp3|3|WaitForFirstConsumer|Retain|true|vault-bootstrap|gp3-encrypted"
class_fields() {
  kubectl get storageclass gp3-encrypted --ignore-not-found \
    -o go-template='{{.provisioner}}|{{index .parameters "encrypted"}}|{{index .parameters "kmsKeyId"}}|{{index .parameters "type"}}|{{len .parameters}}|{{.volumeBindingMode}}|{{.reclaimPolicy}}|{{.allowVolumeExpansion}}|{{index .metadata.labels "node-operator.io/managed-by"}}|{{index .metadata.labels "node-operator.io/storage-profile"}}'
}
verify_class() {
  local actual
  actual="$(class_fields)" || { printf '%s\n' 'unable to read gp3-encrypted StorageClass' >&2; exit 65; }
  [ "$actual" = "$expected" ] || {
    printf '%s\n' 'existing gp3-encrypted StorageClass is not the required EBS CSI/KMS configuration; refusing replacement' >&2
    exit 65
  }
}

umask 077
rendered="$(mktemp /tmp/node-operator-vault-storageclass.XXXXXX)"
trap 'rm -f "$rendered"' EXIT
escaped_kms_key="$(printf '%s' "$kms_key_arn" | sed 's/[\\&|]/\\&/g')"
sed "s|REPLACE_WITH_VAULT_EBS_KMS_KEY_ARN|$escaped_kms_key|g" "$template" > "$rendered"
grep -Fq 'REPLACE_WITH_VAULT_EBS_KMS_KEY_ARN' "$rendered" && { printf '%s\n' 'StorageClass template placeholder was not rendered' >&2; exit 65; }

existing="$(class_fields)" || { printf '%s\n' 'unable to read gp3-encrypted StorageClass' >&2; exit 65; }
if [ -n "$existing" ]; then
  [ "$existing" = "$expected" ] || {
    printf '%s\n' 'existing gp3-encrypted StorageClass is not the required EBS CSI/KMS configuration; refusing replacement' >&2
    exit 65
  }
else
  # `create`, not `apply`, prevents field adoption or replacement.  A racing
  # creator is acceptable only if its resulting class passes exact validation.
  kubectl create -f "$rendered" >/dev/null 2>&1 || verify_class
  verify_class
fi

# Fresh deployments have no claims.  Every retained Vault data/audit claim,
# including a claim from a prior larger replica count, must already bind the
# reviewed class; changing it would require an explicit migration.
claims="$(kubectl -n vault get pvc --ignore-not-found -o go-template='{{range .items}}{{.metadata.name}}|{{.spec.storageClassName}}{{"\n"}}{{end}}')" || {
  printf '%s\n' 'unable to list existing Vault PVCs' >&2
  exit 65
}
while IFS='|' read -r claim actual_class; do
  case "$claim" in
    data-vault-[0-9]*|audit-vault-[0-9]*)
      [ "$actual_class" = gp3-encrypted ] || {
        printf '%s\n' "existing Vault PVC requires migration and is not gp3-encrypted: $claim" >&2
        exit 65
      }
      ;;
    *) ;;
  esac
done <<< "$claims"

printf '%s\n' 'PASS: gp3-encrypted StorageClass and any retained Vault PVC declarations match the CMK-bound deployment policy.' >&2
