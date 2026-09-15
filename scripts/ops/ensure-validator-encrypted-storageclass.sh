#!/usr/bin/env bash
# Create only an absent, exact validator EBS CSI StorageClass. Existing classes
# are verification-only: this helper never adopts, replaces, deletes, or migrates storage.
set -euo pipefail

usage() {
  printf '%s\n' 'usage: ensure-validator-encrypted-storageclass.sh --template ABSOLUTE_FILE --kms-key-arn ARN' >&2
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

expected="ebs.csi.aws.com|true|$kms_key_arn|gp3|3|WaitForFirstConsumer|Retain|true|4|hoodi-validator|baseline-ebs-kms|validator-staging|validator-hoodi-gp3-kms"
class_fields() {
  kubectl get storageclass validator-hoodi-gp3-kms --ignore-not-found \
    -o go-template='{{.provisioner}}|{{index .parameters "encrypted"}}|{{index .parameters "kmsKeyId"}}|{{index .parameters "type"}}|{{len .parameters}}|{{.volumeBindingMode}}|{{.reclaimPolicy}}|{{.allowVolumeExpansion}}|{{len .metadata.labels}}|{{index .metadata.labels "app.kubernetes.io/part-of"}}|{{index .metadata.labels "node-operator.io/encryption-policy"}}|{{index .metadata.labels "node-operator.io/managed-by"}}|{{index .metadata.labels "node-operator.io/storage-profile"}}'
}
verify_class() {
  local actual
  actual="$(class_fields)" || { printf '%s\n' 'unable to read validator-hoodi-gp3-kms StorageClass' >&2; exit 65; }
  [ "$actual" = "$expected" ] || {
    printf '%s\n' 'existing validator-hoodi-gp3-kms StorageClass is not the required EBS CSI/KMS configuration; refusing replacement' >&2
    exit 65
  }
}

umask 077
rendered="$(mktemp /tmp/node-operator-validator-storageclass.XXXXXX)"
trap 'rm -f "$rendered"' EXIT
escaped_kms_key="$(printf '%s' "$kms_key_arn" | sed 's/[\\&|]/\\&/g')"
sed "s|REPLACE_WITH_VALIDATOR_HOODI_EBS_KMS_KEY_ARN|$escaped_kms_key|g" "$template" > "$rendered"
grep -Fq 'REPLACE_WITH_VALIDATOR_HOODI_EBS_KMS_KEY_ARN' "$rendered" && { printf '%s\n' 'StorageClass template placeholder was not rendered' >&2; exit 65; }

existing="$(class_fields)" || { printf '%s\n' 'unable to read validator-hoodi-gp3-kms StorageClass' >&2; exit 65; }
if [ -n "$existing" ]; then
  verify_class
else
  # `create`, not `apply`, prevents field adoption or replacement. A racing
  # creator is acceptable only if its resulting class passes exact validation.
  kubectl create -f "$rendered" >/dev/null 2>&1 || verify_class
  verify_class
fi

printf '%s\n' 'PASS: validator-hoodi-gp3-kms StorageClass matches the CMK-bound deployment policy.' >&2
