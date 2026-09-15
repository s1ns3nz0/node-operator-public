#!/usr/bin/env bash
set +x
set -euo pipefail

# Reads the administrator token only from the terminal. The local snapshot is
# removed on every exit after a verified, encrypted S3 upload.
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
region="${AWS_REGION:-ap-northeast-2}"
bucket="${VAULT_SNAPSHOT_BUCKET:-}"
kms_key="alias/node-operator-baseline-vault-snapshot"

usage() { printf 'Usage: %s [--bucket BUCKET] [--kms-key KMS_KEY]\n' "${0##*/}" >&2; exit 64; }
while [ "$#" -gt 0 ]; do
  case "$1" in
    --bucket) bucket="${2:-}"; shift 2 ;;
    --kms-key)
      kms_key="${2:-}"
      [ -n "$kms_key" ] || { printf '%s\n' '--kms-key requires a non-empty KMS key ID or ARN' >&2; exit 64; }
      shift 2
      ;;
    *) usage ;;
  esac
done
for command in aws vault jq mktemp shasum openssl base64 wc; do
  command -v "$command" >/dev/null 2>&1 || { printf 'missing command: %s\n' "$command" >&2; exit 69; }
done

if [ -z "$bucket" ]; then
  bucket_arn="$(aws resourcegroupstaggingapi get-resources --region "$region" --resource-type-filters s3 --tag-filters Key=Purpose,Values=private-vault-raft-migration-backup --query 'ResourceTagMappingList[].ResourceARN' --output text)"
  case "$bucket_arn" in arn:aws:s3:::*) bucket="${bucket_arn#arn:aws:s3:::}" ;; *) printf 'unable to resolve the unique Vault snapshot bucket; pass --bucket explicitly\n' >&2; exit 65 ;; esac
fi

object_lock="$(aws s3api get-object-lock-configuration --bucket "$bucket" --region "$region" --output json)"
jq -e '.ObjectLockConfiguration.ObjectLockEnabled == "Enabled" and .ObjectLockConfiguration.Rule.DefaultRetention.Mode == "GOVERNANCE" and .ObjectLockConfiguration.Rule.DefaultRetention.Days >= 90' <<<"$object_lock" >/dev/null || { printf 'snapshot bucket does not meet the Object Lock retention boundary\n' >&2; exit 65; }
versioning="$(aws s3api get-bucket-versioning --bucket "$bucket" --region "$region" --output json)"
jq -e '.Status == "Enabled"' <<<"$versioning" >/dev/null || { printf 'snapshot bucket does not have versioning enabled\n' >&2; exit 65; }
expected_kms_key_arn="$(aws kms describe-key --key-id "$kms_key" --region "$region" --output json | jq -er '.KeyMetadata.Arn')"
encryption="$(aws s3api get-bucket-encryption --bucket "$bucket" --region "$region" --output json)"
jq -e --arg kms_key "$expected_kms_key_arn" '.ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault | .SSEAlgorithm == "aws:kms" and .KMSMasterKeyID == $kms_key' <<<"$encryption" >/dev/null || { printf 'snapshot bucket does not enforce the required SSE-KMS key\n' >&2; exit 65; }

snapshot_file="$(mktemp "${TMPDIR:-/tmp}/node-operator-vault-raft.XXXXXX")"
chmod 600 "$snapshot_file"
cleanup() {
  unset VAULT_TOKEN
  [ -z "${snapshot_file:-}" ] || rm -f "$snapshot_file"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
if [ -z "${VAULT_TOKEN:-}" ]; then
  read -r -s -p 'Vault administrator token: ' VAULT_TOKEN
  printf '\n' >&2
fi
export VAULT_TOKEN
"$root/scripts/ops/with-private-vault.sh" -- vault operator raft snapshot save "$snapshot_file"
"$root/scripts/ops/with-private-vault.sh" -- vault operator raft snapshot inspect -format=json "$snapshot_file" >/dev/null

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
object_key="raft-migration/${timestamp}.snap"
checksum_hex="$(shasum -a 256 "$snapshot_file" | awk '{print $1}')"
checksum_b64="$(openssl dgst -sha256 -binary "$snapshot_file" | base64)"
snapshot_bytes="$(wc -c < "$snapshot_file")"
# PutObject is deliberately single-part. It gives S3 one unambiguous full-object
# SHA-256 to verify; snapshots at or above S3's 5 GB single-PUT limit fail closed.
[ "$snapshot_bytes" -gt 0 ] && [ "$snapshot_bytes" -lt 5000000000 ] || { printf 'snapshot size is outside the verified single-PutObject upload boundary\n' >&2; exit 65; }
upload_started_at="$(date -u +%s)"
put_result="$(aws s3api put-object --bucket "$bucket" --key "$object_key" --body "$snapshot_file" --region "$region" --server-side-encryption aws:kms --ssekms-key-id "$kms_key" --checksum-algorithm SHA256 --checksum-sha256 "$checksum_b64" --output json)"
version_id="$(jq -er '.VersionId | strings | select(length > 0 and . != "null")' <<<"$put_result")" || { printf 'snapshot upload did not return an object version ID\n' >&2; exit 65; }
metadata="$(aws s3api head-object --bucket "$bucket" --key "$object_key" --version-id "$version_id" --checksum-mode ENABLED --region "$region" --output json)"
jq -e \
  --arg checksum "$checksum_b64" \
  --arg kms_key "$expected_kms_key_arn" \
  --arg version_id "$version_id" \
  --argjson bytes "$snapshot_bytes" \
  --argjson upload_started_at "$upload_started_at" \
  'def epoch:
     sub("\\.[0-9]+\\+00:00$"; "+00:00")
     | sub("\\.[0-9]+Z$"; "Z")
     | sub("\\+00:00$"; "Z")
     | fromdateiso8601;
   .ServerSideEncryption == "aws:kms"
   and .SSEKMSKeyId == $kms_key
   and .VersionId == $version_id
   and .ChecksumType == "FULL_OBJECT"
   and .ChecksumSHA256 == $checksum
   and .ContentLength == $bytes
   and .ObjectLockMode == "GOVERNANCE"
   and (.ObjectLockRetainUntilDate | type == "string")
   and (.LastModified | type == "string")
   and ((.LastModified | epoch) >= $upload_started_at)
   # S3 may round LastModified to whole seconds while preserving fractional
   # Object Lock retention metadata. Allow only that one-second precision gap.
   and ((.ObjectLockRetainUntilDate | epoch) >= ((.LastModified | epoch) + (90 * 24 * 60 * 60) - 1))' <<<"$metadata" >/dev/null || { printf 'uploaded snapshot does not meet exact encryption, versioning, length, full-object SHA-256, or 90-day configured retention (one-second metadata precision tolerance) boundaries\n' >&2; exit 65; }
printf 'PASS: encrypted immutable Raft snapshot saved as s3://%s/%s (sha256=%s).\n' "$bucket" "$object_key" "$checksum_hex"
