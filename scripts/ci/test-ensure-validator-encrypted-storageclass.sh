#!/usr/bin/env bash
# Check objective: Ensure validator EBS storage is created only when absent and never adopted.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
helper="$root/scripts/ops/ensure-validator-encrypted-storageclass.sh"
template="$root/deploy/validator/storage-class.yaml"
kms='arn:aws:kms:ap-northeast-2:123456789012:key/12345678-1234-1234-1234-123456789abc'
fail() { printf 'FAIL encrypted validator StorageClass: %s\n' "$*" >&2; exit 1; }

test -x "$helper" || fail 'helper is not executable'
for field in \
  '  name: validator-hoodi-gp3-kms' \
  '    app.kubernetes.io/part-of: hoodi-validator' \
  '    node-operator.io/encryption-policy: baseline-ebs-kms' \
  '    node-operator.io/managed-by: validator-staging' \
  '    node-operator.io/storage-profile: validator-hoodi-gp3-kms' \
  'provisioner: ebs.csi.aws.com' '  encrypted: "true"' \
  '  kmsKeyId: REPLACE_WITH_VALIDATOR_HOODI_EBS_KMS_KEY_ARN' '  type: gp3' \
  'volumeBindingMode: WaitForFirstConsumer' 'reclaimPolicy: Retain' \
  'allowVolumeExpansion: true'; do
  grep -Fqx "$field" "$template" || fail "template omits $field"
done

temporary="$(mktemp -d)"
trap 'rm -rf "$temporary"' EXIT
mkdir -p "$temporary/bin"
cat > "$temporary/bin/kubectl" <<'SCRIPT'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "$FAKE_TRACE"
expected="ebs.csi.aws.com|true|$FAKE_KMS|gp3|3|WaitForFirstConsumer|Retain|true|4|hoodi-validator|baseline-ebs-kms|validator-staging|validator-hoodi-gp3-kms"
if [ "${1:-}:${2:-}" = 'get:storageclass' ]; then
  if [ "$FAKE_MODE" = absent ] && [ ! -e "$FAKE_STATE" ]; then exit 0; fi
  if [ "$FAKE_MODE" = read-error ]; then exit 91; fi
  if [ "$FAKE_MODE" = mismatch ]; then printf '%s' "ebs.csi.aws.com|true|$FAKE_KMS|gp3|3|WaitForFirstConsumer|Retain|true|4|hoodi-validator|baseline-ebs-kms|other|validator-hoodi-gp3-kms"; exit 0; fi
  printf '%s' "$expected"; exit 0
fi
if [ "${1:-}:${2:-}" = 'create:-f' ]; then
  [ -f "${3:-}" ] || exit 92
  grep -Fqx '  name: validator-hoodi-gp3-kms' "$3"
  grep -Fqx "  kmsKeyId: $FAKE_KMS" "$3"
  : > "$FAKE_STATE"
  exit 0
fi
exit 93
SCRIPT
chmod 700 "$temporary/bin/kubectl"

run_helper() {
  FAKE_MODE="$1" FAKE_STATE="$temporary/state" FAKE_TRACE="$temporary/trace" FAKE_KMS="$kms" \
    PATH="$temporary/bin:$PATH" "$helper" --template "$template" --kms-key-arn "$kms"
}
reset() { rm -f "$temporary/state" "$temporary/trace"; }

reset
run_helper absent >/dev/null
test -f "$temporary/state" || fail 'absent class was not created'
grep -Fq 'create -f ' "$temporary/trace" || fail 'absent class did not use create'

reset
run_helper matching >/dev/null
if grep -Fq 'create -f ' "$temporary/trace"; then fail 'matching class was mutated'; fi

reset
for mode in mismatch read-error; do
  if run_helper "$mode" >/dev/null 2>&1; then fail "$mode existing class was accepted"; fi
  if grep -Fq 'create -f ' "$temporary/trace"; then fail "$mode class was replaced"; fi
done

printf '%s\n' 'PASS validator encrypted StorageClass create/verify is exact and refuses adoption.'
