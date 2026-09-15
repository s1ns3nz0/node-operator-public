#!/usr/bin/env bash
# Check objective: Ensure a fresh Vault install uses only the reviewed CMK-bound EBS CSI class without adopting retained or foreign storage.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
helper="$root/scripts/ops/ensure-vault-encrypted-storageclass.sh"
template="$root/docs/gitops/vault-gp3-encrypted-storageclass.yaml"
bootstrap="$root/infra/terraform/vault-bootstrap.tf"
kms='arn:aws:kms:ap-northeast-2:123456789012:key/12345678-1234-1234-1234-123456789abc'
fail() { printf 'FAIL encrypted Vault StorageClass: %s\n' "$*" >&2; exit 1; }

test -x "$helper" || fail 'helper is not executable'
test -f "$template" || fail 'StorageClass template is missing'
for field in \
  'apiVersion: storage.k8s.io/v1' 'kind: StorageClass' '  name: gp3-encrypted' \
  '    node-operator.io/managed-by: vault-bootstrap' \
  '    node-operator.io/storage-profile: gp3-encrypted' \
  'provisioner: ebs.csi.aws.com' '  encrypted: "true"' \
  '  kmsKeyId: REPLACE_WITH_VAULT_EBS_KMS_KEY_ARN' '  type: gp3' \
  'volumeBindingMode: WaitForFirstConsumer' 'reclaimPolicy: Retain' \
  'allowVolumeExpansion: true'; do
  grep -Fqx "$field" "$template" || fail "template omits $field"
done
grep -Fq 'value = aws_kms_key.ebs.arn' "$bootstrap" || fail 'CodeBuild does not receive the existing EBS CMK ARN'
grep -Fq 'ensure-vault-encrypted-storageclass.sh --template /opt/node-operator/vault-gp3-encrypted-storageclass.yaml --kms-key-arn "$VAULT_EBS_KMS_KEY_ARN"' "$bootstrap" || fail 'CodeBuild does not verify encrypted StorageClass before Helm'
if grep -Fq "s#gp3-encrypted#gp2#g" "$bootstrap"; then fail 'CodeBuild still substitutes gp2 for encrypted storage'; fi
temporary="$(mktemp -d)"
trap 'rm -rf "$temporary"' EXIT
mkdir -p "$temporary/bin"

cat > "$temporary/bin/kubectl" <<'SCRIPT'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "$FAKE_TRACE"
expected="ebs.csi.aws.com|true|$FAKE_KMS|gp3|3|WaitForFirstConsumer|Retain|true|vault-bootstrap|gp3-encrypted"
if [ "${1:-}:${2:-}" = 'get:storageclass' ]; then
  if [ "$FAKE_MODE" = absent ] && [ ! -e "$FAKE_STATE" ]; then exit 0; fi
  if [ "$FAKE_MODE" = read-error ]; then exit 91; fi
  if [ "$FAKE_MODE" = mismatch ]; then printf '%s' 'ebs.csi.aws.com|true|arn:aws:kms:ap-northeast-2:123456789012:key/ffffffff-ffff-ffff-ffff-ffffffffffff|gp3|WaitForFirstConsumer|Retain|true'; exit 0; fi
  if [ "$FAKE_MODE" = foreign ]; then printf '%s' "ebs.csi.aws.com|true|$FAKE_KMS|gp3|3|WaitForFirstConsumer|Retain|true|other|gp3-encrypted"; exit 0; fi
  if [ "$FAKE_MODE" = extra-parameter ]; then printf '%s' "ebs.csi.aws.com|true|$FAKE_KMS|gp3|4|WaitForFirstConsumer|Retain|true|vault-bootstrap|gp3-encrypted"; exit 0; fi
  printf '%s' "$expected"; exit 0
fi
if [ "${1:-}:${2:-}" = 'create:-f' ]; then
  [ -f "${3:-}" ] || exit 92
  grep -Fqx '  name: gp3-encrypted' "$3"
  grep -Fqx '    node-operator.io/managed-by: vault-bootstrap' "$3"
  grep -Fqx '    node-operator.io/storage-profile: gp3-encrypted' "$3"
  grep -Fqx 'provisioner: ebs.csi.aws.com' "$3"
  grep -Fqx '  encrypted: "true"' "$3"
  grep -Fqx "  kmsKeyId: $FAKE_KMS" "$3"
  grep -Fqx '  type: gp3' "$3"
  grep -Fqx 'volumeBindingMode: WaitForFirstConsumer' "$3"
  grep -Fqx 'reclaimPolicy: Retain' "$3"
  cp "$3" "$FAKE_RENDERED"
  : > "$FAKE_STATE"
  exit 0
fi
if [ "${1:-}" = -n ] && [ "${3:-}:${4:-}" = 'get:pvc' ]; then
  case "$FAKE_MODE" in
    data-gp2) printf 'data-vault-0|gp2\n' ;;
    audit-gp2) printf 'audit-vault-4|gp2\n' ;;
    classless) printf 'data-vault-0|\n' ;;
    *) printf '' ;;
  esac
  exit 0
fi
exit 93
SCRIPT
chmod 700 "$temporary/bin/kubectl"

run_helper() {
  FAKE_MODE="$1" FAKE_STATE="$temporary/state" FAKE_TRACE="$temporary/trace" FAKE_RENDERED="$temporary/rendered.yaml" FAKE_KMS="$kms" \
    PATH="$temporary/bin:$PATH" "$helper" --template "$template" --kms-key-arn "$kms"
}
reset() { rm -f "$temporary/state" "$temporary/trace" "$temporary/rendered.yaml"; }

reset
run_helper absent >/dev/null
test -f "$temporary/state" || fail 'absent class was not created'
test -f "$temporary/rendered.yaml" || fail 'absent class render was not submitted'
grep -Fq 'create -f ' "$temporary/trace" || fail 'absent class did not use create'

reset
run_helper matching >/dev/null
if grep -Fq 'create -f ' "$temporary/trace"; then fail 'matching class was mutated'; fi

reset
for mode in mismatch foreign extra-parameter; do
  reset
  if run_helper "$mode" >/dev/null 2>&1; then fail "$mode existing class was accepted"; fi
  if grep -Fq 'create -f ' "$temporary/trace"; then fail "$mode class was replaced"; fi
done

reset
if run_helper read-error >/dev/null 2>&1; then fail 'StorageClass read error was accepted'; fi
if grep -Fq 'create -f ' "$temporary/trace"; then fail 'StorageClass read error attempted a create'; fi

for mode in data-gp2 audit-gp2 classless; do
  reset
  if run_helper "$mode" >/dev/null 2>&1; then fail "$mode retained PVC was accepted"; fi
  if grep -Fq 'create -f ' "$temporary/trace"; then fail "$mode PVC path attempted class mutation"; fi
done

printf '%s\n' 'PASS encrypted Vault StorageClass create/verify and retained-PVC migration guards are fail-closed.'
