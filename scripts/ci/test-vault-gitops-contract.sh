#!/usr/bin/env bash
# Check objective: Validate the Vault GitOps contract.
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$script_dir/lib/common.sh"
root="$(repo_root)"
fail() { printf 'FAIL %s\n' "$*" >&2; exit 1; }

application="$root/docs/gitops/vault-application.example.yaml"
values="$root/docs/gitops/vault-values.example.yaml"
operations="$root/docs/gitops/vault-operations-contract.md"

for file in "$application" "$values" "$operations"; do
  test -f "$file" || fail "missing Vault GitOps contract file: $file"
done

grep -Fqx '    path: platform/vault' "$application" || fail "Vault Application must use the approved Vault path"
grep -Fqx '        - vault-values.yaml' "$application" || fail "Vault Application must consume reviewed values"

for required in \
  '  tlsDisable: false' \
  '    enabled: true' \
  '    create: true' \
  '    name: vault' \
  '  authDelegator:' \
  '    enabled: true' \
  '    replicas: 3' \
  '      enabled: true' \
  '      setNodeId: true' \
  '    type: ClusterIP' \
  '    enabled: false' \
  '        secretName: vault-tls' \
  '          retry_join {' \
  '            leader_api_addr         = "https://vault-0.vault-internal:8200"' \
  '            leader_ca_cert_file     = "/vault/userconfig/vault-tls/ca.crt"' \
  '            leader_client_cert_file = "/vault/userconfig/vault-tls/tls.crt"' \
  '            leader_client_key_file  = "/vault/userconfig/vault-tls/tls.key"' \
  '        seal "awskms" {' \
  '          kms_key_id = "REPLACE_WITH_VAULT_UNSEAL_KEY_ARN"'; do
  grep -Fqx "$required" "$values" || fail "Vault values missing required boundary: $required"
done

# This release owns the in-cluster server. Setting either chart external address
# would suppress that server deployment, so an external endpoint is forbidden.
if grep -Eq '^[[:space:]]*externalVaultAddr:' "$values"; then
  fail 'Vault values must not configure an external Vault address'
fi

for required in \
  '  dataStorage:' \
  '    enabled: true' \
  '    size: 20Gi' \
  '    storageClass: gp3-encrypted' \
  '  auditStorage:' \
  '    enabled: true' \
  '    size: 20Gi' \
  '    storageClass: gp3-encrypted' \
  '    accessMode: ReadWriteOnce'; do
  grep -Fqx "$required" "$values" || fail "Vault values omit required audit-storage boundary: $required"
done
if grep -Fqx '    storageClass: gp2' "$values"; then
  fail 'Vault values retain an AWS-managed gp2 PVC class'
fi

for placeholder in \
  '    repository: REPLACE_WITH_PRIVATE_VAULT_SERVER_REPOSITORY' \
  '    tag: REPLACE_WITH_PRIVATE_VAULT_SERVER_TAG' \
  '    repository: REPLACE_WITH_PRIVATE_VAULT_AGENT_REPOSITORY' \
  '    tag: REPLACE_WITH_PRIVATE_VAULT_AGENT_TAG' \
  '    repository: REPLACE_WITH_PRIVATE_VAULT_INJECTOR_REPOSITORY' \
  '    tag: REPLACE_WITH_PRIVATE_VAULT_INJECTOR_TAG'; do
  grep -Fqx "$placeholder" "$values" || fail "Vault base template omits canonical-overlay placeholder: $placeholder"
done
if grep -Eq '^[[:space:]]*tag:[[:space:]]*"?[0-9a-f]{64}@sha256:[0-9a-f]{64}"?' "$values"; then
  fail 'Vault base template retains a copied runtime digest instead of a canonical-overlay placeholder'
fi
bootstrap_tf="$root/infra/terraform/vault-bootstrap.tf"
grep -Fq -- '--values /tmp/vault-values.yaml --values /tmp/vault-image-overrides.json' "$bootstrap_tf" || fail 'Vault bootstrap does not apply the canonical image overlay after the base template'
grep -Fq 'vault_image_values_overlay_base64' "$bootstrap_tf" || fail 'Vault bootstrap does not require a catalog-bound image overlay'

if grep -Eq '(type:[[:space:]]*(LoadBalancer|NodePort)|tls_disable[[:space:]]*=[[:space:]]*1|AWS_(ACCESS|SECRET)_ACCESS_KEY|aws_access_key|aws_secret_key)' "$values"; then
  fail "Vault values include a public, plaintext, or static-credential configuration"
fi

for required in \
  'hardened self-hosted runner' \
  'GitHub-hosted runners' \
  'audit device' \
  'snapshot restore test' \
  'fail-closed' \
  'static credential' \
  'public-endpoint fallback'; do
  grep -Fq "$required" "$operations" || fail "Vault operations contract omits: $required"
done

grep -Fq 'first Vault StatefulSet installation' "$root/docs/operations/vault-validator-audit.md" || fail "Vault audit operation contract permits unsafe retrofit"
grep -Fq 'retrofitted with' "$root/docs/operations/vault-validator-audit.md" || fail "Vault audit operation contract omits StatefulSet immutability gate"
grep -Fq 'helm upgrade' "$root/docs/operations/vault-validator-audit.md" || fail "Vault audit operation contract omits Helm migration guidance"

printf 'PASS Vault GitOps chart and private-runner contract is structurally constrained.\n'
