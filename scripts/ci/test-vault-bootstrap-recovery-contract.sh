#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$script_dir/lib/common.sh"
require_command jq
root="$(repo_root)"
fail() { printf 'FAIL Vault bootstrap and recovery contract: %s\n' "$*" >&2; exit 1; }

contract="$root/deploy/vault/bootstrap/release-path-contract.json"
documentation="$root/docs/gitops/vault-bootstrap-recovery-contract.md"
for file in "$contract" "$documentation"; do
  test -f "$file" || fail "missing required contract: $file"
done

jq -e '
  .schema_version == "v1" and
  .kind == "vault-release-path-bootstrap-recovery-contract" and
  (.execution | contains("declarative-only")) and
  .release_credentials.enable_when == "every ordered phase has status=passed evidence and every deny-path probe has status=denied evidence" and
  .release_credentials.otherwise == "deny" and
  [.phases[].id] == [
    "private-connectivity-and-tls",
    "operator-initialize-and-unseal-boundary",
    "audit-device-delivery-probe",
    "encrypted-raft-snapshot-and-isolated-restore-drill",
    "github-jwt-release-role-and-policy",
    "aws-secrets-engine-dynamic-release-role",
    "aws-auth-codebuild-signer-role",
    "transit-key-and-signer-policy"
  ] and
  [.phases[].order] == [1,2,3,4,5,6,7,8] and
  .phases[1].external_material == ["root token", "recovery material", "unseal material"] and
  (.phases[1].automation | contains("never")) and
  .phases[7].permissions == ["sign", "verify"] and
  ([.non_secret_evidence_fields[]] | sort) == [
    "aws_request_id", "codebuild_build_id", "deny_path_status", "environment_id", "github_repository_id", "github_run_id", "github_workflow_ref", "operator_approval_id", "phase_id", "private_dns_probe_id", "recorded_at", "restore_drill_id", "snapshot_reference", "status", "tls_probe_id", "transit_verification_status", "vault_audit_request_id", "vault_cluster_id"
  ] and
  ([.forbidden_evidence[]] | sort) == [
    "aws_access_key", "aws_secret_key", "aws_session_token", "certificate_private_key", "oidc_jwt", "private_key", "recovery_key", "root_token", "transit_signature", "unseal_key", "vault_token"
  ]
' "$contract" >/dev/null || fail 'schema, phase ordering, evidence fields, or permission boundary changed'

for artifact in \
  'docs/gitops/vault-private-connectivity-contract.md' \
  'docs/gitops/private-release-runner-contract.md' \
  'deploy/vault/auth/github-release-jwt-role.json' \
  'deploy/vault/policies/release-runner-dynamic-aws.hcl' \
  'deploy/vault/aws/release-runner-assumed-role-policy.json' \
  'deploy/vault/release-signer-aws-auth.md' \
  'deploy/vault/buildspec-release-sign.yml' \
  'deploy/vault/policies/release-signer.hcl' \
  'scripts/ci/verify-release-signature.sh'; do
  test -f "$root/$artifact" || fail "referenced artifact is missing: $artifact"
  jq -e --arg artifact "$artifact" 'any(.phases[]; (.requires // []) | index($artifact))' "$contract" >/dev/null || fail "contract does not reference required artifact: $artifact"
done

if jq -e '.. | objects | keys[]? | select(test("command|script|shell|apply"; "i"))' "$contract" >/dev/null; then
  fail 'declarative contract contains an executable or imperative field'
fi
if grep -Eqi '(vault[[:space:]]+operator[[:space:]]+(init|unseal)|vault[[:space:]]+(write|policy[[:space:]]+write)|kubectl[[:space:]]+apply|helm[[:space:]]+(install|upgrade))' "$contract"; then
  fail 'declarative contract contains a live Vault or deployment command'
fi

for required in \
  "No \`vault operator init\`" \
  "\`vault operator unseal\`" \
  'or apply command is included or executable' \
  'separately authorized live rollout' \
  'Root material, recovery material, and unseal' \
  'material are external' \
  'Do not retain an OIDC JWT' \
  'Transit signature' \
  'fail-closed'; do
  grep -Fq "$required" "$documentation" || fail "documentation omits required boundary: $required"
done

printf 'PASS Vault bootstrap and recovery contract is ordered, non-secret, and fail-closed.\n'
