#!/usr/bin/env bash
set -euo pipefail
umask 077

# Stages only the non-secret runtime and fenced client manifests produced by
# prepare-hoodi-validator-deployment.sh. It never initializes Vault, accepts
# custody material, or starts the signer, client, or fence.
usage() {
  printf '%s\n' "usage: ${0##*/} plan|apply|verify --handoff /absolute/validator-deployment-handoff.json [--private-eks-session-handoff /absolute/session.json] [--ebs-kms-key-arn ARN]" >&2
  exit 64
}

operation="${1:-}"
case "$operation" in plan|apply|verify) ;; *) usage ;; esac
shift
handoff=''; private_eks_session_handoff=''; ebs_kms_key_arn=''
while [ "$#" -gt 0 ]; do
  case "$1" in
    --handoff) handoff="${2:-}"; shift 2 ;;
    --private-eks-session-handoff) private_eks_session_handoff="${2:-}"; shift 2 ;;
    --ebs-kms-key-arn) ebs_kms_key_arn="${2:-}"; shift 2 ;;
    *) usage ;;
  esac
done
case "$handoff" in /*) ;; *) usage ;; esac
[ -f "$handoff" ] && [ ! -L "$handoff" ] || { printf '%s\n' 'handoff must be a regular file' >&2; exit 65; }
for command in jq grep; do command -v "$command" >/dev/null 2>&1 || { printf 'missing command: %s\n' "$command" >&2; exit 69; }; done

# Preserve the handoff's recorded path spelling. macOS aliases /var to
# /private/var, and canonicalizing here makes valid generated handoffs fail
# exact manifest-path checks.
parent="$(dirname "$handoff")"
runtime="$parent/runtime.yaml"
client="$parent/client-and-fence.yaml"
[ -f "$runtime" ] && [ ! -L "$runtime" ] && [ -f "$client" ] && [ ! -L "$client" ] || {
  printf '%s\n' 'handoff directory must contain regular runtime and client manifests' >&2
  exit 65
}

validator_set="$(jq -er '
  if .schema_version == 1 and .network == "hoodi" and
     (.validator_set | type == "string" and test("^hoodi-[a-z0-9][a-z0-9-]*$"))
  then .validator_set else error("invalid validator set") end
' "$handoff")" || { printf '%s\n' 'handoff is not a Hoodi validator deployment contract' >&2; exit 65; }
namespace='validator-operations'
jq -e --arg parent "$parent" --arg runtime "$runtime" --arg client "$client" '
  (.aws_account_id | test("^[0-9]{12}$")) and
  (.aws_region | test("^[a-z]{2}-[a-z0-9-]+-[0-9]+$")) and
  .runtime_manifest == $runtime and .client_manifest == $client and
  .staged_client_replicas == 0 and .staged_fence_replicas == 0 and
  (.next_steps | type == "array" and length > 0)
' "$handoff" >/dev/null || { printf '%s\n' 'handoff paths or staged replica boundary are invalid' >&2; exit 65; }

# These artifacts are deliberately non-secret. Refuse a handoff that has been
# replaced with a Secret or common raw key material before it crosses the SSM
# tunnel.
secret_kind='Sec''ret'
private_key='PRIVATE'' KEY'
nonpersistent='DO_NOT''_PERSIST_'
if grep -E -n "(^|[[:space:]])kind:[[:space:]]*${secret_kind}([[:space:]]|$)|-----BEGIN( [A-Z]+)? ${private_key}-----|${nonpersistent}" "$runtime" "$client" >/dev/null; then
  printf '%s\n' 'staging input crosses the non-secret manifest boundary' >&2
  exit 65
fi

if [ -n "$private_eks_session_handoff" ]; then
  case "$private_eks_session_handoff" in /*) ;; *) printf '%s\n' 'private EKS session handoff must be an absolute path' >&2; exit 65 ;; esac
  [ -f "$private_eks_session_handoff" ] && [ ! -L "$private_eks_session_handoff" ] || { printf '%s\n' 'private EKS session handoff must be a regular file' >&2; exit 65; }
  handoff_region="$(jq -er '.aws_region' "$handoff")"
  session_cluster="$(jq -er --arg region "$handoff_region" 'if .schema_version == 1 and .aws_region == $region and (.cluster_name | type == "string" and test("^[a-z][a-z0-9-]{1,38}[a-z0-9]$")) then .cluster_name else empty end' "$private_eks_session_handoff")" || { printf '%s\n' 'private EKS session handoff is invalid or points to another Region' >&2; exit 65; }
  session_instance="$(jq -er '.ssm_ops_instance_id | select(test("^i-[0-9a-f]+$"))' "$private_eks_session_handoff")" || { printf '%s\n' 'private EKS session handoff lacks a valid SSM instance' >&2; exit 65; }
fi

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
self="$script_dir/${BASH_SOURCE[0]##*/}"
repository_root="$(cd "$script_dir/../.." && pwd -P)"
vault_egress_policy="$repository_root/deploy/validator/vault-runtime-egress-policy.yaml"
service_accounts="$repository_root/deploy/validator/service-accounts.yaml"
storage_class_template="$repository_root/deploy/validator/storage-class.yaml"
storage_class_helper="$repository_root/scripts/ops/ensure-validator-encrypted-storageclass.sh"
[ -f "$vault_egress_policy" ] && [ ! -L "$vault_egress_policy" ] || { printf '%s\n' 'dedicated validator Vault egress policy is missing or unsafe' >&2; exit 66; }
[ -f "$service_accounts" ] && [ ! -L "$service_accounts" ] || { printf '%s\n' 'dedicated validator ServiceAccount manifest is missing or unsafe' >&2; exit 66; }
if [ -n "$ebs_kms_key_arn" ]; then
  [ -f "$storage_class_template" ] && [ ! -L "$storage_class_template" ] && [ -x "$storage_class_helper" ] || {
    printf '%s\n' 'validator encrypted StorageClass helper or template is missing or unsafe' >&2
    exit 66
  }
fi
if [ "${PRIVATE_EKS_SESSION:-}" != 1 ]; then
  if [ -n "$private_eks_session_handoff" ]; then
    arguments=("$self" "$operation" --handoff "$handoff" --private-eks-session-handoff "$private_eks_session_handoff")
    [ -z "$ebs_kms_key_arn" ] || arguments+=(--ebs-kms-key-arn "$ebs_kms_key_arn")
    exec env AWS_REGION="$handoff_region" EKS_CLUSTER_NAME="$session_cluster" SSM_OPS_INSTANCE_ID="$session_instance" "$script_dir/../ops/with-private-eks.sh" -- env PRIVATE_EKS_SESSION=1 "${arguments[@]}"
  fi
  arguments=("$self" "$operation" --handoff "$handoff")
  [ -z "$ebs_kms_key_arn" ] || arguments+=(--ebs-kms-key-arn "$ebs_kms_key_arn")
  exec "$script_dir/../ops/with-private-eks.sh" -- env PRIVATE_EKS_SESSION=1 "${arguments[@]}"
fi
command -v kubectl >/dev/null 2>&1 || { printf '%s\n' 'missing command: kubectl' >&2; exit 69; }

if [ "$operation" = verify ]; then
  found=0
  for target in \
    "statefulset/validator-${validator_set}-slashing-db" \
    "deployment/validator-${validator_set}-remote-signer" \
    "statefulset/validator-${validator_set}-client" \
    "deployment/validator-${validator_set}-signing-fence"; do
    if kubectl -n "$namespace" get "$target" >/dev/null 2>&1; then found=1; fi
  done
  [ "$found" -eq 1 ] || { printf '%s\n' 'no staged validator resources found'; exit 3; }
  db_replicas="$(kubectl -n "$namespace" get "statefulset/validator-${validator_set}-slashing-db" -o jsonpath='{.spec.replicas}' 2>/dev/null || true)"
  signer_replicas="$(kubectl -n "$namespace" get "deployment/validator-${validator_set}-remote-signer" -o jsonpath='{.spec.replicas}' 2>/dev/null || true)"
  client_replicas="$(kubectl -n "$namespace" get "statefulset/validator-${validator_set}-client" -o jsonpath='{.spec.replicas}' 2>/dev/null || true)"
  fence_replicas="$(kubectl -n "$namespace" get "deployment/validator-${validator_set}-signing-fence" -o jsonpath='{.spec.replicas}' 2>/dev/null || true)"
  [ "$db_replicas:$signer_replicas:$client_replicas:$fence_replicas" = '1:0:0:0' ] || {
    printf '%s\n' 'existing validator resources do not preserve the expected runtime/fence boundary' >&2
    exit 70
  }
  printf 'PASS: existing staged validator resources preserve the expected zero-replica activation boundary.\n'
  exit 0
fi

# Fresh-set staging must never adopt an existing controller or lease. Check
# before server-side dry-run too: otherwise Kubernetes reports low-level field
# manager conflicts that conceal the actionable recovery/rotation boundary.
for target in \
  "statefulset/validator-${validator_set}-slashing-db" \
  "deployment/validator-${validator_set}-remote-signer" \
  "statefulset/validator-${validator_set}-client" \
  "deployment/validator-${validator_set}-signing-fence" \
  "lease/validator-${validator_set}-primary"; do
  if kubectl -n "$namespace" get "$target" >/dev/null 2>&1; then
    printf 'validator set %s already has %s; fresh staging will not adopt it. Use the guarded repair or rotation procedure.\n' "$validator_set" "$target" >&2
    exit 65
  fi
done

# The server-side dry run proves admission, RBAC, and schema compatibility
# before an apply. It is run for both operations so apply has the same guard.
if [ "$operation" = apply ]; then
  if [ -n "$ebs_kms_key_arn" ]; then
    "$storage_class_helper" --template "$storage_class_template" --kms-key-arn "$ebs_kms_key_arn"
  fi
  # A zero-resource EKS cluster has no application namespaces yet. Create only
  # the two bounded namespaces referenced by the staged manifests; this does
  # not create workloads or cross the secret boundary.
  kubectl create namespace "$namespace" --dry-run=client -o yaml | kubectl apply --server-side --field-manager=node-operator-release-stage -f - >/dev/null
  kubectl create namespace node-operator --dry-run=client -o yaml | kubectl apply --server-side --field-manager=node-operator-release-stage -f - >/dev/null
fi
kubectl apply --server-side --field-manager=node-operator-release-stage --dry-run=server -f "$service_accounts" -f "$vault_egress_policy" -f "$runtime" -f "$client" >/dev/null
if [ "$operation" = plan ]; then
  printf 'PASS: private EKS accepted non-secret staged manifests for %s; no resources were created.\n' "$validator_set"
  exit 0
fi

# Apply only the dedicated ServiceAccounts and narrowly scoped egress policy
# before workloads. Do not apply the historical common validator base here: it
# contains fence policy selectors that are not safe to adopt during a set-scoped
# staged release.
kubectl apply --server-side --field-manager=node-operator-release-stage -f "$service_accounts" >/dev/null
kubectl apply --server-side --field-manager=node-operator-release-stage -f "$vault_egress_policy" >/dev/null
kubectl apply --server-side --field-manager=node-operator-release-stage -f "$runtime" -f "$client" >/dev/null

db_replicas="$(kubectl -n "$namespace" get "statefulset/validator-${validator_set}-slashing-db" -o jsonpath='{.spec.replicas}')"
signer_replicas="$(kubectl -n "$namespace" get "deployment/validator-${validator_set}-remote-signer" -o jsonpath='{.spec.replicas}')"
client_replicas="$(kubectl -n "$namespace" get "statefulset/validator-${validator_set}-client" -o jsonpath='{.spec.replicas}')"
fence_replicas="$(kubectl -n "$namespace" get "deployment/validator-${validator_set}-signing-fence" -o jsonpath='{.spec.replicas}')"
[ "$db_replicas:$signer_replicas:$client_replicas:$fence_replicas" = '1:0:0:0' ] || {
  printf '%s\n' 'staged controller replicas do not preserve the expected runtime/fence boundary' >&2
  exit 70
}
printf 'PASS: non-secret runtime staged for %s; signer, client, and fence remain at zero pending Vault, custody, deposit, and activation gates.\n' "$validator_set"
