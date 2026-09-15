#!/usr/bin/env bash
set -euo pipefail
umask 077
dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
root="$(cd "$dir/../.." && pwd -P)"
usage() { printf 'Usage: %s --phase audit|enforce --evidence-output <new-absolute-json> --execute\n' "${0##*/}" >&2; exit 64; }
phase=''; evidence=''; execute=false
while [ "$#" -gt 0 ]; do case "$1" in
  --phase) phase="${2:-}"; shift 2;;
  --evidence-output) evidence="${2:-}"; shift 2;;
  --execute) execute=true; shift;;
  *) usage;;
esac; done
case "$phase" in audit|enforce) ;; *) usage;; esac
[[ "$evidence" = /* ]] && [ "$execute" = true ] || usage
[ ! -e "$evidence" ] && [ ! -L "$evidence" ] || { printf 'evidence must be new\n' >&2; exit 65; }
if [ "${PRIVATE_EKS_SESSION:-}" != 1 ]; then
  exec "$dir/with-private-eks.sh" -- env PRIVATE_EKS_SESSION=1 "$0" --phase "$phase" --evidence-output "$evidence" --execute
fi
for command in kubectl jq; do command -v "$command" >/dev/null || exit 69; done
scratch="$(mktemp -d "${TMPDIR:-/tmp}/node-operator-kyverno-coverage.XXXXXX")"
trap 'find "$scratch" -type f -exec unlink {} \;; rmdir "$scratch"' EXIT
kubectl -n kyverno rollout status deployment/kyverno-admission-controller --timeout=60s >/dev/null
kubectl kustomize "$root/deploy/kyverno" > "$scratch/policies.yaml"
# Store only the fields used by workload policies. No commands, environment,
# projected tokens, Secret contents or Vault annotations enter this evidence.
kubectl get pods -A -o json | jq '
  {apiVersion:"v1",kind:"List",items:[.items[] |
    select(.metadata.namespace | IN("node-operator","validator-operations","vault","argocd","cert-manager","validator-observability")) |
    select(.status.phase != "Succeeded" and .status.phase != "Failed") |
    {apiVersion:"v1",kind:"Pod",metadata:{name:.metadata.name,namespace:.metadata.namespace,labels:.metadata.labels},
     spec:{serviceAccountName:.spec.serviceAccountName,securityContext:.spec.securityContext,
       hostNetwork:.spec.hostNetwork,hostPID:.spec.hostPID,hostIPC:.spec.hostIPC,
       volumes:[.spec.volumes[]? | {name,hostPath} | with_entries(select(.value != null))],
       containers:[.spec.containers[] | {name,image,securityContext,resources,volumeMounts}],
       initContainers:[.spec.initContainers[]? | {name,image,securityContext,resources,volumeMounts}]}}]}' > "$scratch/pods.json"
if [ "$phase" = enforce ]; then
  kyverno_bin="${KYVERNO_BIN:-kyverno}"
  command -v "$kyverno_bin" >/dev/null || { printf 'Kyverno CLI required for live Enforce preflight\n' >&2; exit 69; }
  jq -e '(.items | type == "array") and (.items | length > 0) and all(.items[]; .kind == "Pod")' "$scratch/pods.json" >/dev/null || { printf 'No valid project Pods were observed; refusing an empty or malformed preflight\n' >&2; exit 65; }
  # The CLI treats kind:List as one unmatched object rather than evaluating its
  # items. Supply separate YAML documents so each actual Pod is evaluated.
  jq -r '.items[] | tojson + "\n---"' "$scratch/pods.json" > "$scratch/pods.yaml"
  "$kyverno_bin" apply "$scratch/policies.yaml" --resource "$scratch/pods.yaml" --warn-no-pass --warn-exit-code 65 || {
    printf 'Live workload preflight failed; no policy was changed. Harden workloads before Enforce.\n' >&2; exit 65;
  }
fi
kubectl create --dry-run=client --validate=false -f "$scratch/policies.yaml" -o json |
  jq --arg phase "$phase" '
    def stage: if .metadata.name == "node-operator-workload-baseline" then .
      else .spec.validationFailureAction = (if $phase == "audit" then "Audit" else "Enforce" end) end;
    if .kind == "List" then .items |= map(stage) else stage end' > "$scratch/apply.json"
kubectl apply --dry-run=server -f "$scratch/apply.json" >/dev/null
kubectl apply -f "$scratch/apply.json" >/dev/null
kubectl wait --for=condition=Ready --timeout=120s -f "$scratch/apply.json" >/dev/null
mkdir -p "$(dirname "$evidence")"
kubectl get clusterpolicies -o json | jq --arg phase "$phase" --arg at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" '
  {operation:"kyverno-project-coverage",phase:$phase,collected_at_utc:$at,
   policies:[.items[]|select(.metadata.name|startswith("node-operator-"))|
     {name:.metadata.name,mode:.spec.validationFailureAction,background:.spec.background,conditions:.status.conditions}],
   scope:"Project namespaces; system/Kyverno controller exclusions remain explicit",
   secret_values_emitted:false}' > "$evidence"
printf 'PASS: Kyverno project policy phase %s applied. Audit is not enforcement. Evidence: %s\n' "$phase" "$evidence"
