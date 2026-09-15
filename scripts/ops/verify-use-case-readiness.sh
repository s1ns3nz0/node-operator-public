#!/usr/bin/env bash
set -euo pipefail

namespace="${HOODI_NAMESPACE:-node-operator}"
validator_namespace="${VALIDATOR_NAMESPACE:-validator-operations}"
for command in kubectl jq; do command -v "$command" >/dev/null 2>&1 || { printf 'missing command: %s\n' "$command" >&2; exit 127; }; done

app="$(kubectl -n argocd get application node-operator-client -o json)"
printf '%s' "$app" | jq -e '.status.sync.status == "Synced" and .status.health.status == "Healthy"' >/dev/null || { printf 'UC-1 application is not Synced/Healthy\n' >&2; exit 1; }

for pod in nethermind-execution-0 prysm-beacon-0; do
  ready="$(kubectl -n "$namespace" get pod "$pod" -o json | jq -r '[.status.containerStatuses[]?.ready] | all')"
  [ "$ready" = true ] || { printf 'UC-1 client is not Ready: %s\n' "$pod" >&2; exit 1; }
done

kubectl -n "$validator_namespace" get serviceaccount validator-remote-signer >/dev/null
kubectl -n "$validator_namespace" get serviceaccount validator-client >/dev/null

# A signer endpoint and its fence belong to exactly one validator set.  The
# former base-wide objects selected every signer Pod, including test sets; that
# would permit a future client to reach the wrong signer.  Refuse readiness
# while either legacy object remains, or while any unscoped signer Service is
# present.  A test-only signer may exist, but it must be reachable only by its
# own set-scoped Service.
for legacy in 'service hoodi-validator-remote-signer' 'lease hoodi-validator-set-primary'; do
  kind="${legacy%% *}"
  name="${legacy#* }"
  if kubectl -n "$validator_namespace" get "$kind" "$name" >/dev/null 2>&1; then
    printf 'legacy unscoped %s remains: %s; remove it before any operational signer activation\n' "$kind" "$name" >&2
    exit 1
  fi
done
unscoped_services="$(kubectl -n "$validator_namespace" get service -o json | jq -r '
  [.items[]
   | select(.spec.selector["app.kubernetes.io/component"] == "validator-remote-signer")
   | select(.spec.selector["node-operator.io/validator-set"] | not)
   | .metadata.name] | join(",")
')"
[ -z "$unscoped_services" ] || { printf 'unscoped remote-signer Service(s) remain: %s\n' "$unscoped_services" >&2; exit 1; }

printf '%s\n' 'PASS UC-1 is operational; UC-2 through UC-5 require a separately rendered, set-scoped signer and remain fail-closed.'
