#!/usr/bin/env bash
set -euo pipefail
umask 077

# Applies only the Engine pair after migration evidence exists. It updates the
# immutable Argo chart revision, waits for desired templates, then restarts the
# OnDelete StatefulSets one at a time. It never deletes the legacy JWT Secret.
dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
usage() { printf 'Usage: %s --chart-version 0.1.N --chart-digest sha256:HEX --migration-evidence <absolute-json> --preflight-evidence <absolute-json> --evidence-output <new-absolute-json> --execute\n' "${0##*/}" >&2; exit 64; }
version=''; digest=''; migration=''; preflight=''; evidence=''; execute=false
while [ "$#" -gt 0 ]; do case "$1" in
  --chart-version) version="${2:-}"; shift 2;; --chart-digest) digest="${2:-}"; shift 2;; --migration-evidence) migration="${2:-}"; shift 2;; --preflight-evidence) preflight="${2:-}"; shift 2;; --evidence-output) evidence="${2:-}"; shift 2;; --execute) execute=true; shift;; *) usage;;
esac; done
[[ "$version" =~ ^0\.1\.[0-9]+$ ]] && [[ "$digest" =~ ^sha256:[0-9a-f]{64}$ ]] || usage
case "$migration:$preflight:$evidence" in /*:/*:/*) ;; *) usage;; esac
[ "$execute" = true ] || usage
[ -f "$migration" ] && [ ! -L "$migration" ] && [ -f "$preflight" ] && [ ! -L "$preflight" ] && [ ! -e "$evidence" ] && [ ! -L "$evidence" ] || { printf '%s\n' 'invalid evidence paths' >&2; exit 65; }
if [ "${PRIVATE_EKS_SESSION:-}" != 1 ]; then exec "$dir/with-private-eks.sh" -- env PRIVATE_EKS_SESSION=1 "$0" --chart-version "$version" --chart-digest "$digest" --migration-evidence "$migration" --preflight-evidence "$preflight" --evidence-output "$evidence" --execute; fi
for command in aws kubectl jq date mkdir sleep seq; do command -v "$command" >/dev/null 2>&1 || { printf 'missing command: %s\n' "$command" >&2; exit 69; }; done
jq -e -f "$dir/lib/vault-cutover-authorization.jq" "$migration" >/dev/null
jq -e '.operation == "live-vault-cutover-preflight" and .phase == "baseline" and .engine_pair_ready == true and .vault_injector_ready == true' "$preflight" >/dev/null

app_ns='argocd'; app='node-operator-client'; namespace='node-operator'
before="$(kubectl -n "$app_ns" get application "$app" -o json)"
jq -e '.status.sync.status == "Synced" and .status.health.status == "Healthy"' <<<"$before" >/dev/null || { printf '%s\n' 'Argo Application is not healthy before cutover' >&2; exit 65; }
# The digest is an approval input, not merely an annotation.  Bind it to the
# exact immutable version in the ECR OCI repository before Argo can consume it.
repository="$(jq -er '.spec.source as $source | ($source.repoURL | capture("^[^/]+/(?<repository>[a-z0-9][a-z0-9._/-]*)$").repository) + "/" + ($source.chart | select(test("^[a-z0-9][a-z0-9._-]*$")))' <<<"$before")"
published_digest="$(aws ecr describe-images --region "${AWS_REGION:-ap-northeast-2}" --repository-name "$repository" --image-ids "imageTag=${version}" --query 'imageDetails[0].imageDigest' --output text)"
[ "$published_digest" = "$digest" ] || { printf '%s\n' 'approved chart digest does not match the requested ECR chart version' >&2; exit 65; }
# Public CA only: never copy Vault server private keys or runtime credentials.
# Agent TLS trust Secrets are namespace-scoped, so Engine Pods need their own.
public_trust="$(kubectl -n validator-operations get secret vault-agent-ca -o json)"
jq -e '(.data | keys) == ["ca.crt"]' <<<"$public_trust" >/dev/null
existing_trust="$(kubectl -n "$namespace" get secret vault-agent-ca --ignore-not-found -o json)"
if [ -n "$existing_trust" ]; then
  jq -ne --argjson source "$public_trust" --argjson target "$existing_trust" '$source.data == $target.data' >/dev/null || { printf '%s\n' 'Engine public Vault CA differs; explicit trust rotation is required' >&2; exit 65; }
else
  jq --arg namespace "$namespace" '{apiVersion:"v1",kind:"Secret",metadata:{name:"vault-agent-ca",namespace:$namespace},type:"Opaque",data:{"ca.crt":.data["ca.crt"]}}' <<<"$public_trust" | kubectl create -f - >/dev/null
fi
kubectl -n "$app_ns" patch application "$app" --type merge -p "{\"metadata\":{\"annotations\":{\"node-operator.io/approved-chart-digest\":\"${digest}\"}},\"spec\":{\"source\":{\"targetRevision\":\"${version}\"}}}" >/dev/null

ready=false
for _ in $(seq 1 120); do
  app_json="$(kubectl -n "$app_ns" get application "$app" -o json)"
  if jq -e --arg version "$version" '.spec.source.targetRevision == $version and .status.sync.status == "Synced" and .status.health.status == "Healthy" and .status.sync.revision == $version' <<<"$app_json" >/dev/null; then ready=true; break; fi
  sleep 5
done
[ "$ready" = true ] || { printf '%s\n' 'Argo did not converge to requested immutable chart revision' >&2; exit 70; }

for stateful in nethermind-execution prysm-beacon; do
  template="$(kubectl -n "$namespace" get statefulset "$stateful" -o json)"
  jq -e '.spec.template.metadata.annotations["vault.hashicorp.com/agent-inject"] == "true" and .spec.template.metadata.annotations["vault.hashicorp.com/agent-inject-secret-engine.jwt"] == "node-operator-runtime/data/nodes/hoodi/engine-api-jwt"' <<<"$template" >/dev/null || { printf 'isolated Vault injection template missing: %s\n' "$stateful" >&2; exit 65; }
  jq -e '[.spec.template.spec.volumes[]? | select(.secret.secretName == "engine-api-jwt")] | length == 0' <<<"$template" >/dev/null || { printf 'legacy JWT Secret remains mounted: %s\n' "$stateful" >&2; exit 65; }
done

for stateful in nethermind-execution prysm-beacon; do
  revision="$(kubectl -n "$namespace" get statefulset "$stateful" -o jsonpath='{.status.updateRevision}')"
  existing="$(kubectl -n "$namespace" get pod "${stateful}-0" --ignore-not-found -o json)"
  # Resume after a partial cutover without deleting an already updated Pod.
  if [ -n "$existing" ] && ! jq -e --arg revision "$revision" '.metadata.labels["controller-revision-hash"] == $revision' <<<"$existing" >/dev/null; then
    kubectl -n "$namespace" delete pod "${stateful}-0" --wait=true >/dev/null
  fi
  pod_ready=false
  for _ in $(seq 1 240); do
    pod="$(kubectl -n "$namespace" get pod "${stateful}-0" --ignore-not-found -o json)"
    if [ -n "$pod" ] && jq -e --arg revision "$revision" '.metadata.labels["controller-revision-hash"] == $revision and any(.status.conditions[]?; .type == "Ready" and .status == "True")' <<<"$pod" >/dev/null; then pod_ready=true; break; fi
    sleep 5
  done
  [ "$pod_ready" = true ] || { printf 'updated OnDelete Pod did not become Ready: %s\n' "$stateful" >&2; exit 70; }
  pod="$(kubectl -n "$namespace" get pod "${stateful}-0" -o json)"
  jq -e '[.status.initContainerStatuses[]? | select(.name == "vault-agent-init" and .state.terminated.exitCode == 0)] | length == 1' <<<"$pod" >/dev/null || { printf 'Vault Agent init did not succeed: %s\n' "$stateful" >&2; exit 70; }
done

mkdir -p "$(dirname "$evidence")"
jq -n --arg version "$version" --arg digest "$digest" --arg at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  '{schema_version:1,operation:"live-engine-vault-cutover",completed_at_utc:$at,argocd_chart_version:$version,argocd_chart_digest:$digest,nethermind_restarted:true,prysm_restarted:true,vault_agent_init_succeeded:true,legacy_engine_jwt_secret_retained:true,secret_values_emitted:false}' > "$evidence"
chmod 600 "$evidence"
printf 'PASS: Engine pair cut over to Vault-injected JWT with one-at-a-time OnDelete restarts. Legacy Secret remains until final cleanup. Evidence: %s\n' "$evidence"
