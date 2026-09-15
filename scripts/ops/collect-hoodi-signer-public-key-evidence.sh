#!/usr/bin/env bash
set -euo pipefail
umask 077

# Collects one bounded, mTLS-authenticated GET of the public signer key after
# the signer has been started.  The disposable probe receives its client TLS
# only from Vault and is UID-deleted on every exit path.  It never requests a
# signature, reads a keystore, or prints TLS material.
dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
usage() { printf 'Usage: %s --validator-set <hoodi-id> --validator-public-key <0x-key> --probe-image <private-ecr-digest> --output-dir <absolute-dir>\n' "${0##*/}" >&2; exit 64; }
validator_set=''; public_key=''; probe_image=''; output_dir=''
while [ "$#" -gt 0 ]; do
  case "$1" in
    --validator-set) validator_set="${2:-}"; shift 2 ;;
    --validator-public-key) public_key="${2:-}"; shift 2 ;;
    --probe-image) probe_image="${2:-}"; shift 2 ;;
    --output-dir) output_dir="${2:-}"; shift 2 ;;
    *) usage ;;
  esac
done
case "$validator_set" in hoodi-[a-z0-9][a-z0-9-]*) ;; *) usage ;; esac
case "$public_key" in 0x????????????????????????????????????????????????????????????????????????????????????????????????) ;; *) usage ;; esac
[[ "$probe_image" =~ ^[0-9]{12}\.dkr\.ecr\.ap-northeast-[12]\.amazonaws\.com/[a-z][a-z0-9-]{1,18}[a-z0-9]-baseline-validator-signer-identity-probe@sha256:[a-f0-9]{64}$ ]] || usage
case "$output_dir" in /*) ;; *) usage ;; esac
if [ "${PRIVATE_EKS_SESSION:-}" != 1 ]; then
  exec "$dir/with-private-eks.sh" -- env PRIVATE_EKS_SESSION=1 "$0" --validator-set "$validator_set" --validator-public-key "$public_key" --probe-image "$probe_image" --output-dir "$output_dir"
fi
for command in kubectl jq date mkdir mktemp sleep tr; do command -v "$command" >/dev/null 2>&1 || { printf 'missing command: %s\n' "$command" >&2; exit 69; }; done

namespace='validator-operations'
mkdir -p "$output_dir"; chmod 700 "$output_dir"; output_dir="$(cd "$output_dir" && pwd -P)"
public_key="$(printf '%s' "$public_key" | tr '[:upper:]' '[:lower:]')"
suffix="$(date -u +%Y%m%d%H%M%S)"
pod="signer-public-key-evidence-${validator_set}-${suffix}"
temporary_directory="${TMPDIR:-/tmp}"
case "$temporary_directory" in /*) ;; *) printf '%s\n' 'temporary directory must be absolute' >&2; exit 65 ;; esac
[ -d "$temporary_directory" ] && [ ! -L "$temporary_directory" ] || { printf '%s\n' 'temporary directory is unsafe' >&2; exit 65; }
manifest="$(mktemp "$temporary_directory/node-operator-signer-public-key.XXXXXX")"
created=''
cleanup() {
  status="${1:-$?}"; cleanup_failed=0; set +e
  if [ -n "$created" ]; then
    jq -cn --arg uid "$created" '{apiVersion:"v1",kind:"DeleteOptions",preconditions:{uid:$uid}}' | kubectl -n "$namespace" delete --raw "/api/v1/namespaces/${namespace}/pods/${pod}" -f - >/dev/null || cleanup_failed=1
  fi
  rm -f "$manifest" || cleanup_failed=1
  if [ "$cleanup_failed" -ne 0 ]; then
    printf '%s\n' 'signer public-key probe cleanup failed' >&2
    [ "$status" -ne 0 ] || status=70
  fi
  return "$status"
}
on_exit() {
  status=$?
  trap - EXIT
  cleanup "$status"
  exit $?
}
trap on_exit EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# A failed disposable probe is useful operationally only when its Kubernetes
# state is reported.  Never collect Pod logs here: Vault and workload logs can
# contain credentials.  This projection is deliberately limited to lifecycle
# metadata and Kubernetes-provided reason/exit-code fields.
print_probe_status() {
  jq -c '{phase:(.status.phase // "Unknown"),init_containers:[.status.initContainerStatuses[]? | {name,waiting_reason:(.state.waiting.reason // null),terminated_reason:(.state.terminated.reason // null),exit_code:(.state.terminated.exitCode // null)}],containers:[.status.containerStatuses[]? | {name,waiting_reason:(.state.waiting.reason // null),terminated_reason:(.state.terminated.reason // null),exit_code:(.state.terminated.exitCode // null)}]}' <<<"$status" >&2
}

kubectl -n "$namespace" get deployment "validator-${validator_set}-remote-signer" -o json | jq -e '.spec.replicas == 1 and .status.readyReplicas == 1' >/dev/null
kubectl -n "$namespace" get statefulset "validator-${validator_set}-client" -o json | jq -e '.spec.replicas == 0' >/dev/null
kubectl -n "$namespace" get deployment "validator-${validator_set}-signing-fence" -o json | jq -e '.spec.replicas == 0' >/dev/null

jq -n --arg name "$pod" --arg set "$validator_set" --arg key "$public_key" --arg image "$probe_image" '
  {apiVersion:"v1",kind:"Pod",metadata:{name:$name,namespace:"validator-operations",labels:{"app.kubernetes.io/component":"validator-signing-fence","node-operator.io/validator-set":$set,"node-operator.io/vault-client":"true","node-operator.io/purpose":"signer-public-key-evidence"},annotations:{"vault.hashicorp.com/agent-inject":"true","vault.hashicorp.com/secret-volume-path":"/tls","vault.hashicorp.com/agent-pre-populate-only":"true","vault.hashicorp.com/agent-service-account-token-volume-name":"vault-auth","vault.hashicorp.com/tls-secret":"vault-agent-ca","vault.hashicorp.com/ca-cert":"/vault/tls/ca.crt","vault.hashicorp.com/tls-server-name":"vault.vault.svc","vault.hashicorp.com/role":("hoodi-"+$set+"-client-tls"),"vault.hashicorp.com/agent-inject-secret-tls.crt":("node-operator-runtime/data/validators/hoodi/"+$set+"/runtime/client-tls"),"vault.hashicorp.com/agent-inject-template-tls.crt":("{{- with secret \"node-operator-runtime/data/validators/hoodi/"+$set+"/runtime/client-tls\" -}}{{ .Data.data.tls_crt_b64 | base64Decode }}{{- end }}"),"vault.hashicorp.com/agent-inject-secret-tls.key":("node-operator-runtime/data/validators/hoodi/"+$set+"/runtime/client-tls"),"vault.hashicorp.com/agent-inject-template-tls.key":("{{- with secret \"node-operator-runtime/data/validators/hoodi/"+$set+"/runtime/client-tls\" -}}{{ .Data.data.tls_key_b64 | base64Decode }}{{- end }}"),"vault.hashicorp.com/agent-inject-secret-ca.crt":("node-operator-runtime/data/validators/hoodi/"+$set+"/runtime/client-tls"),"vault.hashicorp.com/agent-inject-template-ca.crt":("{{- with secret \"node-operator-runtime/data/validators/hoodi/"+$set+"/runtime/client-tls\" -}}{{ .Data.data.ca_crt_b64 | base64Decode }}{{- end }}"),"node-operator.io/scope":"GET-only public-key identity probe; no signing request"}},spec:{restartPolicy:"Never",activeDeadlineSeconds:120,automountServiceAccountToken:false,enableServiceLinks:false,serviceAccountName:"validator-client",securityContext:{runAsNonRoot:true,runAsUser:65532,runAsGroup:65532,fsGroup:65532,seccompProfile:{type:"RuntimeDefault"}},volumes:[{name:"vault-auth",projected:{sources:[{serviceAccountToken:{audience:"vault",expirationSeconds:600,path:"token"}}]}}],containers:[{name:"get-only-identity-probe",image:$image,args:["--validator-set",$set,"--expected-public-key",$key],resources:{requests:{cpu:"10m",memory:"32Mi"},limits:{cpu:"100m",memory:"64Mi"}},securityContext:{allowPrivilegeEscalation:false,readOnlyRootFilesystem:true,capabilities:{drop:["ALL"]}},volumeMounts:[{name:"vault-auth",mountPath:"/var/run/secrets/vault.hashicorp.com/serviceaccount",readOnly:true}]}]}}' > "$manifest"
kubectl create --dry-run=server -f "$manifest" >/dev/null
created="$(kubectl create -f "$manifest" -o json | jq -er .metadata.uid)"
for _ in $(seq 1 60); do
  status="$(kubectl -n "$namespace" get pod "$pod" -o json)"
  if jq -e '.status.phase == "Succeeded" or .status.phase == "Failed"' <<<"$status" >/dev/null; then break; fi
  sleep 2
done
if ! jq -e '(.status.phase == "Succeeded") and ([.status.initContainerStatuses[]? | select(.name == "vault-agent-init" and .state.terminated.exitCode == 0)] | length == 1) and any(.status.containerStatuses[]?; .name == "get-only-identity-probe" and .state.terminated.exitCode == 0)' <<<"$status" >/dev/null; then
  printf '%s\n' 'signer public-key probe did not complete successfully; sanitized Pod status follows:' >&2
  print_probe_status
  # The fixed probe emits only constant failure categories, never TLS material.
  # Still allowlist exact lines instead of relaying arbitrary container logs.
  kubectl -n "$namespace" logs "$pod" -c get-only-identity-probe 2>/dev/null |
    grep -Ex 'signer identity probe failed: (client certificate is unavailable|signer CA is unavailable|signer CA is invalid|mutual TLS signer request failed|signer returned a non-success status|signer response was not a public-key array|signer did not return exactly one public key|signer public key did not match expected identity)' >&2 || true
  kubectl -n "$namespace" get pod "$pod" -o json | jq -c '{node:.spec.nodeName,pod_ip:.status.podIP}' >&2
  exit 70
fi
log="$(kubectl -n "$namespace" logs "$pod" -c get-only-identity-probe)"
jq -e --arg key "$public_key" '.tls_verified == true and .public_key_match == true and .public_key_count == 1 and .validator_public_key == $key' <<<"$log" >/dev/null
record="$output_dir/signer-public-key-${validator_set}-$(date -u +%Y%m%dT%H%M%SZ).json"
jq -n --arg at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --arg set "$validator_set" --arg key "$public_key" --arg pod "$pod" \
  '{schema_version:1,event_type:"signer-public-key",collected_at_utc:$at,network:"hoodi",validator_set:$set,validator_public_key:$key,source:"vault-injected-mtls-get-only-probe",tls_verified:true,public_key_count:1,public_key_match:true,vault_agent_init_succeeded:true,probe_pod:$pod,scope:"GET-only public key; no signature, keystore, client key, or Vault response retained"}' > "$record"
chmod 600 "$record"
if cleanup 0; then cleanup_status=0; else cleanup_status=$?; fi
trap - EXIT INT TERM
[ "$cleanup_status" -eq 0 ] || exit "$cleanup_status"
printf 'PASS: signer public key and Vault-injected mTLS were verified with a GET-only disposable probe. Evidence: %s\n' "$record"
