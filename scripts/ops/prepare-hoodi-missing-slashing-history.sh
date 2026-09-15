#!/usr/bin/env bash
# Hoodi-only, explicitly approved preparation for unavailable signing history.
# It repairs current native Web3Signer floors; it never claims to recover history.
set -euo pipefail
umask 077

usage() { printf '%s\n' "Usage: ${0##*/} --validator-set hoodi-example --validator-public-key <0x-key> --exception-approval-id <id> --output-dir <absolute-dir> --execute" >&2; exit "${1:-64}"; }
set_id=''; public_key=''; approval=''; operation=''; output_dir=''; execute=false
while [ "$#" -gt 0 ]; do case "$1" in
  --validator-set) set_id="${2:-}"; shift 2;; --validator-public-key) public_key="${2:-}"; shift 2;;
  --exception-approval-id) approval="${2:-}"; shift 2;;
  --output-dir) output_dir="${2:-}"; shift 2;; --execute) execute=true; shift;; --help|-h) usage 0;; *) usage;; esac; done
[ "$set_id" = hoodi-example ] || usage
[[ "$public_key" =~ ^0x[0-9a-f]{96}$ ]] || usage
# This is the operator's approval/change reference, not a credential or a
# cryptographically verified authorization. --execute is an explicit opt-in.
[[ "$approval" =~ ^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$ ]] || usage
case "$output_dir" in /*) ;; *) usage;; esac
[ "$execute" = true ] || usage
operation="missing-history-$(date -u +%Y%m%d%H%M%S)-$RANDOM"
for command in kubectl jq python3 mktemp mkdir chmod date rm sleep tee; do command -v "$command" >/dev/null 2>&1 || { printf 'missing command: %s\n' "$command" >&2; exit 69; }; done
[ ! -L "$output_dir" ] || { printf '%s\n' 'output directory must not be a symlink' >&2; exit 65; }
case "$output_dir" in /|/tmp|/private/tmp|/Users|"$HOME"|"$PWD") printf '%s\n' 'use a dedicated evidence subdirectory' >&2; exit 65;; esac
mkdir -p "$output_dir"; output_dir="$(cd "$output_dir" && pwd -P)"

namespace=validator-operations
signer="validator-${set_id}-remote-signer"; client="validator-${set_id}-client"; fence="validator-${set_id}-signing-fence"
database="validator-${set_id}-slashing-db"; pvc="data-${database}-0"; lease="validator-${set_id}-primary"
safe_operation="$(printf '%s' "$operation" | tr '[:upper:]' '[:lower:]' | tr -c 'a-z0-9-' '-')"
job="validator-${set_id}-slashing-prepare"
config="${job}-public-$RANDOM"
db_policy="${job}-db-ingress"; job_policy="${job}-egress"
scratch="$(mktemp -d "${TMPDIR:-/tmp}/hoodi-slashing-prepare.XXXXXX")"; chmod 700 "$scratch"
# Keep the Job and its dependencies for inspection. A failed or interrupted
# operation never deletes a different run's mutex or claims rollback of DB writes.
cleanup() { rm -rf -- "$scratch"; }
trap cleanup EXIT
trap 'cleanup; exit 130' INT
trap 'cleanup; exit 143' TERM
refuse() { printf 'REFUSED: %s\n' "$1" >&2; exit 65; }
repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
source_lock="$repository_root/.ci/web3signer-hardened/source.lock.json"
[ -r "$source_lock" ] && jq -e '.tag == "26.4.2" and .commit == "221996a5ddf6ab7648a8102ee029d9723762c116"' "$source_lock" >/dev/null || refuse 'reviewed Web3Signer 26.4.2 source lock is unavailable'
beacon_reader="$repository_root/scripts/ops/lib/uc5-beacon-reader.py"
[ -r "$beacon_reader" ] || refuse 'trusted Hoodi Beacon reader is unavailable'
read_fresh_floor() {
  local observation head
  observation="$(python3 - "$beacon_reader" "$public_key" <<'PY'
import importlib.util, json, sys
spec = importlib.util.spec_from_file_location("uc5_beacon_reader", sys.argv[1]); module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
print(json.dumps(module.read_ready(sys.argv[2]), sort_keys=True))
PY
)" || refuse 'trusted private Beacon read failed'
  head="$(jq -er --arg key "$public_key" 'select(.result == "PASS_PRIVATE_BEACON_READY" and .validator_public_key == $key and (.head_slot|type == "number")) | .head_slot' <<<"$observation")" || refuse 'trusted private Beacon observation is malformed'
  beacon_head="$head"; slot="$(( (head / 32 + 2) * 32 ))"; epoch="$(( head / 32 + 2 ))"
}

# Recheck all live state; do not accept caller-supplied assertions as a stop proof.
assert_stopped() {
  kubectl -n "$namespace" get deployment "$signer" -o json | jq -e '.spec.replicas == 0 and (.status.replicas // 0) == 0 and (.status.readyReplicas // 0) == 0 and (.status.observedGeneration // 0) >= .metadata.generation' >/dev/null || refuse 'remote signer is not stopped'
  kubectl -n "$namespace" get statefulset "$client" -o json | jq -e '.spec.replicas == 0 and (.status.replicas // 0) == 0 and (.status.readyReplicas // 0) == 0 and (.status.observedGeneration // 0) >= .metadata.generation' >/dev/null || refuse 'validator client is not stopped'
  kubectl -n "$namespace" get deployment "$fence" -o json | jq -e '.spec.replicas == 0 and (.status.replicas // 0) == 0 and (.status.readyReplicas // 0) == 0 and (.status.observedGeneration // 0) >= .metadata.generation' >/dev/null || refuse 'signing fence is not stopped'
  kubectl get pods --all-namespaces -o json | jq -e --arg set "$set_id" '[.items[] | select(.metadata.labels["node-operator.io/validator-set"] == $set and (.metadata.labels["app.kubernetes.io/component"] == "validator-client" or .metadata.labels["app.kubernetes.io/component"] == "validator-remote-signer" or .metadata.labels["app.kubernetes.io/component"] == "validator-signing-fence"))] | length == 0' >/dev/null || refuse 'a signing-path Pod remains'
  [ -z "$(kubectl -n "$namespace" get lease "$lease" -o jsonpath='{.spec.holderIdentity}')" ] || refuse 'active signing lease holder remains'
}
assert_stopped
read_fresh_floor
pvc_json="$(kubectl -n "$namespace" get pvc "$pvc" -o json)"
pvc_uid="$(jq -er --arg set "$set_id" 'select(.status.phase == "Bound" and .metadata.labels["node-operator.io/validator-set"] == $set and (.metadata.uid | type == "string" and length > 0)) | .metadata.uid' <<<"$pvc_json")" || refuse 'retained slashing DB PVC is not exactly bound and Bound'
signer_json="$(kubectl -n "$namespace" get deployment "$signer" -o json)"
web3signer_image="$(jq -er '.spec.template.spec.containers[] | select(.name == "web3signer") | .image' <<<"$signer_json")" || refuse 'staged signer image is unavailable'
db_controller="$(kubectl -n "$namespace" get statefulset "$database" -o json)"
db_image="$(jq -er '.spec.template.spec.containers[] | select(.name == "postgres") | .image' <<<"$db_controller")" || refuse 'staged database image is unavailable'
db_uid="$(jq -er 'select(.spec.replicas == 1 and .status.readyReplicas == 1) | .metadata.uid | strings | select(length > 0)' <<<"$db_controller")" || refuse 'database must be a ready singleton'
inventory="$repository_root/.ci/validator/approved-runtime-images.json"
approved_signer="$(jq -er '.images.web3signer | select(.reference == "26.4.2") | .source' "$inventory")"
approved_db="$(jq -er '.images.postgres.source' "$inventory")"
[[ "$web3signer_image" =~ ^[0-9]{12}\.dkr\.ecr\.ap-northeast-2\.amazonaws\.com/[a-z0-9-]+-validator-runtime-web3signer@sha256:[0-9a-f]{64}$ && "${web3signer_image#*@}" = "${approved_signer#*@}" ]] || refuse 'staged Web3Signer image is not the approved immutable runtime'
[[ "$db_image" =~ ^[0-9]{12}\.dkr\.ecr\.ap-northeast-2\.amazonaws\.com/[a-z0-9-]+-validator-runtime-postgres@sha256:[0-9a-f]{64}$ && "${db_image#*@}" = "${approved_db#*@}" && "${db_image%%/*}" = "${web3signer_image%%/*}" ]] || refuse 'staged PostgreSQL image is not the approved same-registry runtime'
pv="$(jq -er '.spec.volumeName | strings | select(test("^[a-z0-9][a-z0-9.-]*$"))' <<<"$pvc_json")" || refuse 'PVC has no bound volume'
kubectl get pv "$pv" -o json | jq -e --arg uid "$pvc_uid" --arg claim "$pvc" --arg ns "$namespace" '.spec.claimRef.uid == $uid and .spec.claimRef.name == $claim and .spec.claimRef.namespace == $ns and .status.phase == "Bound"' >/dev/null || refuse 'PV does not belong to the retained claim'
# Bind the service address used below to exactly the retained StatefulSet Pod.
db_pod="${database}-0"
db_pod_json="$(kubectl -n "$namespace" get pod "$db_pod" -o json)"
db_pod_uid="$(jq -er --arg set "$set_id" '.metadata.uid as $uid | select(.metadata.labels["app.kubernetes.io/component"] == "validator-slashing-db" and .metadata.labels["node-operator.io/validator-set"] == $set and (.status.phase == "Running")) | $uid' <<<"$db_pod_json")" || refuse 'retained slashing DB Pod is not the exact running target'
jq -e --arg uid "$db_uid" --arg claim "$pvc" --arg image "$db_image" '
  .metadata.deletionTimestamp == null and
  any(.metadata.ownerReferences[]?; .controller == true and .kind == "StatefulSet" and .uid == $uid) and
  any(.status.conditions[]?; .type == "Ready" and .status == "True") and
  ([.spec.volumes[]? | select(.persistentVolumeClaim != null)] | length == 1) and
  any(.spec.volumes[]?; .persistentVolumeClaim.claimName == $claim) and
  any(.spec.containers[]?; .name == "postgres" and .image == $image and
    any(.volumeMounts[]?; .mountPath == "/var/lib/postgresql/data" and .name as $name |
      $name != null))
' <<<"$db_pod_json" >/dev/null || refuse 'DB Pod owner, readiness, image, or retained claim is mismatched'
data_volume="$(jq -er '.spec.containers[] | select(.name == "postgres") | .volumeMounts[] | select(.mountPath == "/var/lib/postgresql/data") | .name' <<<"$db_pod_json")"
jq -e --arg volume "$data_volume" --arg claim "$pvc" 'any(.spec.volumes[]; .name == $volume and .persistentVolumeClaim.claimName == $claim)' <<<"$db_pod_json" >/dev/null || refuse 'PostgreSQL data mount is not the retained claim'
kubectl -n "$namespace" get service "$database" -o json | jq -e --arg set "$set_id" '.spec.selector == {"app.kubernetes.io/component":"validator-slashing-db","node-operator.io/validator-set":$set}' >/dev/null || refuse 'slashing DB Service selector is not exact'
db_endpoints() { kubectl -n "$namespace" get endpointslice -l "kubernetes.io/service-name=$database" -o json; }
db_endpoints | jq -e --arg uid "$db_pod_uid" --arg ip "$(jq -er '.status.podIP' <<<"$db_pod_json")" '[.items[].endpoints[]?] as $endpoints | ($endpoints | length == 1 and .[0].targetRef.uid == $uid and .[0].conditions.ready == true and .[0].conditions.terminating != true and .[0].addresses == [$ip]) and all(.items[].ports[]?; .port == 5432 and .protocol == "TCP")' >/dev/null || refuse 'slashing DB EndpointSlice is not exactly bound to retained DB Pod'
bindings() {
  kubectl -n "$namespace" get deployment "$signer" "$fence" -o json | jq -cer '[.items[] | {uid:.metadata.uid,generation:.metadata.generation,resourceVersion:.metadata.resourceVersion,specReplicas:.spec.replicas}] | sort_by(.uid)'
  kubectl -n "$namespace" get statefulset "$client" "$database" -o json | jq -cer '[.items[] | {uid:.metadata.uid,generation:.metadata.generation,resourceVersion:.metadata.resourceVersion,specReplicas:.spec.replicas}] | sort_by(.uid)'
  kubectl -n "$namespace" get pvc "$pvc" -o json | jq -cer '{uid:.metadata.uid,resourceVersion:.metadata.resourceVersion,phase:.status.phase}'
  kubectl -n "$namespace" get pod "$db_pod" -o json | jq -cer '{uid:.metadata.uid,resourceVersion:.metadata.resourceVersion,phase:.status.phase}'
  kubectl -n "$namespace" get service "$database" -o json | jq -cer '{uid:.metadata.uid,resourceVersion:.metadata.resourceVersion,selector:.spec.selector}'
  kubectl get pv "$pv" -o json | jq -cer '{uid:.metadata.uid,resourceVersion:.metadata.resourceVersion,claim:.spec.claimRef}'
  db_endpoints | jq -cS '[.items[] | {uid:.metadata.uid,resourceVersion:.metadata.resourceVersion,endpoints:.endpoints,ports:.ports}] | sort_by(.uid)'
}
binding_before="$(bindings)"
planned_slot="$slot"; planned_epoch="$epoch"
# The reviewed v26.4.2 image layout makes this the native binary, not a shell/server wrapper.
gvr='0x212f13fc4df078b6cb7db228f1c8307566dcecf900867401a92023d7ba99cb5f'
printf '{"metadata":{"interchange_format_version":"5","genesis_validators_root":"%s"},"data":[{"pubkey":"%s","signed_blocks":[],"signed_attestations":[]}]}' "$gvr" "$public_key" > "$scratch/import.json"
kubectl -n "$namespace" create configmap "$config" --from-file=import.json="$scratch/import.json" --dry-run=client -o json | jq --arg op "$safe_operation" '.metadata.labels["node-operator.io/operation"] = $op' > "$scratch/config.json"

# Existing DB policy permits only the signer. These narrowly scoped, temporary
# policies grant this maintenance Job DNS, Vault, and the exact DB connection.
bindings_before_job="$(bindings)"; [ "$bindings_before_job" = "$binding_before" ] || refuse 'controller, PVC, Pod, or Service binding changed before native mutation'
assert_stopped
read_fresh_floor
tee "$scratch/policies.yaml" >/dev/null <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: $db_policy, labels: {node-operator.io/operation: $safe_operation}}
spec:
  podSelector: {matchLabels: {app.kubernetes.io/component: validator-slashing-db, node-operator.io/validator-set: $set_id}}
  policyTypes: [Ingress]
  ingress:
    - from: [{podSelector: {matchLabels: {app.kubernetes.io/component: slashing-history-maintenance, node-operator.io/validator-set: $set_id, node-operator.io/operation: $safe_operation}}}]
      ports: [{protocol: TCP, port: 5432}]
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: $job_policy, labels: {node-operator.io/operation: $safe_operation}}
spec:
  podSelector: {matchLabels: {app.kubernetes.io/component: slashing-history-maintenance, node-operator.io/validator-set: $set_id, node-operator.io/operation: $safe_operation}}
  policyTypes: [Egress]
  egress:
    - to: [{podSelector: {matchLabels: {app.kubernetes.io/component: validator-slashing-db, node-operator.io/validator-set: $set_id}}}]
      ports: [{protocol: TCP, port: 5432}]
    - to: [{namespaceSelector: {matchLabels: {kubernetes.io/metadata.name: vault}}, podSelector: {matchLabels: {app.kubernetes.io/name: vault}}}]
      ports: [{protocol: TCP, port: 8200}]
    - to: [{namespaceSelector: {matchLabels: {kubernetes.io/metadata.name: kube-system}}}]
      ports: [{protocol: UDP, port: 53}, {protocol: TCP, port: 53}]
EOF

# The maintenance Job carries only a public interchange record. Vault injects
# the existing DB pool file; neither this Job nor its ConfigMap mounts BLS keys.
kubectl -n "$namespace" create -f - >/dev/null <<EOF
apiVersion: batch/v1
kind: Job
metadata:
  name: $job
  labels: {app.kubernetes.io/component: slashing-history-maintenance, node-operator.io/validator-set: $set_id, node-operator.io/operation: $safe_operation}
spec:
  suspend: true
  activeDeadlineSeconds: 120
  backoffLimit: 0
  template:
    metadata:
      labels: {app.kubernetes.io/component: slashing-history-maintenance, node-operator.io/validator-set: $set_id, node-operator.io/operation: $safe_operation, node-operator.io/vault-client: "true"}
      annotations:
        vault.hashicorp.com/agent-inject: "true"
        vault.hashicorp.com/agent-pre-populate-only: "true"
        vault.hashicorp.com/agent-service-account-token-volume-name: vault-auth
        vault.hashicorp.com/tls-secret: vault-agent-ca
        vault.hashicorp.com/ca-cert: /vault/tls/ca.crt
        vault.hashicorp.com/tls-server-name: vault.vault.svc
        vault.hashicorp.com/role: hoodi-$set_id-slashing-db
        vault.hashicorp.com/agent-inject-secret-slashing-db.properties: node-operator-runtime/data/validators/hoodi/$set_id/runtime/slashing-db-password
        vault.hashicorp.com/agent-init-first: "true"
        vault.hashicorp.com/agent-inject-template-slashing-db.properties: '{{- with secret "node-operator-runtime/data/validators/hoodi/$set_id/runtime/slashing-db-password" -}}password={{ .Data.data.password }}{{- end }}'
        vault.hashicorp.com/agent-inject-secret-postgres-password: node-operator-runtime/data/validators/hoodi/$set_id/runtime/slashing-db-password
        vault.hashicorp.com/agent-inject-template-postgres-password: '{{- with secret "node-operator-runtime/data/validators/hoodi/$set_id/runtime/slashing-db-password" -}}{{ .Data.data.password }}{{- end }}'
    spec:
      restartPolicy: Never
      serviceAccountName: validator-slashing-db
      automountServiceAccountToken: false
      securityContext: {runAsNonRoot: true, runAsUser: 999, runAsGroup: 999, fsGroup: 999, fsGroupChangePolicy: OnRootMismatch, seccompProfile: {type: RuntimeDefault}}
      volumes:
        - name: public-import
          # The interchange record contains only public metadata and a public
          # key. Web3Signer runs as UID 999, so do not rely on fsGroup mode
          # mutation to make a root-owned ConfigMap file readable.
          configMap: {name: $config, defaultMode: 0444}
        - name: vault-auth
          projected: {sources: [{serviceAccountToken: {audience: vault, expirationSeconds: 600, path: token}}]}
        - name: maintenance-tmp
          emptyDir: {}
      initContainers:
        - name: strict-singleton-preflight
          image: $db_image
          command: ["/bin/sh", "-ec"]
          args:
            - |
              export PGPASSWORD="\$(cat /vault/secrets/postgres-password)"
              test -n "\${PGPASSWORD}"
              test "\$(psql -Atq -v ON_ERROR_STOP=1 -h $database.$namespace.svc -U web3signer -d web3signer -c 'SELECT version FROM database_version WHERE id = 1')" = 12
              test "\$(psql -Atq -v ON_ERROR_STOP=1 -h $database.$namespace.svc -U web3signer -d web3signer -c "SELECT count(*) FROM metadata WHERE encode(genesis_validators_root, 'hex') <> '${gvr#0x}'")" = 0
              test "\$(psql -Atq -v ON_ERROR_STOP=1 -h $database.$namespace.svc -U web3signer -d web3signer -c 'SELECT count(*) FROM metadata')" -le 1
              test "\$(psql -Atq -v ON_ERROR_STOP=1 -h $database.$namespace.svc -U web3signer -d web3signer -c 'SELECT count(*) FROM validators')" -le 1
              test "\$(psql -Atq -v ON_ERROR_STOP=1 -h $database.$namespace.svc -U web3signer -d web3signer -c "SELECT count(*) FROM validators WHERE encode(public_key, 'hex') <> '${public_key#0x}'")" = 0
              if test "\$(psql -Atq -v ON_ERROR_STOP=1 -h $database.$namespace.svc -U web3signer -d web3signer -c 'SELECT count(*) FROM validators')" = 0; then touch /work-state/import-needed; fi
          volumeMounts: [{name: vault-auth, mountPath: /var/run/secrets/vault.hashicorp.com/serviceaccount, readOnly: true}, {name: maintenance-tmp, mountPath: /work-state}]
          resources: {requests: {cpu: 100m, memory: 128Mi}, limits: {cpu: 500m, memory: 256Mi}}
          securityContext: {allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, capabilities: {drop: ["ALL"]}}
        - name: native-watermark-repair
          image: $web3signer_image
          command: ["/bin/sh", "-ec"]
          args:
            - |
              test \$(date +%s) -lt $((1742213400 + planned_slot * 12))
              test ! -e /work-state/import-needed || {
                export WEB3SIGNER_ETH2_SLASHING_PROTECTION_DB_PASSWORD="\$(cat /vault/secrets/postgres-password)"
                test -n "\${WEB3SIGNER_ETH2_SLASHING_PROTECTION_DB_PASSWORD}"
                exec /opt/web3signer/bin/web3signer eth2 --slashing-protection-db-url=jdbc:postgresql://$database.$namespace.svc:5432/web3signer --slashing-protection-db-username=web3signer --slashing-protection-db-pool-configuration-file=/vault/secrets/slashing-db.properties import --from /work/import.json
              }
          volumeMounts: [{name: public-import, mountPath: /work, readOnly: true}, {name: vault-auth, mountPath: /var/run/secrets/vault.hashicorp.com/serviceaccount, readOnly: true}, {name: maintenance-tmp, mountPath: /tmp}, {name: maintenance-tmp, mountPath: /work-state}]
          resources: {requests: {cpu: 100m, memory: 256Mi}, limits: {cpu: 500m, memory: 512Mi}}
          securityContext: {allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, capabilities: {drop: ["ALL"]}}
        - name: native-watermark-repair-floor
          image: $web3signer_image
          command: ["/bin/sh", "-ec"]
          args:
            - |
              test \$(date +%s) -lt $((1742213400 + planned_slot * 12))
              export WEB3SIGNER_ETH2_SLASHING_PROTECTION_DB_PASSWORD="\$(cat /vault/secrets/postgres-password)"
              test -n "\${WEB3SIGNER_ETH2_SLASHING_PROTECTION_DB_PASSWORD}"
              exec /opt/web3signer/bin/web3signer eth2 --slashing-protection-db-url=jdbc:postgresql://$database.$namespace.svc:5432/web3signer --slashing-protection-db-username=web3signer --slashing-protection-db-pool-configuration-file=/vault/secrets/slashing-db.properties watermark-repair --slot $planned_slot --epoch $planned_epoch
          volumeMounts: [{name: vault-auth, mountPath: /var/run/secrets/vault.hashicorp.com/serviceaccount, readOnly: true}, {name: maintenance-tmp, mountPath: /tmp}]
          resources: {requests: {cpu: 100m, memory: 256Mi}, limits: {cpu: 500m, memory: 512Mi}}
          securityContext: {allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, capabilities: {drop: ["ALL"]}}
      containers:
        - name: persisted-floor-check
          image: $db_image
          command: ["/bin/sh", "-ec"]
          args:
            - |
              export PGPASSWORD="\$(cat /vault/secrets/postgres-password)"
              test -n "\${PGPASSWORD}"
              test "\$(psql -Atq -v ON_ERROR_STOP=1 -h $database.$namespace.svc -U web3signer -d web3signer -c "SELECT count(*) FROM metadata WHERE encode(genesis_validators_root, 'hex') = '${gvr#0x}'")" = 1
              test "\$(psql -Atq -v ON_ERROR_STOP=1 -h $database.$namespace.svc -U web3signer -d web3signer -c 'SELECT count(*) FROM validators')" = 1
              test "\$(psql -Atq -v ON_ERROR_STOP=1 -h $database.$namespace.svc -U web3signer -d web3signer -c "SELECT count(*) FROM validators WHERE encode(public_key, 'hex') = '${public_key#0x}'")" = 1
              test "\$(psql -Atq -v ON_ERROR_STOP=1 -h $database.$namespace.svc -U web3signer -d web3signer -c "SELECT count(*) FROM low_watermarks lw JOIN validators v ON v.id = lw.validator_id WHERE encode(v.public_key, 'hex') = '${public_key#0x}' AND lw.slot >= $planned_slot AND lw.source_epoch >= $planned_epoch AND lw.target_epoch >= $planned_epoch")" = 1
          volumeMounts: [{name: vault-auth, mountPath: /var/run/secrets/vault.hashicorp.com/serviceaccount, readOnly: true}]
          resources: {requests: {cpu: 100m, memory: 128Mi}, limits: {cpu: 500m, memory: 256Mi}}
          securityContext: {allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, capabilities: {drop: ["ALL"]}}
EOF
job_identity="$(kubectl -n "$namespace" get job "$job" -o json | jq -er --arg operation "$safe_operation" 'select(.metadata.labels["node-operator.io/operation"] == $operation) | [.metadata.uid,.metadata.resourceVersion] | @tsv')" || refuse 'created recovery mutex cannot be bound'
IFS=$'\t' read -r job_uid job_rv <<<"$job_identity"
# Job creation is the first external write. Only its owner can now create the
# dependencies and release suspension. Existing Job => no writes or deletions.
kubectl -n "$namespace" create -f "$scratch/config.json" >/dev/null
kubectl -n "$namespace" create -f "$scratch/policies.yaml" >/dev/null
bindings_before_unsuspend="$(bindings)"; [ "$bindings_before_unsuspend" = "$binding_before" ] || refuse 'binding changed before recovery mutex release'
assert_stopped
read_fresh_floor
[ "$beacon_head" -lt "$planned_slot" ] || refuse 'fresh Beacon head has overtaken prepared floor'
kubectl -n "$namespace" patch job "$job" --type=json -p "[{\"op\":\"test\",\"path\":\"/metadata/uid\",\"value\":\"$job_uid\"},{\"op\":\"test\",\"path\":\"/metadata/resourceVersion\",\"value\":\"$job_rv\"},{\"op\":\"replace\",\"path\":\"/spec/suspend\",\"value\":false}]" >/dev/null || refuse 'recovery mutex changed before release'
wait_for_native_job() {
  local deadline status
  deadline="$(( $(date +%s) + 180 ))"
  while :; do
    status="$(kubectl -n "$namespace" get "job/$job" -o json)" || refuse 'cannot read native maintenance Job status; signing remains stopped'
    if jq -e 'any(.status.conditions[]?; .type == "Complete" and .status == "True")' <<<"$status" >/dev/null; then
      return
    fi
    if jq -e '(.status.failed // 0) > 0 or any(.status.conditions[]?; .type == "Failed" and .status == "True")' <<<"$status" >/dev/null; then
      jq -c '{failed:(.status.failed // 0),succeeded:(.status.succeeded // 0)}' <<<"$status" >&2 || true
      refuse 'native maintenance Job failed; signing remains stopped'
    fi
    if [ "$(date +%s)" -ge "$deadline" ]; then
      jq -c '{failed:(.status.failed // 0),succeeded:(.status.succeeded // 0)}' <<<"$status" >&2 || true
      refuse 'native maintenance Job did not complete before bounded deadline; signing remains stopped'
    fi
    sleep 2
  done
}
wait_for_native_job
assert_stopped
[ "$(bindings)" = "$binding_before" ] || refuse 'controller, PVC, Pod, or Service binding changed during native preparation'
[ "$(kubectl -n "$namespace" get pvc "$pvc" -o jsonpath='{.metadata.uid}')" = "$pvc_uid" ] || refuse 'retained slashing DB PVC identity changed during preparation'
receipt="$output_dir/$operation.json"
set -o noclobber
umask 077; jq -n --arg at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --arg set "$set_id" --arg key "$public_key" --arg uid "$pvc_uid" --arg approval "$approval" --arg operation "$operation" --arg image "$web3signer_image" --arg job "$job" --arg job_uid "$job_uid" --argjson slot "$planned_slot" --argjson epoch "$planned_epoch" '{schema_version:1,event_type:"hoodi-missing-history-floor-preparation",collected_at_utc:$at,network:"hoodi",validator_set:$set,validator_public_key:$key,database:{pvc_uid:$uid},maintenance_job:{name:$job,uid:$job_uid,retained:true},web3signer:{image:$image,version:"26.4.2",native_binary:"/opt/web3signer/bin/web3signer"},requested_minimum_watermark_floor:{slot:$slot,source_epoch:$epoch,target_epoch:$epoch},persisted_at_least_requested:true,stopped_after:true,historical_evidence_recovered:false,no_slashing_guarantee:false,activation_required:true,exception_approval_id:$approval,operation_id:$operation,secret_values_emitted:false}' > "$receipt"
chmod 600 "$receipt"
printf 'PASS: Hoodi native floor preparation completed; signing remains stopped and activation is still required. Receipt: %s\n' "$receipt"
printf 'Retained maintenance Job for inspection (not automatically replayed): %s/%s\n' "$namespace" "$job"
