#!/usr/bin/env bash
# Run only during a stopped-client maintenance window, through with-private-eks.sh.
# Fixed to the reviewed hoodi-example signer UID; never accepts real key material.
set -euo pipefail
umask 077
namespace=validator-operations
repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
evidence_dir="$(mktemp -d "${TMPDIR:-/tmp}/hoodi-signer-tls-evidence.XXXXXX")"
fixture="signer-tls-fixture-$(openssl rand -hex 4)"
printf 'TLS evidence directory: %s\n' "$evidence_dir"
cleanup() {
 local role uid name
 for role in pre badca badclient post; do
  if test -s "$evidence_dir/$role.created.json"; then
   uid="$(jq -er .metadata.uid "$evidence_dir/$role.created.json")"
   name="$(jq -er .metadata.name "$evidence_dir/$role.created.json")"
   jq -cn --arg uid "$uid" '{apiVersion:"v1",kind:"DeleteOptions",preconditions:{uid:$uid}}' | kubectl delete --raw "/api/v1/namespaces/validator-operations/pods/$name" -f - >/dev/null || return 1
  fi
 done
 if test -s "$evidence_dir/fixture.metadata.json"; then
  uid="$(jq -er .uid "$evidence_dir/fixture.metadata.json")"
  jq -cn --arg uid "$uid" '{apiVersion:"v1",kind:"DeleteOptions",preconditions:{uid:$uid}}' | kubectl delete --raw "/api/v1/namespaces/validator-operations/secrets/$fixture" -f - >/dev/null || return 1
 fi
 test ! -f "$evidence_dir/synthetic.key" || unlink "$evidence_dir/synthetic.key"
}
trap cleanup EXIT
kubectl -n "$namespace" get statefulset/validator-hoodi-example-client deployment/validator-hoodi-example-signing-fence -o json | jq -e '(.items|length)==2 and all(.items[];.spec.replicas==0)' >/dev/null
kubectl -n "$namespace" get pods -o json | jq -e 'all(.items[]; .metadata.labels["node-operator.io/validator-set"]!="hoodi-example" or (.metadata.labels["app.kubernetes.io/component"]!="validator-client" and .metadata.labels["app.kubernetes.io/component"]!="validator-signing-fence"))' >/dev/null
kubectl -n "$namespace" get lease validator-hoodi-example-primary -o json | jq -e '(.spec.holderIdentity//"")==""' >/dev/null
kubectl -n "$namespace" get deployment validator-hoodi-example-remote-signer -o json | jq -e '.metadata.uid=="d173bc2b-7e77-4864-84c9-9074c853c700" and .spec.replicas==1 and .status.readyReplicas==1 and .status.observedGeneration==.metadata.generation' >/dev/null
kubectl -n "$namespace" get networkpolicy -o json | jq -S '[.items[]|{name:.metadata.name,uid:.metadata.uid,spec}]|sort_by(.name)' > "$evidence_dir/policies-before.json"
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$evidence_dir/synthetic.key" -out "$evidence_dir/synthetic.crt" -days 1 -subj /CN=synthetic-untrusted-probe -addext extendedKeyUsage=clientAuth > "$evidence_dir/cert-generation.log" 2>&1
kubectl -n "$namespace" create secret generic "$fixture" --from-file="tls.crt=$evidence_dir/synthetic.crt" --from-file="tls.key=$evidence_dir/synthetic.key" --from-file="ca.crt=$evidence_dir/synthetic.crt" -o json | jq '.metadata|{name,uid}' > "$evidence_dir/fixture.metadata.json"
unlink "$evidence_dir/synthetic.key"
python3 "$repo/scripts/ops/render-signer-tls-probes.py" --validator-set hoodi-example --expected-public-key 0xa3866b82651039224bfd725fc81e7ff17c1765021dff37f3fd4bc01405e2ed14c97c7c5c82cd95104d8f82c4229ab0d0 --fixture-name "$fixture" > "$evidence_dir/probes.json"
kubectl create --dry-run=server -f "$evidence_dir/probes.json" >/dev/null
for role in pre badca badclient post; do
 jq --arg role "$role" '.items[]|select(.metadata.labels["node-operator.io/probe-role"]==$role)' "$evidence_dir/probes.json" | kubectl create -f - -o json > "$evidence_dir/$role.created.json"
 name="$(jq -er .metadata.name "$evidence_dir/$role.created.json")"
 uid="$(jq -er .metadata.uid "$evidence_dir/$role.created.json")"
 for _ in $(seq 1 60); do
  kubectl -n "$namespace" get pod "$name" -o json > "$evidence_dir/$role.status.json"
  jq -e --arg uid "$uid" '.metadata.uid==$uid' "$evidence_dir/$role.status.json" >/dev/null
  if jq -e '.status.phase=="Succeeded" or .status.phase=="Failed"' "$evidence_dir/$role.status.json" >/dev/null; then break; fi
  sleep 2
 done
 kubectl -n "$namespace" logs "$name" -c get-only-identity-probe > "$evidence_dir/$role.log"
 if [[ "$role" == pre || "$role" == post ]]; then
  jq -e '.status.phase=="Succeeded" and .status.containerStatuses[0].state.terminated.exitCode==0' "$evidence_dir/$role.status.json" >/dev/null
  jq -e '.tls_verified==true and .public_key_match==true and .public_key_count==1' "$evidence_dir/$role.log" >/dev/null
 else
  jq -e '.status.phase=="Failed" and .status.containerStatuses[0].state.terminated.exitCode==1' "$evidence_dir/$role.status.json" >/dev/null
  test "$(< "$evidence_dir/$role.log")" = 'signer identity probe failed: mutual TLS signer request failed'
 fi
 printf 'Verified TLS case: %s\n' "$role"
done
kubectl -n "$namespace" get networkpolicy -o json | jq -S '[.items[]|{name:.metadata.name,uid:.metadata.uid,spec}]|sort_by(.name)' > "$evidence_dir/policies-after.json"
cmp "$evidence_dir/policies-before.json" "$evidence_dir/policies-after.json"
kubectl -n "$namespace" get deployment validator-hoodi-example-remote-signer -o json | jq -e '.spec.replicas==1 and .status.readyReplicas==1' >/dev/null
cleanup
trap - EXIT
for role in pre badca badclient post; do
 test -z "$(kubectl -n "$namespace" get pod "signer-tls-$role-hoodi-example" --ignore-not-found -o name)"
done
test -z "$(kubectl -n "$namespace" get secret "$fixture" --ignore-not-found -o name)"
jq -n --arg dir "$evidence_dir" --slurpfile pre "$evidence_dir/pre.log" --slurpfile post "$evidence_dir/post.log" '{result:"passed",evidence_directory:$dir,pre:$pre[0],post:$post[0],bad_ca:"TLS request rejected",bad_client:"TLS request rejected",network_policies_unchanged:true,temporary_resources_removed:true,scope:"UC2 GET-only transport negative cases, not actual duty or complete runtime security clearance"}' > "$evidence_dir/result.json"
cat "$evidence_dir/result.json"
