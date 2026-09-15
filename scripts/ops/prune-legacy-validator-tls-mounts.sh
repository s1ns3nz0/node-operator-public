#!/usr/bin/env bash
set -euo pipefail
umask 077

# Removes only obsolete, Kubernetes-Secret TLS mounts left behind by a prior
# server-side apply.  This is deliberately a maintenance operation, not a
# workload renderer: it requires the client and signing fence to be quiesced
# and refuses every unexpected template shape.
dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
usage() { printf 'Usage: %s --validator-set <hoodi-id> --execute\n' "${0##*/}" >&2; exit 64; }
validator_set=''; execute=false
while [ "$#" -gt 0 ]; do
  case "$1" in
    --validator-set) validator_set="${2:-}"; shift 2 ;;
    --execute) execute=true; shift ;;
    *) usage ;;
  esac
done
case "$validator_set" in hoodi-[a-z0-9][a-z0-9-]*) ;; *) usage ;; esac
[ "$execute" = true ] || usage
for command in kubectl jq; do command -v "$command" >/dev/null 2>&1 || { printf 'missing command: %s\n' "$command" >&2; exit 69; }; done

namespace='validator-operations'
"$dir/assert-hoodi-validator-quiesced.sh" --validator-set "$validator_set" >/dev/null || {
  printf '%s\n' 'validator client and signing fence must be completely quiesced before pruning legacy TLS mounts' >&2
  exit 65
}

fail_shape() { printf 'refusing legacy TLS mount prune: %s\n' "$1" >&2; exit 65; }

prune_workload() {
  local kind="$1" workload="$2" container="$3" volume_name="$4" secret_name="$5" vault_args="$6"
  local document state patch
  document="$(kubectl -n "$namespace" get "$kind" "$workload" -o json)" || fail_shape "cannot read ${kind}/${workload}"
  state="$(jq -ce --arg container "$container" --arg volume_name "$volume_name" --arg secret_name "$secret_name" --arg vault_args "$vault_args" '
    (.metadata.resourceVersion | select(type == "string" and length > 0)) as $resource_version |
    (.spec.template.spec // error("missing Pod template")) as $pod |
    ($pod.containers // []) as $containers |
    ([range(0; $containers | length) | select($containers[.].name == $container)]) as $container_indices |
    if $container_indices | length != 1 then error("expected exactly one named workload container") else . end |
    ($container_indices[0]) as $container_index |
    ($containers[$container_index].args // []) as $args |
    ($vault_args | split(":::")) as $required_args |
    if all($required_args[]; . as $required | $args | index($required) != null) then . else error("workload arguments are not Vault TLS paths") end |
    ($pod.volumes // []) as $volumes |
    ([range(0; $volumes | length) | select($volumes[.].name == $volume_name)]) as $volume_indices |
    ([range(0; $volumes | length) | select($volumes[.].secret.secretName? == $secret_name)]) as $secret_indices |
    ([range(0; ($containers[$container_index].volumeMounts // [] | length)) | select($containers[$container_index].volumeMounts[.].name == $volume_name)]) as $mount_indices |
    ([range(0; $containers | length) | . as $i | ($containers[$i].volumeMounts // [])[]? | select(.name == $volume_name) | {container_index:$i,mount:.}]
      + [($pod.initContainers // [])[]?.volumeMounts[]? | select(.name == $volume_name) | {container_index:"init",mount:.}]) as $all_mounts |
    if ($volume_indices | length) == 0 and ($secret_indices | length) == 0 and ($all_mounts | length) == 0 then
      {state:"absent"}
    elif ($volume_indices | length) != 1 then error("legacy volume name is missing or ambiguous")
    elif ($secret_indices | length) != 1 or $secret_indices[0] != $volume_indices[0] then error("legacy volume Secret name does not match the exact expected Secret")
    elif ($all_mounts | length) != 1 or $all_mounts[0].container_index != $container_index or ($mount_indices | length) != 1 then error("legacy volume mount is missing, ambiguous, or belongs to another container")
    else
      {state:"present",resource_version:$resource_version,container_index:$container_index,volume_index:$volume_indices[0],volume:$volumes[$volume_indices[0]],mount_index:$mount_indices[0],mount:$all_mounts[0].mount}
    end
  ' <<<"$document")" || fail_shape "${kind}/${workload} has an unexpected legacy TLS volume, mount, container, or Vault argument shape"
  if [ "$(jq -r .state <<<"$state")" = absent ]; then
    printf 'PASS: %s/%s has no legacy %s TLS Secret mount to prune.\n' "$kind" "$workload" "$volume_name"
    return
  fi
  patch="$(jq -cn --arg rv "$(jq -r .resource_version <<<"$state")" --argjson volume_index "$(jq .volume_index <<<"$state")" --argjson volume "$(jq .volume <<<"$state")" --argjson mount_index "$(jq .mount_index <<<"$state")" --argjson mount "$(jq .mount <<<"$state")" --arg container_index "$(jq -r '.container_index // empty' <<<"$state")" '
    [
      {op:"test",path:"/metadata/resourceVersion",value:$rv},
      {op:"test",path:("/spec/template/spec/volumes/" + ($volume_index | tostring)),value:$volume},
      {op:"test",path:("/spec/template/spec/containers/" + $container_index + "/volumeMounts/" + ($mount_index | tostring)),value:$mount},
      {op:"remove",path:("/spec/template/spec/containers/" + $container_index + "/volumeMounts/" + ($mount_index | tostring))},
      {op:"remove",path:("/spec/template/spec/volumes/" + ($volume_index | tostring))}
    ]')"
  kubectl -n "$namespace" patch "$kind" "$workload" --type=json -p "$patch" --dry-run=server >/dev/null || fail_shape "server-side JSON Patch preflight rejected ${kind}/${workload}; no mutation attempted"
  kubectl -n "$namespace" patch "$kind" "$workload" --type=json -p "$patch" >/dev/null || fail_shape "JSON Patch conflict or failure for ${kind}/${workload}; no retry was attempted"
  printf 'PASS: removed only the exact legacy %s TLS Secret volume and mount from %s/%s.\n' "$volume_name" "$kind" "$workload"
}

signer="validator-${validator_set}-remote-signer"
client="validator-${validator_set}-client"
prune_workload deployment "$signer" web3signer signer-tls "validator-${validator_set}-signer-tls" '--tls-keystore-file=/vault/secrets/tls.p12:::--tls-keystore-password-file=/vault/secrets/tls-password.txt'
prune_workload statefulset "$client" validator client-tls "validator-${validator_set}-client-tls" '--validators-external-signer-http-client-cert=/vault/secrets/tls.crt:::--validators-external-signer-http-client-key=/vault/secrets/tls.key:::--validators-external-signer-http-ca-cert=/vault/secrets/ca.crt'
