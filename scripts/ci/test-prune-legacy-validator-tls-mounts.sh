#!/usr/bin/env bash
# Check objective: Ensure legacy validator TLS mounts are removed without broadening runtime access.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
script="$root/scripts/ops/prune-legacy-validator-tls-mounts.sh"
test -x "$script"; bash -n "$script"
scratch="$(mktemp -d "${TMPDIR:-/tmp}/node-operator-prune-legacy-tls.XXXXXX")"
trap 'rm -rf "$scratch"' EXIT
mkdir "$scratch/bin"

cat > "$scratch/bin/kubectl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
trace() { printf '%s\n' "$*" >> "$MOCK_TRACE"; }
workload() {
  local kind="$1" name="$2" volume="$3" secret="$4" container="$5" args="$6" replicas="$7"
  local volumes='[]' mounts='[]'
  [ "${MOCK_MODE}" != legacyargs ] || args='["--tls-keystore-file=/etc/web3signer-tls/tls.p12"]'
  if [ "${MOCK_MODE}" != absent ]; then
    [ "${MOCK_MODE}" != wrong ] || secret="wrong-secret"
    volumes="[{\"name\":\"$volume\",\"secret\":{\"secretName\":\"$secret\"}},{\"name\":\"preserve\",\"emptyDir\":{}}]"
    mounts="[{\"name\":\"$volume\",\"mountPath\":\"/legacy\",\"readOnly\":true},{\"name\":\"preserve\",\"mountPath\":\"/preserve\"}]"
  fi
  jq -n --arg kind "$kind" --arg name "$name" --arg container "$container" --argjson args "$args" --argjson volumes "$volumes" --argjson mounts "$mounts" --argjson replicas "$replicas" \
    '{kind:$kind,metadata:{name:$name,resourceVersion:"rv-1"},spec:{replicas:$replicas,template:{spec:{volumes:$volumes,containers:[{name:$container,args:$args,volumeMounts:$mounts}]}}},status:{replicas:$replicas,readyReplicas:$replicas,observedGeneration:1}}'
}
case "$*" in
  '-n validator-operations get statefulset validator-hoodi-example-client -o json')
    replicas=0; [ "${MOCK_MODE}" != active ] || replicas=1
    workload StatefulSet validator-hoodi-example-client client-tls validator-hoodi-example-client-tls validator '["--validators-external-signer-http-client-cert=/vault/secrets/tls.crt","--validators-external-signer-http-client-key=/vault/secrets/tls.key","--validators-external-signer-http-ca-cert=/vault/secrets/ca.crt"]' "$replicas" ;;
  '-n validator-operations get deployment validator-hoodi-example-signing-fence -o json')
    jq -n '{metadata:{resourceVersion:"rv-fence",generation:1},spec:{replicas:0},status:{replicas:0,readyReplicas:0,observedGeneration:1}}' ;;
  '-n validator-operations get pods -o json') printf '%s\n' '{"items":[]}' ;;
  '-n validator-operations get deployment validator-hoodi-example-remote-signer -o json')
    workload Deployment validator-hoodi-example-remote-signer signer-tls validator-hoodi-example-signer-tls web3signer '["--tls-keystore-file=/vault/secrets/tls.p12","--tls-keystore-password-file=/vault/secrets/tls-password.txt"]' 1 ;;
  *' patch deployment validator-hoodi-example-remote-signer --type=json -p '*|*' patch statefulset validator-hoodi-example-client --type=json -p '*)
    patch=''
    for ((i = 1; i <= $#; i++)); do
      if [ "${!i}" = -p ]; then
        next=$((i + 1)); patch="${!next}"; break
      fi
    done
    [ -n "$patch" ] || exit 64
    if [[ "$*" == *' patch deployment '* ]]; then volume=signer-tls; secret=validator-hoodi-example-signer-tls; else volume=client-tls; secret=validator-hoodi-example-client-tls; fi
    jq -e --arg volume "$volume" --arg secret "$secret" '
      length == 5 and
      .[0] == {op:"test",path:"/metadata/resourceVersion",value:"rv-1"} and
      .[1] == {op:"test",path:"/spec/template/spec/volumes/0",value:{name:$volume,secret:{secretName:$secret}}} and
      .[2] == {op:"test",path:"/spec/template/spec/containers/0/volumeMounts/0",value:{name:$volume,mountPath:"/legacy",readOnly:true}} and
      .[3] == {op:"remove",path:"/spec/template/spec/containers/0/volumeMounts/0"} and
      .[4] == {op:"remove",path:"/spec/template/spec/volumes/0"}
    ' <<<"$patch" >/dev/null
    trace "$*"
    ;;
  *) printf 'unexpected kubectl: %s\n' "$*" >&2; exit 64 ;;
esac
EOF
chmod 700 "$scratch/bin/kubectl"

run() {
  MOCK_MODE="$1" MOCK_TRACE="$scratch/trace" PATH="$scratch/bin:$PATH" \
    bash "$script" --validator-set hoodi-example --execute
}

: > "$scratch/trace"
run present >/dev/null
test "$(wc -l < "$scratch/trace" | tr -d ' ')" = 4 || { printf '%s\n' 'exact legacy mounts did not receive one preview and one CAS patch per workload' >&2; exit 1; }
grep -F 'remove' "$scratch/trace" >/dev/null
if grep -Ei 'get secret|force-conflicts|apply ' "$scratch/trace"; then printf '%s\n' 'prune helper read secrets or took broad ownership' >&2; exit 1; fi

: > "$scratch/trace"
run absent >/dev/null
test ! -s "$scratch/trace" || { printf '%s\n' 'already-removed legacy mounts must be a no-op' >&2; exit 1; }

: > "$scratch/trace"
if run wrong >/dev/null 2>&1; then printf '%s\n' 'wrong legacy Secret unexpectedly accepted' >&2; exit 1; fi
test ! -s "$scratch/trace" || { printf '%s\n' 'wrong legacy Secret reached a patch request' >&2; exit 1; }

: > "$scratch/trace"
if run active >/dev/null 2>&1; then printf '%s\n' 'active client unexpectedly allowed legacy mount prune' >&2; exit 1; fi
test ! -s "$scratch/trace" || { printf '%s\n' 'active client reached a patch request' >&2; exit 1; }

printf '%s\n' 'PASS: legacy validator TLS mount pruning requires quiescence and exact CAS-protected Secret mount shapes.'
: > "$scratch/trace"
if run legacyargs >/dev/null 2>&1; then printf '%s\n' 'legacy TLS arguments unexpectedly allowed mount pruning' >&2; exit 1; fi
test ! -s "$scratch/trace"
