#!/usr/bin/env bash
# Check objective: Verify service-first runtime application and fail-closed private Kubernetes API egress discovery.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
helper="$root/scripts/release/apply-hoodi-validator-runtime.sh"
scratch="$(mktemp -d "${TMPDIR:-/tmp}/node-operator-runtime-apply.XXXXXX")"
trap 'rm -rf "$scratch"' EXIT
tools="$scratch/tools"; mkdir "$tools"
runtime="$scratch/runtime.yaml"; client="$scratch/client.yaml"; rendered="$scratch/rendered-client.yaml"; service="$scratch/service.yaml"
printf '%s\n' 'apiVersion: v1
kind: ConfigMap
metadata: {name: runtime, namespace: validator-operations}' > "$runtime"
cp "$root/deploy/prysm/service.yaml" "$service"
write_client() {
  cat > "$client" <<'YAML'
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: validator-hoodi-example-signing-fence-egress
  namespace: validator-operations
spec:
  podSelector:
    matchLabels:
      app.kubernetes.io/component: validator-signing-fence
      node-operator.io/validator-set: hoodi-example
  policyTypes: [Egress]
  egress:
    - to: [{podSelector: {matchLabels: {app.kubernetes.io/component: validator-remote-signer, node-operator.io/validator-set: hoodi-example}}}]
      ports: [{protocol: TCP, port: 9000}]
    - to: [{ipBlock: {cidr: 127.0.0.1/32}}]
      ports: [{protocol: TCP, port: 443}]
YAML
}
write_client
cat > "$tools/kubectl" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "$KUBECTL_TRACE"
case "$*" in
  *'get service kubernetes -o json'*) printf '%s\n' '{"spec":{"clusterIP":"172.20.0.1"}}' ;;
  *'get endpoints kubernetes -o json'*) printf '%s\n' "${ENDPOINTS_JSON:?}" ;;
  *'apply -f '*) : ;;
  *) printf 'unexpected kubectl invocation: %s\n' "$*" >&2; exit 1 ;;
esac
SH
chmod 700 "$tools/kubectl"
run_helper() { KUBECTL_TRACE="$scratch/trace" ENDPOINTS_JSON="$1" PATH="$tools:$PATH" PRIVATE_EKS_SESSION=1 "$helper" --runtime "$runtime" --client "$client" --rendered-client "$rendered" --beacon-service "$service" --validator-set hoodi-example; }
run_helper '{"subsets":[{"addresses":[{"ip":"10.80.20.84"},{"ip":"10.80.5.80"}]}]}' >/dev/null
sed -n '3p' "$scratch/trace" | grep -F -- "apply -f $service" >/dev/null
sed -n '4p' "$scratch/trace" | grep -F -- "apply -f $runtime -f $rendered" >/dev/null
ruby -ryaml -e '
  p=YAML.load_stream(File.read(ARGV[0])).find{|d| d.is_a?(Hash) && d["kind"]=="NetworkPolicy"}; abort "policy missing" unless p
  abort "selector changed" unless p.dig("spec","podSelector","matchLabels")=={"app.kubernetes.io/component"=>"validator-signing-fence","node-operator.io/validator-set"=>"hoodi-example"}
  e=p.dig("spec","egress").find{|r| r["ports"]==[{"protocol"=>"TCP","port"=>443}]}
  abort "bounded API egress missing" unless e && e["to"].map{|x|x.dig("ipBlock","cidr")} == ["172.20.0.1/32","10.80.20.84/32","10.80.5.80/32"]
' "$rendered"
before="$(shasum -a 256 "$client" | awk '{print $1}')"; rm -f "$rendered"; : > "$scratch/trace"
if run_helper '{"subsets":[{"addresses":[{"ip":"not-an-ip"}]}]}' >/dev/null 2>&1; then
  printf '%s\n' 'malformed endpoint discovery unexpectedly succeeded' >&2; exit 1
fi
after="$(shasum -a 256 "$client" | awk '{print $1}')"
[ "$before" = "$after" ] || { printf '%s\n' 'malformed discovery rewrote the client manifest' >&2; exit 1; }
if rg -F 'apply ' "$scratch/trace" >/dev/null; then
  printf '%s\n' 'malformed discovery applied a Kubernetes resource' >&2; exit 1
fi
write_client; sed -i.bak 's/validator-signing-fence/other-component/' "$client"; rm -f "$client.bak" "$rendered"; : > "$scratch/trace"
if run_helper '{"subsets":[{"addresses":[{"ip":"10.80.20.84"}]}]}' >/dev/null 2>&1; then
  printf '%s\n' 'malformed fence policy unexpectedly succeeded' >&2; exit 1
fi
if rg -F 'apply ' "$scratch/trace" >/dev/null; then
  printf '%s\n' 'malformed fence policy applied a Kubernetes resource' >&2; exit 1
fi
printf '%s\n' 'PASS: runtime applies the Prysm Service first and fails closed unless bounded Kubernetes API egress discovery is valid.'
