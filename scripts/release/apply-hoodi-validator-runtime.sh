#!/usr/bin/env bash
# Apply the non-secret Hoodi runtime in the order required for validator client
# DNS, while deriving fence API egress from the connected private cluster.
set -euo pipefail

usage() {
  printf '%s\n' "usage: ${0##*/} --runtime /absolute/runtime.yaml --client /absolute/client.yaml --rendered-client /new/absolute/client.yaml --beacon-service /absolute/service.yaml --validator-set hoodi-id [--dry-run=server]" >&2
  exit 64
}

runtime=''; client=''; rendered_client=''; beacon_service=''; validator_set=''; dry_run=''
while [ "$#" -gt 0 ]; do
  case "$1" in
    --runtime) runtime="${2:-}"; shift 2 ;;
    --client) client="${2:-}"; shift 2 ;;
    --rendered-client) rendered_client="${2:-}"; shift 2 ;;
    --beacon-service) beacon_service="${2:-}"; shift 2 ;;
    --validator-set) validator_set="${2:-}"; shift 2 ;;
    --dry-run=server) dry_run='--dry-run=server'; shift ;;
    *) usage ;;
  esac
done

case "$runtime:$client:$rendered_client:$beacon_service" in /*:/*:/*:/*) ;; *) usage ;; esac
[[ "$validator_set" =~ ^hoodi-[a-z0-9][a-z0-9-]*$ ]] || usage
[ "${PRIVATE_EKS_SESSION:-}" = 1 ] || { printf '%s\n' 'runtime apply requires an established private EKS session' >&2; exit 65; }
for file in "$runtime" "$client" "$beacon_service"; do
  [ -f "$file" ] && [ ! -L "$file" ] || { printf 'unsafe runtime input: %s\n' "$file" >&2; exit 65; }
done
[ ! -e "$rendered_client" ] && [ ! -L "$rendered_client" ] || { printf '%s\n' 'derived runtime client manifest must be new' >&2; exit 65; }
for command in kubectl ruby mktemp mv chmod; do command -v "$command" >/dev/null 2>&1 || { printf 'missing command: %s\n' "$command" >&2; exit 69; }; done

# Discover and render before any mutation. The Service is applied only after
# the exact fence policy has been derived and validated successfully.
service_json="$(kubectl -n default get service kubernetes -o json)"
endpoints_json="$(kubectl -n default get endpoints kubernetes -o json)"

temporary="$(mktemp "${rendered_client}.egress.XXXXXX")"
cleanup() { [ -z "${temporary:-}" ] || [ ! -e "$temporary" ] || rm -f "$temporary"; }
trap cleanup EXIT INT TERM
ruby -rjson -ryaml -ripaddr - "$client" "$temporary" "$validator_set" "$service_json" "$endpoints_json" <<'RUBY'
source, target, validator_set, service_raw, endpoints_raw = ARGV
fail = ->(message) { warn message; exit 65 }
private_ipv4 = lambda do |value|
  ip = IPAddr.new(value)
  ip.ipv4? && ip.private? && value == ip.to_s
rescue IPAddr::InvalidAddressError
  false
end

service = JSON.parse(service_raw)
endpoints = JSON.parse(endpoints_raw)
service_ip = service.dig("spec", "clusterIP")
fail.call("Kubernetes API Service discovery returned an invalid ClusterIP") unless service_ip.is_a?(String) && private_ipv4.call(service_ip)
endpoint_ips = endpoints.fetch("subsets", []).flat_map { |subset| subset.fetch("addresses", []).map { |address| address["ip"] } }.uniq
fail.call("Kubernetes API endpoint discovery returned no addresses") if endpoint_ips.empty?
fail.call("Kubernetes API endpoint discovery returned a malformed address") unless endpoint_ips.all? { |address| address.is_a?(String) && private_ipv4.call(address) }
allowed_ips = ([service_ip] + endpoint_ips).uniq

# macOS ships Psych 3.x, whose load_stream does not accept safe-load keyword
# arguments. These are installer-produced, non-secret manifests and are
# structurally validated below before any mutation or apply.
documents = File.read(source).split(/^---\s*$/).map do |document|
  Psych.safe_load(document, permitted_classes: [], permitted_symbols: [], aliases: false)
end.compact
name = "validator-#{validator_set}-signing-fence-egress"
matches = documents.select { |document| document.is_a?(Hash) && document["kind"] == "NetworkPolicy" && document.dig("metadata", "name") == name }
fail.call("expected one set-scoped signing-fence egress policy") unless matches.length == 1
policy = matches.first
expected_selector = {"app.kubernetes.io/component" => "validator-signing-fence", "node-operator.io/validator-set" => validator_set}
fail.call("signing-fence egress selector is not exact") unless policy.dig("metadata", "namespace") == "validator-operations" && policy.dig("spec", "podSelector", "matchLabels") == expected_selector && policy.dig("spec", "policyTypes") == ["Egress"]
egress = policy.dig("spec", "egress")
fail.call("signing-fence egress policy is malformed") unless egress.is_a?(Array)
api_rules = egress.select { |rule| rule["ports"] == [{"protocol" => "TCP", "port" => 443}] }
fail.call("signing-fence API egress policy is missing") if api_rules.empty?
fail.call("signing-fence API egress must contain only IP blocks") unless api_rules.all? { |rule| rule["to"].is_a?(Array) && !rule["to"].empty? && rule["to"].all? { |destination| destination.keys == ["ipBlock"] && destination.dig("ipBlock", "cidr").is_a?(String) } }
egress.reject! { |rule| api_rules.include?(rule) }
egress << {"to" => allowed_ips.map { |ip| {"ipBlock" => {"cidr" => "#{ip}/32"}} }, "ports" => [{"protocol" => "TCP", "port" => 443}]}

File.open(target, "w", 0o600) { |out| out.write(YAML.dump_stream(*documents)) }
RUBY
chmod 600 "$temporary"
mv "$temporary" "$rendered_client"
temporary=''
# The Service must precede the runtime apply so the client can resolve
# prysm-beacon; all discovery/rendering failures above leave Kubernetes intact.
if [ -n "$dry_run" ]; then kubectl apply --dry-run=server -f "$beacon_service" >/dev/null
else kubectl apply -f "$beacon_service" >/dev/null; fi
if [ -n "$dry_run" ]; then kubectl apply --dry-run=server -f "$runtime" -f "$rendered_client" >/dev/null
else kubectl apply -f "$runtime" -f "$rendered_client" >/dev/null; fi
if [ -n "$dry_run" ]; then
  printf '%s\n' 'PASS: server-side dry-run validated Prysm Service-before-runtime ordering and bounded fence API egress; no resources were applied.' >&2
else
  printf '%s\n' 'PASS: Prysm Service preceded runtime apply; fence API egress is limited to the discovered Kubernetes Service and private endpoints.' >&2
fi
