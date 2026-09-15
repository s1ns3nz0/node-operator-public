#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
manifest="$root/deploy/validator/client-lease-fence-template.yaml"
model="$root/deploy/validator/client-lease-fence-security-model.md"
fail(){ printf 'FAIL validator signing fence contract: %s\n' "$*" >&2; exit 1; }
if ! test -f "$manifest" || ! test -f "$model"; then fail 'fence manifest/model missing'; fi
ruby -ryaml -e '
docs=YAML.load_stream(File.read(ARGV[0])).select{|d| d.is_a?(Hash)}
role=docs.find{|d| d["kind"]=="Role"} or abort "Role missing"
expected=[{"apiGroups"=>["coordination.k8s.io"],"resources"=>["leases"],"resourceNames"=>["validator-REPLACE_WITH_VALIDATOR_SET-primary"],"verbs"=>["get","patch"]},{"apiGroups"=>[""],"resources"=>["pods"],"resourceNames"=>["validator-REPLACE_WITH_VALIDATOR_SET-client-0"],"verbs"=>["get"]}]
abort "RBAC exceeds exact Lease and client Pod" unless role["rules"]==expected
binding=docs.find{|d| d["kind"]=="RoleBinding"} or abort "RoleBinding missing"
abort "shared client SA received authority" unless binding.dig("subjects",0,"name")=="validator-REPLACE_WITH_VALIDATOR_SET-client-fence"
deployment=docs.find{|d| d["kind"]=="Deployment"} or abort "fence Deployment missing"
spec=deployment.dig("spec","template","spec")
abort "implicit token mount" unless spec["automountServiceAccountToken"]==false
abort "projected token is not group-readable by fence only" unless spec["securityContext"]["fsGroup"]==65532 && spec.dig("volumes",0,"projected","defaultMode")==288
container=spec["containers"].first
abort "signing probe can pin kubelet IP" unless container.dig("readinessProbe","httpGet","port")=="health"
abort "client identity flag missing" unless container["args"].include?("--client-pod-name=validator-REPLACE_WITH_VALIDATOR_SET-client-0")
' "$manifest" || fail 'rendered security contract failed'
grep -Fq 'role deletion alone is not UC-5 fail-closed evidence' "$model" || fail 'Vault cached-key limit missing'
grep -Fq 'TLS passthrough' "$model" || fail 'end-to-end TLS boundary missing'
go test "$root/cmd/validator-signing-fence"
printf '%s\n' 'PASS validator signing fence has exact Lease/Pod RBAC, isolated projected identity, non-signing health probes, and tested fail-closed proxy logic.'
