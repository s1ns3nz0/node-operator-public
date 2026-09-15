package nodeoperator.prysm

import rego.v1

# This package deliberately evaluates each rendered Kubernetes object without
# cluster access. Together, the StatefulSet, StorageClass, and NetworkPolicy
# rules lock the static contract for the Hoodi Prysm workload.
expected_image := "offchainlabs/prysm-beacon-chain@sha256:49f8454eb2a756402eb781025e370eef7d613668c2914bad4cca9c1aa11fafa4"
expected_storage_class := "prysm-hoodi-gp3-kms"

deny contains {"id": "prysm.image-digest", "msg": "Prysm beacon-chain must use the approved v7.1.8 immutable image digest"} if {
	is_prysm_statefulset
	not has_expected_beacon_image
}

deny contains {"id": "prysm.storage-claim", "msg": "Prysm must request a 500Gi claim from the approved encrypted gp3 StorageClass"} if {
	is_prysm_statefulset
	not has_expected_storage_claim
}

deny contains {"id": "prysm.pod-hardening", "msg": "Prysm pod and beacon-chain container must retain the hardened security context"} if {
	is_prysm_statefulset
	not has_hardened_execution
}

deny contains {"id": "prysm.probes", "msg": "Prysm beacon-chain must define the required startup, readiness, and liveness probes"} if {
	is_prysm_statefulset
	not has_required_probes
}

deny contains {"id": "prysm.nethermind-anti-affinity", "msg": "Prysm must require hostname anti-affinity with Nethermind"} if {
	is_prysm_statefulset
	not has_nethermind_anti_affinity
}

deny contains {"id": "prysm.storage-class", "msg": "Prysm StorageClass must use encrypted gp3 with 6000 IOPS and 250 MiB/s throughput"} if {
	is_prysm_storage_class
	not has_expected_storage_class_parameters
}

# A Prysm-selected NetworkPolicy must never introduce an unrestricted route to
# the public internet. The generic runtime package also rejects these shapes;
# this workload-specific rule makes the static workload contract independently
# testable.
deny contains {"id": "prysm.world-egress", "msg": "Prysm NetworkPolicy must not allow world egress"} if {
	is_prysm_network_policy
	allows_world_egress
}

is_prysm_statefulset if {
	input.kind == "StatefulSet"
	metadata := object.get(input, "metadata", {})
	metadata.name == "prysm-beacon"
}

is_prysm_storage_class if {
	input.kind == "StorageClass"
	metadata := object.get(input, "metadata", {})
	metadata.name == expected_storage_class
}

is_prysm_network_policy if {
	input.kind == "NetworkPolicy"
	selector := object.get(object.get(input, "spec", {}), "podSelector", {})
	labels := object.get(selector, "matchLabels", {})
	labels["app.kubernetes.io/name"] == "prysm-beacon"
}

beacon_container contains container if {
	is_prysm_statefulset
	pod_spec := object.get(object.get(object.get(input, "spec", {}), "template", {}), "spec", {})
	container := object.get(pod_spec, "containers", [])[_]
	container.name == "beacon-chain"
}

has_expected_beacon_image if {
	container := beacon_container[_]
	container.image == expected_image
}

has_expected_storage_claim if {
	claim := object.get(object.get(input, "spec", {}), "volumeClaimTemplates", [])[_]
	metadata := object.get(claim, "metadata", {})
	metadata.name == "prysm-data"
	claim_spec := object.get(claim, "spec", {})
	claim_spec.storageClassName == expected_storage_class
	resources := object.get(claim_spec, "resources", {})
	requests := object.get(resources, "requests", {})
	requests.storage == "500Gi"
}

has_hardened_execution if {
	pod_spec := object.get(object.get(object.get(input, "spec", {}), "template", {}), "spec", {})
	pod_security := object.get(pod_spec, "securityContext", {})
	pod_security.runAsNonRoot == true
	pod_security.runAsUser == 1000
	pod_security.runAsGroup == 1000
	seccomp := object.get(pod_security, "seccompProfile", {})
	seccomp.type == "RuntimeDefault"
	container := beacon_container[_]
	security := object.get(container, "securityContext", {})
	security.allowPrivilegeEscalation == false
	security.readOnlyRootFilesystem == true
	security.runAsNonRoot == true
	security.runAsUser == 1000
	drops := object.get(object.get(security, "capabilities", {}), "drop", [])
	"ALL" in drops
}

has_required_probes if {
	container := beacon_container[_]
	startup := object.get(container, "startupProbe", {})
	startup_tcp := object.get(startup, "tcpSocket", {})
	startup_tcp.port == "beacon-api"
	readiness := object.get(container, "readinessProbe", {})
	readiness_http := object.get(readiness, "httpGet", {})
	readiness_http.path == "/eth/v1/node/health"
	readiness_http.port == "beacon-api"
	readiness_http.scheme == "HTTP"
	liveness := object.get(container, "livenessProbe", {})
	liveness_tcp := object.get(liveness, "tcpSocket", {})
	liveness_tcp.port == "beacon-api"
}

has_nethermind_anti_affinity if {
	pod_spec := object.get(object.get(object.get(input, "spec", {}), "template", {}), "spec", {})
	affinity := object.get(pod_spec, "affinity", {})
	pod_anti_affinity := object.get(affinity, "podAntiAffinity", {})
	term := object.get(pod_anti_affinity, "requiredDuringSchedulingIgnoredDuringExecution", [])[_]
	term.topologyKey == "kubernetes.io/hostname"
	labels := object.get(object.get(term, "labelSelector", {}), "matchLabels", {})
	labels["app.kubernetes.io/name"] == "nethermind"
}

has_expected_storage_class_parameters if {
	input.provisioner == "ebs.csi.aws.com"
	parameters := object.get(input, "parameters", {})
	parameters.type == "gp3"
	parameters.iops == "6000"
	parameters.throughput == "250"
	parameters.encrypted == "true"
	kms_key := object.get(parameters, "kmsKeyId", "")
	is_string(kms_key)
	count(trim_space(kms_key)) > 0
}

allows_world_egress if {
	rule := object.get(object.get(input, "spec", {}), "egress", [])[_]
	destinations := object.get(rule, "to", [])
	count(destinations) == 0
}

allows_world_egress if {
  rule := object.get(object.get(input, "spec", {}), "egress", [])[_]
  peer := object.get(rule, "to", [])[_]
  ip_block := object.get(peer, "ipBlock", {})
  ip_block.cidr in {"0.0.0.0/0", "::/0"}
  not approved_hoodi_nat_rule(rule)
}

allows_world_egress if {
	rule := object.get(object.get(input, "spec", {}), "egress", [])[_]
	peer := object.get(rule, "to", [])[_]
	count(peer) == 0
}

approved_hoodi_nat_rule(rule) if {
  metadata := object.get(input, "metadata", {})
  metadata.name == "allow-prysm-nat-port-egress"
  object.get(metadata, "labels", {})["node-operator.io/egress-class"] == "hoodi-nat-port-restricted"
  peer := object.get(rule, "to", [])[0]
  object.get(peer, "ipBlock", {}).cidr == "0.0.0.0/0"
  count(object.get(rule, "to", [])) == 1
  ports := object.get(rule, "ports", [])
  count(ports) == 1
  ports[0].port == 13000
  upper(ports[0].protocol) in {"TCP", "UDP"}
}

approved_hoodi_nat_rule(rule) if {
  metadata := object.get(input, "metadata", {})
  metadata.name == "allow-prysm-nat-port-egress"
  object.get(metadata, "labels", {})["node-operator.io/egress-class"] == "hoodi-nat-port-restricted"
  peer := object.get(rule, "to", [])[0]
  object.get(peer, "ipBlock", {}).cidr == "0.0.0.0/0"
  count(object.get(rule, "to", [])) == 1
  ports := object.get(rule, "ports", [])
  count(ports) == 1
  ports[0].port == 443
  upper(ports[0].protocol) == "TCP"
}

allows_world_egress if {
	rule := object.get(object.get(input, "spec", {}), "egress", [])[_]
	peer := object.get(rule, "to", [])[_]
	selector := object.get(peer, "namespaceSelector", null)
	selector != null
	labels := object.get(selector, "matchLabels", {})
	expressions := object.get(selector, "matchExpressions", [])
	count(labels) == 0
	count(expressions) == 0
}
