package nodeoperator.nethermind

import rego.v1

# This package evaluates each rendered object locally. It deliberately binds the
# Hoodi execution client to an exact image and storage/security posture without
# requiring cluster or AWS access.
expected_image := "nethermind/nethermind@sha256:ec5f6c8158dbf82d4ddbd5500f895c930f52aa3b4c998148d9e1b452793d828e"
expected_storage_class := "nethermind-hoodi-gp3-kms"

deny contains {"id": "nethermind.image-digest", "msg": "Nethermind must use the approved immutable v1.39.3-chiseled image digest"} if {
	is_nethermind_statefulset
	not has_expected_image
}

deny contains {"id": "nethermind.storage-claim", "msg": "Nethermind must request a 2Ti claim from the approved encrypted gp3 StorageClass"} if {
	is_nethermind_statefulset
	not has_expected_storage_claim
}

deny contains {"id": "nethermind.pod-hardening", "msg": "Nethermind pod and container must retain the hardened security context"} if {
	is_nethermind_statefulset
	not has_hardened_execution
}

deny contains {"id": "nethermind.workload-identity", "msg": "Nethermind must use its dedicated ServiceAccount without an API token mount"} if {
	is_nethermind_statefulset
	not has_isolated_workload_identity
}

deny contains {"id": "nethermind.probes", "msg": "Nethermind must define startup, readiness, and liveness TCP probes on P2P"} if {
	is_nethermind_statefulset
	not has_required_probes
}

deny contains {"id": "nethermind.prysm-anti-affinity", "msg": "Nethermind must require hostname anti-affinity with Prysm"} if {
	is_nethermind_statefulset
	not has_prysm_anti_affinity
}

deny contains {"id": "nethermind.storage-class", "msg": "Nethermind StorageClass must use encrypted gp3 with 10000 IOPS, 250 MiB/s throughput, and a KMS key"} if {
	is_nethermind_storage_class
	not has_expected_storage_class_parameters
}

# A selected policy may only name constrained peers. An omitted `to` list,
# broad ipBlock, blank peer, or unqualified namespace selector is world egress.
deny contains {"id": "nethermind.world-egress", "msg": "Nethermind NetworkPolicy must not allow world egress"} if {
	is_nethermind_network_policy
	allows_world_egress
}

is_nethermind_statefulset if {
	input.kind == "StatefulSet"
	object.get(input, "metadata", {}).name == "nethermind-execution"
}

is_nethermind_storage_class if {
	input.kind == "StorageClass"
	object.get(input, "metadata", {}).name == expected_storage_class
}

is_nethermind_network_policy if {
	input.kind == "NetworkPolicy"
	labels := object.get(object.get(object.get(input, "spec", {}), "podSelector", {}), "matchLabels", {})
	labels["app.kubernetes.io/name"] == "nethermind"
}

nethermind_container contains container if {
	is_nethermind_statefulset
	container := object.get(object.get(object.get(object.get(input, "spec", {}), "template", {}), "spec", {}), "containers", [])[_]
	container.name == "nethermind"
}

has_expected_image if {
	container := nethermind_container[_]
	container.image == expected_image
}

has_expected_storage_claim if {
	claim := object.get(object.get(input, "spec", {}), "volumeClaimTemplates", [])[_]
	object.get(claim, "metadata", {}).name == "nethermind-data"
	claim_spec := object.get(claim, "spec", {})
	claim_spec.storageClassName == expected_storage_class
	object.get(object.get(claim_spec, "resources", {}), "requests", {}).storage == "2Ti"
}

has_hardened_execution if {
	pod_spec := object.get(object.get(object.get(input, "spec", {}), "template", {}), "spec", {})
	pod_security := object.get(pod_spec, "securityContext", {})
	pod_security.runAsNonRoot == true
	pod_security.runAsUser == 1000
	pod_security.runAsGroup == 1000
	object.get(pod_security, "seccompProfile", {}).type == "RuntimeDefault"
	security := object.get(nethermind_container[_], "securityContext", {})
	security.allowPrivilegeEscalation == false
	security.readOnlyRootFilesystem == true
	security.runAsNonRoot == true
	security.runAsUser == 1000
	"ALL" in object.get(object.get(security, "capabilities", {}), "drop", [])
}

has_isolated_workload_identity if {
	pod_spec := object.get(object.get(object.get(input, "spec", {}), "template", {}), "spec", {})
	pod_spec.serviceAccountName == "nethermind-execution"
	pod_spec.automountServiceAccountToken == false
}

has_required_probes if {
	container := nethermind_container[_]
	object.get(object.get(container, "startupProbe", {}), "tcpSocket", {}).port == "p2p-tcp"
	object.get(object.get(container, "readinessProbe", {}), "tcpSocket", {}).port == "p2p-tcp"
	object.get(object.get(container, "livenessProbe", {}), "tcpSocket", {}).port == "p2p-tcp"
}

has_prysm_anti_affinity if {
	pod_spec := object.get(object.get(object.get(input, "spec", {}), "template", {}), "spec", {})
	term := object.get(object.get(object.get(pod_spec, "affinity", {}), "podAntiAffinity", {}), "requiredDuringSchedulingIgnoredDuringExecution", [])[_]
	term.topologyKey == "kubernetes.io/hostname"
	object.get(object.get(term, "labelSelector", {}), "matchLabels", {})["app.kubernetes.io/name"] == "prysm-beacon"
}

has_expected_storage_class_parameters if {
	input.provisioner == "ebs.csi.aws.com"
	parameters := object.get(input, "parameters", {})
	parameters.type == "gp3"
	parameters.iops == "10000"
	parameters.throughput == "250"
	parameters.encrypted == "true"
	kms_key := object.get(parameters, "kmsKeyId", "")
	is_string(kms_key)
	count(trim_space(kms_key)) > 0
}

allows_world_egress if {
	rule := object.get(object.get(input, "spec", {}), "egress", [])[_]
	count(object.get(rule, "to", [])) == 0
}

allows_world_egress if {
  rule := object.get(object.get(input, "spec", {}), "egress", [])[_]
  peer := object.get(rule, "to", [])[_]
  object.get(peer, "ipBlock", {}).cidr in {"0.0.0.0/0", "::/0"}
  not approved_hoodi_nat_rule(rule)
}

allows_world_egress if {
	rule := object.get(object.get(input, "spec", {}), "egress", [])[_]
	peer := object.get(rule, "to", [])[_]
	count(peer) == 0
}

approved_hoodi_nat_rule(rule) if {
  metadata := object.get(input, "metadata", {})
  metadata.name == "allow-nethermind-nat-port-egress"
  object.get(metadata, "labels", {})["node-operator.io/egress-class"] == "hoodi-nat-port-restricted"
  peer := object.get(rule, "to", [])[0]
  object.get(peer, "ipBlock", {}).cidr == "0.0.0.0/0"
  count(object.get(rule, "to", [])) == 1
  ports := object.get(rule, "ports", [])
  count(ports) == 1
  ports[0].port == 30303
  upper(ports[0].protocol) in {"TCP", "UDP"}
}

approved_hoodi_nat_rule(rule) if {
  metadata := object.get(input, "metadata", {})
  metadata.name == "allow-nethermind-nat-port-egress"
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
