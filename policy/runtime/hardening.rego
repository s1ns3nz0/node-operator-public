package nodeoperator.runtime

import rego.v1

# These rules are evaluated against one rendered Kubernetes object at a time.
# They deliberately require no cluster state, credentials, or live admission
# endpoint, so the same bundle can be exercised by Conftest in CI.
deny contains {"msg": "containers must not run privileged", "id": "kubernetes.privileged"} if {
	container := workload_containers[_]
	object.get(object.get(container, "securityContext", {}), "privileged", false) == true
}

deny contains {"msg": "containers must run as non-root", "id": "kubernetes.non-root"} if {
	container := workload_containers[_]
	not container_runs_as_non_root(container)
}

deny contains {"msg": "containers must run as non-root", "id": "kubernetes.non-root"} if {
	container := workload_containers[_]
	object.get(object.get(container, "securityContext", {}), "runAsUser", -1) == 0
}

deny contains {"msg": "containers must use a read-only root filesystem", "id": "kubernetes.readonly-root"} if {
	container := workload_containers[_]
	object.get(object.get(container, "securityContext", {}), "readOnlyRootFilesystem", false) != true
}

deny contains {"msg": "containers must define CPU and memory requests and limits", "id": "kubernetes.resources"} if {
	container := workload_containers[_]
	not has_resource_requirements(container)
}

# Egress rules with no target, a wildcard peer, or a world-wide CIDR remove the
# default-deny boundary. This policy does not attempt to validate reachability;
# it only rejects rules that are unbounded by their own declaration.
deny contains {"msg": "NetworkPolicy egress must not allow unbounded destinations", "id": "kubernetes.egress-unbounded"} if {
	input.kind == "NetworkPolicy"
	rule := object.get(object.get(input, "spec", {}), "egress", [])[_]
	unbounded_egress_rule(rule)
}

workload_containers contains container if {
	pod_spec := pod_specs[_]
	containers := object.get(pod_spec, "containers", [])
	is_array(containers)
	container := containers[_]
	is_object(container)
}

workload_containers contains container if {
	pod_spec := pod_specs[_]
	containers := object.get(pod_spec, "initContainers", [])
	is_array(containers)
	container := containers[_]
	is_object(container)
}

pod_specs contains pod_spec if {
	input.kind in {"Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job"}
	pod_spec := object.get(object.get(object.get(input, "spec", {}), "template", {}), "spec", {})
	is_object(pod_spec)
}

pod_specs contains pod_spec if {
	input.kind == "CronJob"
	pod_spec := object.get(object.get(object.get(object.get(object.get(input, "spec", {}), "jobTemplate", {}), "spec", {}), "template", {}), "spec", {})
	is_object(pod_spec)
}

container_runs_as_non_root(container) if {
	object.get(object.get(container, "securityContext", {}), "runAsNonRoot", false) == true
}

container_runs_as_non_root(container) if {
	pod_spec := pod_specs[_]
	object.get(object.get(pod_spec, "securityContext", {}), "runAsNonRoot", false) == true
}

has_resource_requirements(container) if {
	resources := object.get(container, "resources", {})
	is_object(resources)
	requests := object.get(resources, "requests", {})
	is_object(requests)
	limits := object.get(resources, "limits", {})
	is_object(limits)
	valid_quantity(object.get(requests, "cpu", null))
	valid_quantity(object.get(requests, "memory", null))
	valid_quantity(object.get(limits, "cpu", null))
	valid_quantity(object.get(limits, "memory", null))
}

valid_quantity(quantity) if {
	is_string(quantity)
	count(trim_space(quantity)) > 0
}

valid_quantity(quantity) if {
	is_number(quantity)
	quantity > 0
}

unbounded_egress_rule(rule) if {
	not is_object(rule)
}

unbounded_egress_rule(rule) if {
	is_object(rule)
	destinations := object.get(rule, "to", [])
	not is_array(destinations)
}

unbounded_egress_rule(rule) if {
	is_object(rule)
	destinations := object.get(rule, "to", [])
	is_array(destinations)
	count(destinations) == 0
}

unbounded_egress_rule(rule) if {
  is_object(rule)
  destinations := object.get(rule, "to", [])
  is_array(destinations)
  peer := destinations[_]
  unbounded_egress_peer(peer)
}

unbounded_egress_rule(rule) if {
  is_object(rule)
  peer := object.get(rule, "to", [])[_]
  object.get(peer, "ipBlock", {}).cidr in {"0.0.0.0/0", "::/0"}
  not approved_hoodi_nat_egress(rule)
}

unbounded_egress_peer(peer) if {
	not is_object(peer)
}

unbounded_egress_peer(peer) if {
	is_object(peer)
	count(peer) == 0
}

unbounded_egress_peer(peer) if {
	is_object(peer)
	selector := object.get(peer, "namespaceSelector", null)
	selector != null
	unrestricted_selector(selector)
}

# Hoodi peers are dynamic, so a peer-IP allow-list would prevent sync. This is
# the one intentionally bounded exception: only the named workload policies
# may use the existing private NAT, only to their P2P port or HTTPS, and only
# when the dedicated Hoodi node security group independently enforces the same
# port set. Any other world CIDR remains an admission failure.
approved_hoodi_nat_egress(rule) if {
  metadata := object.get(input, "metadata", {})
  object.get(metadata, "labels", {})["node-operator.io/egress-class"] == "hoodi-nat-port-restricted"
  metadata.name == "allow-nethermind-nat-port-egress"
  allowed_world_port(rule, 30303, "TCP")
}

approved_hoodi_nat_egress(rule) if {
  metadata := object.get(input, "metadata", {})
  object.get(metadata, "labels", {})["node-operator.io/egress-class"] == "hoodi-nat-port-restricted"
  metadata.name == "allow-nethermind-nat-port-egress"
  allowed_world_port(rule, 30303, "UDP")
}

approved_hoodi_nat_egress(rule) if {
  metadata := object.get(input, "metadata", {})
  object.get(metadata, "labels", {})["node-operator.io/egress-class"] == "hoodi-nat-port-restricted"
  metadata.name in {"allow-nethermind-nat-port-egress", "allow-prysm-nat-port-egress"}
  allowed_world_port(rule, 443, "TCP")
}

approved_hoodi_nat_egress(rule) if {
  metadata := object.get(input, "metadata", {})
  object.get(metadata, "labels", {})["node-operator.io/egress-class"] == "hoodi-nat-port-restricted"
  metadata.name == "allow-prysm-nat-port-egress"
  allowed_world_port(rule, 13000, "TCP")
}

approved_hoodi_nat_egress(rule) if {
  metadata := object.get(input, "metadata", {})
  object.get(metadata, "labels", {})["node-operator.io/egress-class"] == "hoodi-nat-port-restricted"
  metadata.name == "allow-prysm-nat-port-egress"
  allowed_world_port(rule, 13000, "UDP")
}

allowed_world_port(rule, port, protocol) if {
  peers := object.get(rule, "to", [])
  count(peers) == 1
  object.get(peers[0], "ipBlock", {}).cidr == "0.0.0.0/0"
  ports := object.get(rule, "ports", [])
  count(ports) == 1
  ports[0].port == port
  upper(ports[0].protocol) == protocol
}

unrestricted_selector(selector) if {
	not is_object(selector)
}

unrestricted_selector(selector) if {
	is_object(selector)
	labels := object.get(selector, "matchLabels", {})
	expressions := object.get(selector, "matchExpressions", [])
	is_object(labels)
	is_array(expressions)
	count(labels) == 0
	count(expressions) == 0
}
