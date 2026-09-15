package nodeoperator.runtime_test

import rego.v1
import data.nodeoperator.runtime

secure_container := {
	"name": "node",
	"securityContext": {
		"privileged": false,
		"runAsNonRoot": true,
		"readOnlyRootFilesystem": true,
	},
	"resources": {
		"requests": {"cpu": "250m", "memory": "256Mi"},
		"limits": {"cpu": "1", "memory": "1Gi"},
	},
}

secure_workload := {
	"apiVersion": "apps/v1",
	"kind": "Deployment",
	"spec": {"template": {"spec": {"containers": [secure_container]}}},
}

test_hardened_workload_passes if {
	denial := runtime.deny with input as secure_workload
	count(denial) == 0
}

test_privileged_workload_fails if {
	fixture := object.union(secure_workload, {"spec": {"template": {"spec": {"containers": [object.union(secure_container, {"securityContext": object.union(secure_container.securityContext, {"privileged": true})})]}}}})
	denial := runtime.deny with input as fixture
	denial[_].id == "kubernetes.privileged"
}

test_root_workload_fails if {
	fixture := object.union(secure_workload, {"spec": {"template": {"spec": {"containers": [object.union(secure_container, {"securityContext": object.union(secure_container.securityContext, {"runAsNonRoot": false})})]}}}})
	denial := runtime.deny with input as fixture
	denial[_].id == "kubernetes.non-root"
}

test_writable_root_workload_fails if {
	fixture := object.union(secure_workload, {"spec": {"template": {"spec": {"containers": [object.union(secure_container, {"securityContext": object.union(secure_container.securityContext, {"readOnlyRootFilesystem": false})})]}}}})
	denial := runtime.deny with input as fixture
	denial[_].id == "kubernetes.readonly-root"
}

test_missing_resource_requirements_fail if {
	fixture := object.union(secure_workload, {"spec": {"template": {"spec": {"containers": [object.remove(secure_container, ["resources"])]}}}})
	denial := runtime.deny with input as fixture
	denial[_].id == "kubernetes.resources"
}

test_unbounded_egress_fails if {
	fixture := {"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy", "spec": {"podSelector": {}, "policyTypes": ["Egress"], "egress": [{}]}}
	denial := runtime.deny with input as fixture
	denial[_].id == "kubernetes.egress-unbounded"
}

test_restricted_dns_egress_passes if {
	fixture := {"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy", "spec": {"podSelector": {}, "policyTypes": ["Egress"], "egress": [{"to": [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "kube-system"}}}], "ports": [{"protocol": "UDP", "port": 53}, {"protocol": "TCP", "port": 53}]}]}}
	denial := runtime.deny with input as fixture
	count(denial) == 0
}
