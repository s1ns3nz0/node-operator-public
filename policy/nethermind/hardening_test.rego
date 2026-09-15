package nodeoperator.nethermind

import rego.v1

test_secure_statefulset_is_accepted if {
	violations := deny with input as secure_statefulset
	count(violations) == 0
}

test_secure_storage_class_is_accepted if {
	violations := deny with input as secure_storage_class
	count(violations) == 0
}

test_secure_network_policy_is_accepted if {
	violations := deny with input as secure_network_policy
	count(violations) == 0
}

test_insecure_statefulset_rejects_each_required_invariant if {
	violations := deny with input as insecure_statefulset
	count(violations) == 6
	{"id": "nethermind.image-digest", "msg": "Nethermind must use the approved immutable v1.39.3-chiseled image digest"} in violations
	{"id": "nethermind.storage-claim", "msg": "Nethermind must request a 2Ti claim from the approved encrypted gp3 StorageClass"} in violations
	{"id": "nethermind.pod-hardening", "msg": "Nethermind pod and container must retain the hardened security context"} in violations
	{"id": "nethermind.workload-identity", "msg": "Nethermind must use its dedicated ServiceAccount without an API token mount"} in violations
	{"id": "nethermind.probes", "msg": "Nethermind must define startup, readiness, and liveness TCP probes on P2P"} in violations
	{"id": "nethermind.prysm-anti-affinity", "msg": "Nethermind must require hostname anti-affinity with Prysm"} in violations
}

test_insecure_storage_class_is_rejected if {
	violations := deny with input as insecure_storage_class
	{"id": "nethermind.storage-class", "msg": "Nethermind StorageClass must use encrypted gp3 with 10000 IOPS, 250 MiB/s throughput, and a KMS key"} in violations
}

test_insecure_network_policy_is_rejected if {
	violations := deny with input as insecure_network_policy
	{"id": "nethermind.world-egress", "msg": "Nethermind NetworkPolicy must not allow world egress"} in violations
}

secure_statefulset := {
	"kind": "StatefulSet",
	"metadata": {"name": "nethermind-execution"},
	"spec": {
		"template": {"spec": {
			"serviceAccountName": "nethermind-execution",
			"automountServiceAccountToken": false,
			"securityContext": {"runAsNonRoot": true, "runAsUser": 1000, "runAsGroup": 1000, "seccompProfile": {"type": "RuntimeDefault"}},
			"affinity": {"podAntiAffinity": {"requiredDuringSchedulingIgnoredDuringExecution": [{"topologyKey": "kubernetes.io/hostname", "labelSelector": {"matchLabels": {"app.kubernetes.io/name": "prysm-beacon"}}}]}},
			"containers": [{"name": "nethermind", "image": expected_image, "securityContext": {"allowPrivilegeEscalation": false, "readOnlyRootFilesystem": true, "runAsNonRoot": true, "runAsUser": 1000, "capabilities": {"drop": ["ALL"]}}, "startupProbe": {"tcpSocket": {"port": "p2p-tcp"}}, "readinessProbe": {"tcpSocket": {"port": "p2p-tcp"}}, "livenessProbe": {"tcpSocket": {"port": "p2p-tcp"}}}]
		}},
		"volumeClaimTemplates": [{"metadata": {"name": "nethermind-data"}, "spec": {"storageClassName": expected_storage_class, "resources": {"requests": {"storage": "2Ti"}}}}]
	}
}

secure_storage_class := {"kind": "StorageClass", "metadata": {"name": expected_storage_class}, "provisioner": "ebs.csi.aws.com", "parameters": {"type": "gp3", "iops": "10000", "throughput": "250", "encrypted": "true", "kmsKeyId": "alias/node-operator-baseline-ebs"}}

secure_network_policy := {"kind": "NetworkPolicy", "spec": {"podSelector": {"matchLabels": {"app.kubernetes.io/name": "nethermind"}}, "egress": [{"to": [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "kube-system"}}}]}]}}

insecure_statefulset := {"kind": "StatefulSet", "metadata": {"name": "nethermind-execution"}, "spec": {"template": {"spec": {"containers": [{"name": "nethermind", "image": "nethermind/nethermind:latest"}]}}, "volumeClaimTemplates": [{"metadata": {"name": "nethermind-data"}, "spec": {"storageClassName": "standard", "resources": {"requests": {"storage": "20Gi"}}}}]}}

insecure_storage_class := {"kind": "StorageClass", "metadata": {"name": expected_storage_class}, "provisioner": "kubernetes.io/no-provisioner", "parameters": {"type": "gp2", "encrypted": "false"}}

insecure_network_policy := {"kind": "NetworkPolicy", "spec": {"podSelector": {"matchLabels": {"app.kubernetes.io/name": "nethermind"}}, "egress": [{"to": [{"ipBlock": {"cidr": "0.0.0.0/0"}}]}]}}
