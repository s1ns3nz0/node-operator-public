package nodeoperator.prysm_test

import rego.v1
import data.nodeoperator.prysm

expected_image := "offchainlabs/prysm-beacon-chain@sha256:49f8454eb2a756402eb781025e370eef7d613668c2914bad4cca9c1aa11fafa4"

secure_statefulset := {
	"apiVersion": "apps/v1",
	"kind": "StatefulSet",
	"metadata": {"name": "prysm-beacon"},
	"spec": {
		"template": {"spec": {
			"securityContext": {
				"runAsNonRoot": true,
				"runAsUser": 1000,
				"runAsGroup": 1000,
				"seccompProfile": {"type": "RuntimeDefault"},
			},
			"affinity": {"podAntiAffinity": {"requiredDuringSchedulingIgnoredDuringExecution": [{
				"topologyKey": "kubernetes.io/hostname",
				"labelSelector": {"matchLabels": {"app.kubernetes.io/name": "nethermind"}},
			}]}},
			"containers": [{
				"name": "beacon-chain",
				"image": expected_image,
				"securityContext": {
					"allowPrivilegeEscalation": false,
					"readOnlyRootFilesystem": true,
					"runAsNonRoot": true,
					"runAsUser": 1000,
					"capabilities": {"drop": ["ALL"]},
				},
				"startupProbe": {"tcpSocket": {"port": "beacon-api"}},
				"readinessProbe": {"httpGet": {"path": "/eth/v1/node/health", "port": "beacon-api", "scheme": "HTTP"}},
				"livenessProbe": {"tcpSocket": {"port": "beacon-api"}},
			}],
		}},
		"volumeClaimTemplates": [{
			"metadata": {"name": "prysm-data"},
			"spec": {"storageClassName": "prysm-hoodi-gp3-kms", "resources": {"requests": {"storage": "500Gi"}}},
		}],
	},
}

secure_storage_class := {
	"apiVersion": "storage.k8s.io/v1",
	"kind": "StorageClass",
	"metadata": {"name": "prysm-hoodi-gp3-kms"},
	"provisioner": "ebs.csi.aws.com",
	"parameters": {"type": "gp3", "iops": "6000", "throughput": "250", "encrypted": "true", "kmsKeyId": "alias/node-operator-baseline-ebs"},
}

secure_network_policy := {
	"apiVersion": "networking.k8s.io/v1",
	"kind": "NetworkPolicy",
	"metadata": {"name": "allow-prysm-dns"},
	"spec": {
		"podSelector": {"matchLabels": {"app.kubernetes.io/name": "prysm-beacon"}},
		"policyTypes": ["Egress"],
		"egress": [{"to": [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "kube-system"}}}], "ports": [{"protocol": "UDP", "port": 53}]}],
	},
}

test_secure_prysm_contract_passes if {
	a := prysm.deny with input as secure_statefulset
	b := prysm.deny with input as secure_storage_class
	c := prysm.deny with input as secure_network_policy
	count(a) == 0
	count(b) == 0
	count(c) == 0
}

test_unpinned_or_wrong_prysm_image_fails if {
	fixture := object.union(secure_statefulset, {"spec": {"template": {"spec": {"containers": [object.union(secure_statefulset.spec.template.spec.containers[0], {"image": "offchainlabs/prysm-beacon-chain:v7.1.8"})]}}}})
	denial := prysm.deny with input as fixture
	denial[_].id == "prysm.image-digest"
}

test_wrong_pvc_size_or_class_fails if {
	fixture := object.union(secure_statefulset, {"spec": {"volumeClaimTemplates": [{"metadata": {"name": "prysm-data"}, "spec": {"storageClassName": "gp2", "resources": {"requests": {"storage": "20Gi"}}}}]}})
	denial := prysm.deny with input as fixture
	denial[_].id == "prysm.storage-claim"
}

test_unencrypted_or_underprovisioned_storage_class_fails if {
	fixture := object.union(secure_storage_class, {"parameters": {"type": "gp3", "iops": "3000", "throughput": "125", "encrypted": "false", "kmsKeyId": ""}})
	denial := prysm.deny with input as fixture
	denial[_].id == "prysm.storage-class"
}

test_missing_hardening_or_probes_fails if {
	container := object.union(secure_statefulset.spec.template.spec.containers[0], {"securityContext": {"allowPrivilegeEscalation": true, "readOnlyRootFilesystem": false}, "startupProbe": {"tcpSocket": {"port": "metrics"}}, "readinessProbe": {"httpGet": {"path": "/", "port": "metrics", "scheme": "HTTP"}}, "livenessProbe": {"tcpSocket": {"port": "metrics"}}})
	fixture := object.union(secure_statefulset, {"spec": {"template": {"spec": {"securityContext": {"runAsNonRoot": false}, "containers": [container]}}}})
	denial := prysm.deny with input as fixture
	denial[_].id == "prysm.pod-hardening"
	denial[_].id == "prysm.probes"
}

test_missing_nethermind_anti_affinity_fails if {
	fixture := object.union(secure_statefulset, {"spec": {"template": {"spec": {"affinity": {"podAntiAffinity": {"requiredDuringSchedulingIgnoredDuringExecution": [{"topologyKey": "topology.kubernetes.io/zone", "labelSelector": {"matchLabels": {"app.kubernetes.io/name": "nethermind"}}}]}}}}}})
	denial := prysm.deny with input as fixture
	denial[_].id == "prysm.nethermind-anti-affinity"
}

test_world_egress_fails if {
	fixture := object.union(secure_network_policy, {"spec": object.union(secure_network_policy.spec, {"egress": [{"to": [{"ipBlock": {"cidr": "0.0.0.0/0"}}]}]})})
	denial := prysm.deny with input as fixture
	denial[_].id == "prysm.world-egress"
}
