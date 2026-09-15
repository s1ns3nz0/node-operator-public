#!/usr/bin/env python3
# Check objective: Validate the bounded validator metrics collector.
"""Offline structural tests for the bounded validator metrics collector."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
RELEASE = ROOT / "scripts/release"
sys.path.insert(0, str(RELEASE))
spec = importlib.util.spec_from_file_location("collector", RELEASE / "validator_monitoring_collector.py")
collector = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(collector)

ARGS = {
    "deployment": "hoodi-node", "region": "ap-northeast-2", "account": "123456789012", "validator_set": "hoodi-a",
    "public_key": "0x" + "a" * 96,
    "image": "123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/validator/cwagent@sha256:" + "b" * 64,
    "logs_endpoint_ips": ["10.80.4.8", "10.80.4.9", "10.80.4.8"],
}


class ValidatorMonitoringCollectorTest(unittest.TestCase):
    def test_release_boundary_includes_only_reviewed_observability_assets(self):
        # Execute the actual selector without invoking a build or publication.
        builder = (ROOT / "scripts/ci/build-release-bundle.sh").read_text()
        function = "path_is_in_release_boundary() {" + builder.split(
            "path_is_in_release_boundary() {", 1
        )[1].split("\n}\n", 1)[0] + "\n}\n"
        allowed = [
            "kustomization.yaml", "namespace.yaml", "service-accounts.yaml",
            "rbac.yaml", "network-policies.yaml", "fluent-bit-config.yaml",
            "fluent-bit-daemonset.template.yaml", "evidence-envelope.schema.json",
        ]
        for name in allowed + ["credentials.json", "audit.log", "secret.yaml"]:
            path = f"deploy/observability/{name}"
            result = subprocess.run(
                ["bash", "-c", function + 'path_is_in_release_boundary "$1"', "boundary-test", path],
                capture_output=True, text=True, timeout=10,
            )
            self.assertEqual(result.returncode, 0 if name in allowed else 1, path)
            if name in allowed:
                self.assertTrue((ROOT / path).is_file(), path)

    def setUp(self):
        self.manifests = collector.build_manifests(**ARGS)
        self.items = {item["kind"]: item for item in self.manifests["items"]}
        self.deployment = self.items["Deployment"]
        self.pod = self.deployment["spec"]["template"]["spec"]
        self.container = self.pod["containers"][0]
        self.policy = self.items["NetworkPolicy"]

    def test_list_has_only_scoped_workload_objects(self):
        self.assertEqual(self.manifests["kind"], "List")
        self.assertEqual([item["kind"] for item in self.manifests["items"]], ["ConfigMap", "ServiceAccount", "Deployment", "NetworkPolicy"])
        self.assertFalse(any(item["kind"] in {"Role", "RoleBinding", "ClusterRole", "ClusterRoleBinding"} for item in self.manifests["items"]))
        self.assertTrue(all(item["metadata"]["namespace"] == collector.NAMESPACE for item in self.manifests["items"]))

    def test_service_account_pod_identity_binding_and_pending_uid_review_are_explicit(self):
        service_account = self.items["ServiceAccount"]
        self.assertEqual(service_account["metadata"]["name"], collector.SERVICE_ACCOUNT)
        self.assertFalse(service_account["automountServiceAccountToken"])
        self.assertEqual(self.pod["serviceAccountName"], collector.SERVICE_ACCOUNT)
        self.assertFalse(self.pod["automountServiceAccountToken"])
        self.assertEqual(self.pod["nodeSelector"], {"node-operator.io/role": "system"})
        annotations = self.deployment["spec"]["template"]["metadata"]["annotations"]
        self.assertEqual(annotations["node-operator.io/agent-image-uid-review"], "runtime-contract-required")
        self.assertIn("node-operator.io/config-sha256", annotations)
        self.assertTrue(self.pod["securityContext"]["runAsNonRoot"])
        self.assertEqual(self.pod["securityContext"]["runAsUser"], 1000)

    def test_config_map_environment_is_generated_from_monitoring_config(self):
        config_map = self.items["ConfigMap"]
        data = config_map["data"]
        prometheus = json.loads(data["PROMETHEUS_CONFIG_CONTENT"])
        cwagent = json.loads(data["CW_CONFIG_CONTENT"])
        self.assertEqual(prometheus["global"]["scrape_interval"], "60s")
        self.assertEqual(cwagent["agent"]["region"], ARGS["region"])
        prometheus_agent = cwagent["logs"]["metrics_collected"]["prometheus"]
        self.assertEqual(prometheus_agent["cluster_name"], ARGS["deployment"])
        self.assertEqual(prometheus_agent["log_group_name"], "/aws/eks/hoodi-node/validator-metrics")
        self.assertEqual(prometheus_agent["prometheus_config_path"], "env:PROMETHEUS_CONFIG_CONTENT")
        static_env = {item["name"]: item["value"] for item in self.container["env"] if "value" in item}
        self.assertEqual(static_env, {"RUN_IN_AWS": "True"})
        env = {item["name"]: item["valueFrom"]["configMapKeyRef"] for item in self.container["env"] if "valueFrom" in item}
        self.assertEqual(env, {
            "PROMETHEUS_CONFIG_CONTENT": {"name": config_map["metadata"]["name"], "key": "PROMETHEUS_CONFIG_CONTENT"},
            "CW_CONFIG_CONTENT": {"name": config_map["metadata"]["name"], "key": "CW_CONFIG_CONTENT"},
        })
        self.assertNotIn("password", json.dumps(self.manifests).lower())
        self.assertNotIn("secret", json.dumps(self.manifests).lower())

    def test_verified_nonroot_runtime_paths_are_only_writable_empty_dirs(self):
        self.assertEqual(self.pod["securityContext"]["runAsUser"], 1000)
        self.assertEqual(self.pod["securityContext"]["runAsGroup"], 1000)
        self.assertEqual(self.pod["securityContext"]["fsGroup"], 1000)
        security = self.container["securityContext"]
        self.assertTrue(security["runAsNonRoot"])
        self.assertEqual(security["runAsUser"], 1000)
        self.assertTrue(security["readOnlyRootFilesystem"])
        self.assertFalse(security["allowPrivilegeEscalation"])
        self.assertEqual(security["capabilities"], {"drop": ["ALL"]})
        self.assertEqual(self.pod["volumes"], [
            {"name": "agent-etc", "emptyDir": {}},
            {"name": "agent-logs", "emptyDir": {}},
            {"name": "agent-var", "emptyDir": {}},
            {"name": "agent-tmp", "emptyDir": {"medium": "Memory", "sizeLimit": "64Mi"}},
        ])
        self.assertEqual(self.container["volumeMounts"], [
            {"name": "agent-etc", "mountPath": "/opt/aws/amazon-cloudwatch-agent/etc"},
            {"name": "agent-logs", "mountPath": "/opt/aws/amazon-cloudwatch-agent/logs"},
            {"name": "agent-var", "mountPath": "/opt/aws/amazon-cloudwatch-agent/var"},
            {"name": "agent-tmp", "mountPath": "/tmp"},
        ])

    def test_standalone_isolated_cli_renders_json_without_ambient_python_path(self):
        command = [
            sys.executable, "-I", "-B", str(RELEASE / "validator_monitoring_collector.py"),
            "--deployment", ARGS["deployment"], "--region", ARGS["region"], "--account", ARGS["account"],
            "--validator-set", ARGS["validator_set"], "--public-key", ARGS["public_key"], "--image", ARGS["image"],
            "--logs-endpoint-ip", "10.80.4.8",
        ]
        rendered = subprocess.run(command, check=True, capture_output=True, text=True, timeout=10)
        self.assertEqual(json.loads(rendered.stdout)["kind"], "List")

    def test_network_policy_has_exact_private_destinations_and_ports(self):
        egress = self.policy["spec"]["egress"]
        self.assertEqual(len(egress), 6)
        self.assertEqual(egress[0]["ports"], [{"protocol": "UDP", "port": 53}, {"protocol": "TCP", "port": 53}])
        self.assertEqual(egress[1], {"to": [{"ipBlock": {"cidr": "169.254.170.23/32"}}], "ports": [{"protocol": "TCP", "port": 80}]})
        self.assertEqual({item["ipBlock"]["cidr"] for item in egress[2]["to"]}, {"10.80.4.8/32", "10.80.4.9/32"})
        self.assertEqual(egress[2]["ports"], [{"protocol": "TCP", "port": 443}])
        self.assertEqual([rule["ports"][0]["port"] for rule in egress[3:]], [8080, 6060, 8081])
        rendered = json.dumps(self.policy)
        for forbidden in ("0.0.0.0/0", "10.80.0.0/16", "4430", "kubernetes.default"):
            self.assertNotIn(forbidden, rendered)

    def test_image_and_endpoint_inputs_are_strict_and_not_an_approval_claim(self):
        self.assertEqual(self.container["image"], ARGS["image"])
        annotations = self.deployment["spec"]["template"]["metadata"]["annotations"]
        self.assertEqual(annotations["node-operator.io/image-receipt-status"], "pending-reviewed-receipt")
        invalid = [
            {"image": "public.ecr.aws/cloudwatch-agent/cloudwatch-agent@sha256:" + "b" * 64},
            {"image": ARGS["image"].replace("ap-northeast-2", "us-east-1")},
            {"logs_endpoint_ips": ["8.8.8.8"]},
            {"logs_endpoint_ips": ["169.254.1.1"]},
            {"logs_endpoint_ips": []},
        ]
        for changed in invalid:
            with self.subTest(changed=changed), self.assertRaises(collector.CollectorError):
                collector.build_manifests(**{**ARGS, **changed})


if __name__ == "__main__":
    unittest.main()
