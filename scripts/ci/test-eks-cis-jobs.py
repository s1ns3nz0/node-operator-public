#!/usr/bin/env python3
# Check objective: Validate bounded EKS CIS job rendering without cluster mutation.
"""Offline renderer tests; rendering does not approve images or assess CIS compliance."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("renderer", ROOT / "scripts/ops/render-eks-cis-jobs.py")
MODULE = importlib.util.module_from_spec(SPEC); assert SPEC.loader; SPEC.loader.exec_module(MODULE)
IMAGE = "123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/node-operator/kube-bench@sha256:" + "a" * 64


def node(name, os_name="linux", os_image="Amazon Linux 2023", architecture="amd64", provider="aws:///ap-northeast-2a/i-0123456789abcdef0", labels=None):
    return {"metadata": {"name": name, "labels": labels or {}}, "spec": {"providerID": provider}, "status": {"nodeInfo": {"operatingSystem": os_name, "osImage": os_image, "architecture": architecture}}}


class EksCisJobsTests(unittest.TestCase):
    def write(self, root, nodes):
        inventory = root / "nodes.json"; inventory.write_text(json.dumps({"metadata": {"continue": "", "remainingItemCount": 0}, "items": nodes}))
        return inventory

    def render(self, nodes):
        temp = tempfile.TemporaryDirectory(); root = Path(temp.name)
        inventory = self.write(root, nodes); output = root / "rendered.json"
        MODULE.render(inventory, "123456789012", "ap-northeast-2", "node-operator", IMAGE, ROOT / "policy/data/cis_eks.json", output)
        return temp, json.loads(output.read_text())

    def test_renders_every_linux_ec2_node_with_bounded_hardened_jobs(self):
        temp, rendered = self.render([node("ip-10-0-0-1.ap-northeast-2.compute.internal", os_image="Amazon Linux 2023.9.20250903"), node("ip-10-0-0-2.ap-northeast-2.compute.internal")])
        with temp:
            self.assertEqual(rendered["kind"], "List")
            self.assertEqual(len(rendered["items"]), 4)
            self.assertEqual(rendered["items"][0]["metadata"]["annotations"]["node-operator.io/deployment"], "node-operator")
            network = rendered["items"][1]; self.assertEqual(network["spec"]["policyTypes"], ["Ingress", "Egress"])
            jobs = rendered["items"][2:]
            self.assertEqual({job["spec"]["template"]["spec"]["nodeName"] for job in jobs}, {"ip-10-0-0-1.ap-northeast-2.compute.internal", "ip-10-0-0-2.ap-northeast-2.compute.internal"})
            container = jobs[0]["spec"]["template"]["spec"]["containers"][0]
            pod = jobs[0]["spec"]["template"]["spec"]
            self.assertEqual(container["command"], ["kube-bench", "run", "--targets", "node", "--benchmark", "eks-1.5.0", "--json"])
            self.assertFalse(pod["automountServiceAccountToken"]); self.assertTrue(pod["hostPID"])
            self.assertFalse(container["securityContext"]["privileged"]); self.assertFalse(container["securityContext"]["allowPrivilegeEscalation"])
            self.assertEqual(container["securityContext"]["seccompProfile"], {"type": "RuntimeDefault"})
            self.assertEqual(container["securityContext"]["capabilities"]["drop"], ["ALL"])
            self.assertTrue(all(mount["readOnly"] for mount in container["volumeMounts"]))
            self.assertNotIn("/etc", [mount["mountPath"] for mount in container["volumeMounts"]])
            self.assertNotIn("/usr/bin", [mount["mountPath"] for mount in container["volumeMounts"]])
            self.assertEqual({mount["mountPath"] for mount in container["volumeMounts"]}, {"/var/lib/kubelet", "/etc/kubernetes/kubelet"})
            self.assertEqual(jobs[0]["metadata"]["annotations"]["node-operator.io/al2023-nodeadm-config"], "/etc/kubernetes/kubelet/config.json; resolved from host kubelet process arguments")
            self.assertEqual(jobs[0]["metadata"]["annotations"]["node-operator.io/image-approval"], "not-asserted-by-renderer")
            self.assertEqual(jobs[0]["metadata"]["labels"]["node-operator.io/deployment"], "node-operator")

    def test_rejects_fargate_windows_and_unsupported_nodes_instead_of_skipping(self):
        cases = [node("fargate", labels={"eks.amazonaws.com/compute-type": "fargate"}), node("windows", os_name="windows"), node("al2", os_image="Amazon Linux 2"), node("external", provider="kube://external"), node("wrong-region", provider="aws:///us-east-1a/i-0123456789abcdef0")]
        for item in cases:
            with self.subTest(node=item["metadata"]["name"]), tempfile.TemporaryDirectory() as temp:
                root = Path(temp); inventory = self.write(root, [node("valid"), item])
                with self.assertRaises(MODULE.RenderError): MODULE.render(inventory, "123456789012", "ap-northeast-2", "node-operator", IMAGE, ROOT / "policy/data/cis_eks.json", root / "output.json")

    def test_rejects_empty_or_duplicate_inventory_and_unapproved_profile(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for nodes in ([], [node("duplicate"), node("duplicate")]):
                inventory = self.write(root, nodes)
                with self.assertRaises(MODULE.RenderError): MODULE.render(inventory, "123456789012", "ap-northeast-2", "node-operator", IMAGE, ROOT / "policy/data/cis_eks.json", root / "output.json")
            profile = root / "profile.json"; profile.write_text(json.dumps({"cis_eks": {"benchmark": "eks-2.0.0", "source_revision": "a" * 40, "target": "node", "required_check_ids": ["1"]}}))
            inventory = self.write(root, [node("valid")])
            with self.assertRaises(MODULE.RenderError): MODULE.render(inventory, "123456789012", "ap-northeast-2", "node-operator", IMAGE, profile, root / "output.json")
            profile.write_text(json.dumps({"cis_eks": {"benchmark": "eks-1.5.0", "source_revision": "a" * 40, "target": "node", "required_check_ids": ["3.1.1"]}}))
            with self.assertRaises(MODULE.RenderError): MODULE.render(inventory, "123456789012", "ap-northeast-2", "node-operator", IMAGE, profile, root / "output.json")

    def test_rejects_mismatched_ecr_and_pagination_and_uses_collision_safe_names(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            prefix = "a" * 43
            inventory = self.write(root, [node(prefix + "one"), node(prefix + "two")])
            output = root / "output.json"
            MODULE.render(inventory, "123456789012", "ap-northeast-2", "node-operator", IMAGE, ROOT / "policy/data/cis_eks.json", output)
            jobs = json.loads(output.read_text())["items"][2:]
            self.assertEqual(len({job["metadata"]["name"] for job in jobs}), 2)
            self.assertTrue(all(len(job["metadata"]["labels"]["node-operator.io/node-hash"]) == 12 for job in jobs))
            with self.assertRaises(MODULE.RenderError): MODULE.render(inventory, "123456789012", "ap-northeast-2", "node-operator", "ghcr.io/example/kube-bench@sha256:" + "a" * 64, ROOT / "policy/data/cis_eks.json", root / "second.json")
            inventory.write_text(json.dumps({"metadata": {"continue": "next"}, "items": [node("valid")] }))
            with self.assertRaises(MODULE.RenderError): MODULE.render(inventory, "123456789012", "ap-northeast-2", "node-operator", IMAGE, ROOT / "policy/data/cis_eks.json", root / "third.json")
            inventory.write_text(json.dumps({"metadata": {"remainingItemCount": 1}, "items": [node("valid")] }))
            with self.assertRaises(MODULE.RenderError): MODULE.render(inventory, "123456789012", "ap-northeast-2", "node-operator", IMAGE, ROOT / "policy/data/cis_eks.json", root / "fourth.json")


if __name__ == "__main__": unittest.main()
