#!/usr/bin/env python3
"""Render, but never apply, bounded kube-bench EKS worker-node jobs."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

MAX_INPUT = 1024 * 1024
SHA = re.compile(r"[0-9a-f]{40}$")
DNS_LABEL = re.compile(r"[a-z0-9]([-a-z0-9]*[a-z0-9])?$")
DNS_SUBDOMAIN = re.compile(r"[a-z0-9]([a-z0-9.-]*[a-z0-9])?$")
AL2023_OS_IMAGE = re.compile(r"Amazon Linux 2023(?:\.[0-9]+){0,3}$")
MAX_NODES = 100
CONTROL_IDS = ("3.1.1", "3.1.2", "3.1.3", "3.1.4", "3.2.1", "3.2.2", "3.2.3", "3.2.4", "3.2.5", "3.2.6", "3.2.7", "3.2.8", "3.2.9")
PROFILE_REVISION = "5c6c22d51b926020e7414e1f1e051851d1a2feff"


class RenderError(ValueError):
    pass


def pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise RenderError("duplicate JSON key")
        result[key] = value
    return result


def load(path: Path):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_INPUT:
            os.close(fd); raise RenderError("unsafe input")
        with os.fdopen(fd, "rb") as handle: raw = handle.read(MAX_INPUT + 1)
    except OSError as error:
        raise RenderError("cannot read input") from error
    if len(raw) > MAX_INPUT: raise RenderError("unsafe input")
    try: return json.loads(raw, object_pairs_hook=pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as error: raise RenderError("malformed JSON") from error


def profile(path: Path):
    value = load(path)
    item = value.get("cis_eks") if isinstance(value, dict) else None
    if not isinstance(item, dict) or set(item) != {"benchmark", "source_revision", "target", "required_check_ids"}:
        raise RenderError("invalid approved CIS profile")
    required = item.get("required_check_ids")
    if (item.get("benchmark") != "eks-1.5.0" or item.get("target") != "node" or item.get("source_revision") != PROFILE_REVISION or required != list(CONTROL_IDS)):
        raise RenderError("unsupported CIS profile")
    return item


def selected_nodes(path: Path, region: str):
    value = load(path)
    nodes = value.get("items") if isinstance(value, dict) else None
    inventory_metadata = value.get("metadata") if isinstance(value, dict) else None
    if not isinstance(nodes, list) or not nodes or len(nodes) > MAX_NODES or not isinstance(inventory_metadata, dict): raise RenderError("complete explicit Kubernetes Node inventory is required")
    continuation, remaining = inventory_metadata.get("continue", ""), inventory_metadata.get("remainingItemCount")
    if not isinstance(continuation, str) or continuation or (remaining is not None and (type(remaining) is not int or remaining != 0)): raise RenderError("paginated, truncated, or malformed Node inventory metadata is not permitted")
    result = []
    for node in nodes:
        if not isinstance(node, dict): raise RenderError("invalid Node inventory item")
        metadata, status, spec = node.get("metadata"), node.get("status"), node.get("spec", {})
        if not isinstance(metadata, dict) or not isinstance(status, dict) or not isinstance(spec, dict): raise RenderError("incomplete Node inventory item")
        name, labels = metadata.get("name"), metadata.get("labels", {})
        node_info = status.get("nodeInfo")
        if not isinstance(name, str) or len(name) > 253 or not DNS_SUBDOMAIN.fullmatch(name) or not isinstance(labels, dict) or not isinstance(node_info, dict): raise RenderError("incomplete Node inventory item")
        os_name, os_image, architecture, provider = node_info.get("operatingSystem"), node_info.get("osImage"), node_info.get("architecture"), spec.get("providerID")
        if labels.get("eks.amazonaws.com/compute-type") == "fargate": raise RenderError("Fargate node cannot be silently skipped: " + name)
        if os_name != "linux": raise RenderError("non-Linux node cannot be silently skipped: " + name)
        if not isinstance(os_image, str) or not AL2023_OS_IMAGE.fullmatch(os_image) or architecture != "amd64": raise RenderError("unsupported node OS layout cannot be silently skipped: " + name)
        provider_pattern = re.compile(r"aws:///" + re.escape(region) + r"[a-z]/i-(?:[0-9a-f]{8}|[0-9a-f]{17})$")
        if not isinstance(provider, str) or not provider_pattern.fullmatch(provider): raise RenderError("unsupported, malformed, or wrong-region EC2 node cannot be silently skipped: " + name)
        result.append(name)
    if len(set(result)) != len(result): raise RenderError("duplicate node name in inventory")
    return sorted(result)


def job(node, namespace, image, profile, deployment):
    labels = {"app.kubernetes.io/name": "eks-cis-kube-bench", "node-operator.io/cis-scope": "eks-worker-node", "node-operator.io/image-admission": "pending", "node-operator.io/deployment": deployment}
    annotations = {"node-operator.io/render-status": "pending-admission-and-execution", "node-operator.io/image-approval": "not-asserted-by-renderer", "node-operator.io/raw-results": "normalize with scripts/ci/normalize-eks-cis.py before evidence use", "node-operator.io/hostpid-rationale": "required by the pinned kube-bench EKS node profile to inspect node processes; no host mutation is permitted", "node-operator.io/al2023-nodeadm-config": "/etc/kubernetes/kubelet/config.json; resolved from host kubelet process arguments", "node-operator.io/kube-bench-profile": "eks-1.5.0 standard profile with AL2023 nodeadm path mapping", "node-operator.io/limitations": "source-derived AL2023 mapping only; live AMI/runtime compatibility, raw results, control-plane controls, and CIS compliance remain unverified"}
    annotations["node-operator.io/full-node-name"] = node
    annotations["node-operator.io/root-rationale"] = "root is required only to read ownership and mode metadata of root-owned kubelet configuration; privileges and Linux capabilities remain disabled"
    node_hash = hashlib.sha256(node.encode("utf-8")).hexdigest()[:12]
    safe_name = node.replace(".", "-")[:42].rstrip("-")
    job_name = "eks-cis-" + safe_name + "-" + node_hash
    node_label = node_hash
    # AL2023 nodeadm writes config.json beneath this narrow directory (the
    # upstream nodeadm source fixes kubeletConfigRoot and kubeletConfigFile).
    # The standard EKS profile resolves it from the host kubelet --config arg.
    # Do not mount /etc, /usr/bin, or any HostPathDirectoryOrCreate volume.
    mounts = [("kubelet-state", "/var/lib/kubelet", "Directory"), ("kubelet-config", "/etc/kubernetes/kubelet", "Directory")]
    pod_labels = labels | {"node-operator.io/node-hash": node_label}
    return {"apiVersion": "batch/v1", "kind": "Job", "metadata": {"name": job_name, "namespace": namespace, "labels": pod_labels, "annotations": annotations}, "spec": {"backoffLimit": 0, "activeDeadlineSeconds": 300, "ttlSecondsAfterFinished": 600, "template": {"metadata": {"labels": pod_labels}, "spec": {"nodeName": node, "restartPolicy": "Never", "automountServiceAccountToken": False, "hostPID": True, "containers": [{"name": "kube-bench", "image": image, "imagePullPolicy": "IfNotPresent", "command": ["kube-bench", "run", "--targets", profile["target"], "--benchmark", profile["benchmark"], "--json"], "resources": {"requests": {"cpu": "100m", "memory": "128Mi"}, "limits": {"cpu": "250m", "memory": "256Mi"}}, "securityContext": {"runAsUser": 0, "runAsGroup": 0, "privileged": False, "allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True, "seccompProfile": {"type": "RuntimeDefault"}, "capabilities": {"drop": ["ALL"]}}, "volumeMounts": [{"name": name, "mountPath": mount, "readOnly": True} for name, mount, _ in mounts]}], "volumes": [{"name": name, "hostPath": {"path": mount, "type": kind}} for name, mount, kind in mounts]}}}}


def render(nodes_path, account, region, deployment, image, profile_path, output):
    image_prefix = account + ".dkr.ecr." + region + ".amazonaws.com/"
    if not re.fullmatch(r"[0-9]{12}", account) or not re.fullmatch(r"[a-z]{2}-[a-z]+-[0-9]", region) or not DNS_LABEL.fullmatch(deployment) or not image.startswith(image_prefix) or not re.fullmatch(r"[a-z0-9][a-z0-9._/-]*@sha256:[0-9a-f]{64}", image[len(image_prefix):]): raise RenderError("image must be a selected account and region private-ECR digest reference")
    approved = profile(profile_path); nodes = selected_nodes(nodes_path, region)
    namespace = "node-operator-cis"
    common = {"node-operator.io/cis-scope": "eks-worker-node", "node-operator.io/managed-by": "render-eks-cis-jobs", "node-operator.io/image-admission": "pending", "node-operator.io/deployment": deployment}
    items = [{"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": namespace, "labels": common, "annotations": {"node-operator.io/admission": "pending; renderer does not approve images or exceptions", "node-operator.io/network": "default-deny-egress", "node-operator.io/deployment": deployment}}}, {"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy", "metadata": {"name": "default-deny", "namespace": namespace, "labels": common, "annotations": {"node-operator.io/deployment": deployment}}, "spec": {"podSelector": {}, "policyTypes": ["Ingress", "Egress"]}}]
    items.extend(job(node, namespace, image, approved, deployment) for node in nodes)
    value = {"apiVersion": "v1", "kind": "List", "metadata": {"annotations": {"node-operator.io/account": account, "node-operator.io/region": region, "node-operator.io/deployment": deployment, "node-operator.io/profile-source-revision": approved["source_revision"], "node-operator.io/claim": "rendered jobs are not execution evidence or full EKS CIS compliance"}}, "items": items}
    if output.exists() or output.is_symlink() or output.parent.is_symlink() or not output.parent.is_dir(): raise RenderError("unsafe output")
    with output.open("x", encoding="utf-8") as handle: json.dump(value, handle, sort_keys=True, separators=(",", ":")); handle.write("\n")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--nodes", type=Path, required=True); parser.add_argument("--account", required=True); parser.add_argument("--region", required=True); parser.add_argument("--deployment", required=True); parser.add_argument("--image", required=True); parser.add_argument("--profile", type=Path, required=True); parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try: render(args.nodes, args.account, args.region, args.deployment, args.image, args.profile, args.output)
    except (RenderError, OSError) as error: print("EKS CIS job rendering rejected: " + str(error), file=sys.stderr); return 2
    return 0


if __name__ == "__main__": raise SystemExit(main())
