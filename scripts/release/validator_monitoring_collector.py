#!/usr/bin/env python3
"""Render local Kubernetes manifests for the bounded validator EMF collector.

The image argument is syntax-validated against the selected account and Region;
that is not image approval. A caller must separately carry the reviewed image
receipt before any deployment is admitted. This module has no Kubernetes or AWS
API calls.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import ipaddress
import json
import re
from pathlib import Path
from typing import Any

_CONFIG_SPEC = importlib.util.spec_from_file_location(
    "validator_monitoring_config", Path(__file__).with_name("validator_monitoring_config.py")
)
if _CONFIG_SPEC is None or _CONFIG_SPEC.loader is None:
    raise RuntimeError("validator monitoring config module is unavailable")
_CONFIG_MODULE = importlib.util.module_from_spec(_CONFIG_SPEC)
_CONFIG_SPEC.loader.exec_module(_CONFIG_MODULE)
ConfigError = _CONFIG_MODULE.ConfigError
build_config = _CONFIG_MODULE.build_config

NAMESPACE = "validator-observability"
SERVICE_ACCOUNT = "validator-metrics-collector"
COMPONENT = "validator-metrics-collector"
_ACCOUNT = re.compile(r"[0-9]{12}$")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}$")
_RFC1918 = (ipaddress.ip_network("10.0.0.0/8"), ipaddress.ip_network("172.16.0.0/12"), ipaddress.ip_network("192.168.0.0/16"))
_MAX_LOGS_ENDPOINTS = 8


class CollectorError(ValueError):
    """Raised when a local collector manifest input is unsafe or incomplete."""


def _validated_image(account: str, region: str, image: str) -> str:
    if not isinstance(account, str) or not _ACCOUNT.fullmatch(account):
        raise CollectorError("invalid AWS account")
    if not isinstance(image, str) or "@" not in image:
        raise CollectorError("image must be an ECR digest reference")
    repository, digest = image.rsplit("@", 1)
    prefix = f"{account}.dkr.ecr.{region}.amazonaws.com/"
    if not repository.startswith(prefix) or not _DIGEST.fullmatch(digest):
        raise CollectorError("image must be a digest in the selected account and region")
    remainder = repository[len(prefix):]
    if not re.fullmatch(r"[a-z0-9](?:[a-z0-9._/-]*[a-z0-9])?", remainder):
        raise CollectorError("invalid ECR repository path")
    return image


def _logs_endpoint_cidrs(values: list[str]) -> list[str]:
    if not isinstance(values, list) or not values:
        raise CollectorError("at least one Logs endpoint IPv4 address is required")
    cidrs: list[str] = []
    for value in values:
        try:
            address = ipaddress.IPv4Address(value)
        except (ipaddress.AddressValueError, TypeError) as error:
            raise CollectorError("Logs endpoint must be an IPv4 address") from error
        if not any(address in network for network in _RFC1918):
            raise CollectorError("Logs endpoint must be RFC1918 private IPv4")
        cidr = f"{address}/32"
        if cidr not in cidrs:
            cidrs.append(cidr)
    if len(cidrs) > _MAX_LOGS_ENDPOINTS:
        raise CollectorError(f"at most {_MAX_LOGS_ENDPOINTS} Logs endpoint addresses are allowed")
    return cidrs


def _labels(deployment: str, validator_set: str) -> dict[str, str]:
    return {
        "app.kubernetes.io/name": COMPONENT,
        "app.kubernetes.io/component": COMPONENT,
        "node-operator.io/deployment-name": deployment,
        "node-operator.io/network": "hoodi",
        "node-operator.io/validator-set": validator_set,
    }


def build_manifests(
    deployment: str,
    region: str,
    account: str,
    validator_set: str,
    public_key: str,
    image: str,
    logs_endpoint_ips: list[str],
) -> dict[str, Any]:
    """Return a JSON-valid Kubernetes List for a single private collector.

    UID 1000 and the required writable paths are pinned from the local candidate
    runtime check. Image-receipt review remains a separate admission requirement.
    """
    config = build_config(deployment, region, validator_set, public_key)
    image = _validated_image(account, region, image)
    endpoint_cidrs = _logs_endpoint_cidrs(logs_endpoint_ips)
    prometheus_content = json.dumps(config["prometheus"], sort_keys=True, separators=(",", ":"))
    cwagent_content = json.dumps(config["cwagent"], sort_keys=True, separators=(",", ":"))
    config_hash = hashlib.sha256(f"{prometheus_content}\n{cwagent_content}".encode()).hexdigest()
    labels = _labels(deployment, validator_set)
    config_name = "validator-metrics-collector-config"

    config_map = {
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {"name": config_name, "namespace": NAMESPACE, "labels": labels},
        "data": {"PROMETHEUS_CONFIG_CONTENT": prometheus_content, "CW_CONFIG_CONTENT": cwagent_content},
    }
    service_account = {
        "apiVersion": "v1",
        "kind": "ServiceAccount",
        "metadata": {"name": SERVICE_ACCOUNT, "namespace": NAMESPACE, "labels": labels},
        "automountServiceAccountToken": False,
    }
    pod_labels = {**labels}
    deployment_object = {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": COMPONENT, "namespace": NAMESPACE, "labels": labels},
        "spec": {
            "replicas": 1,
            "selector": {"matchLabels": {"app.kubernetes.io/component": COMPONENT}},
            "template": {
                "metadata": {
                    "labels": pod_labels,
                    "annotations": {
                        "node-operator.io/config-sha256": config_hash,
                        "node-operator.io/image-receipt-status": "pending-reviewed-receipt",
                        "node-operator.io/agent-image-uid-review": "runtime-contract-required",
                    },
                },
                "spec": {
                    "serviceAccountName": SERVICE_ACCOUNT,
                    "automountServiceAccountToken": False,
                    "nodeSelector": {"node-operator.io/role": "system"},
                    "securityContext": {
                        "runAsNonRoot": True,
                        "runAsUser": 1000,
                        "runAsGroup": 1000,
                        "fsGroup": 1000,
                        "seccompProfile": {"type": "RuntimeDefault"},
                    },
                    "containers": [{
                        "name": "cloudwatch-agent",
                        "image": image,
                        "imagePullPolicy": "IfNotPresent",
                        "env": [
                            # EKS uses workload credentials, not the Agent's
                            # on-premises shared-credential-file fallback.
                            {"name": "RUN_IN_AWS", "value": "True"},
                            {"name": "PROMETHEUS_CONFIG_CONTENT", "valueFrom": {"configMapKeyRef": {"name": config_name, "key": "PROMETHEUS_CONFIG_CONTENT"}}},
                            {"name": "CW_CONFIG_CONTENT", "valueFrom": {"configMapKeyRef": {"name": config_name, "key": "CW_CONFIG_CONTENT"}}},
                        ],
                        "securityContext": {
                            "allowPrivilegeEscalation": False,
                            "privileged": False,
                            "capabilities": {"drop": ["ALL"]},
                            "runAsNonRoot": True,
                            "runAsUser": 1000,
                            "readOnlyRootFilesystem": True,
                        },
                        "resources": {"requests": {"cpu": "200m", "memory": "256Mi"}, "limits": {"cpu": "1", "memory": "1Gi"}},
                    }],
                    "volumes": [
                        {"name": "agent-etc", "emptyDir": {}},
                        {"name": "agent-logs", "emptyDir": {}},
                        {"name": "agent-var", "emptyDir": {}},
                        {"name": "agent-tmp", "emptyDir": {"medium": "Memory", "sizeLimit": "64Mi"}},
                    ],
                },
            },
        },
    }
    deployment_object["spec"]["template"]["spec"]["containers"][0]["volumeMounts"] = [
        {"name": "agent-etc", "mountPath": "/opt/aws/amazon-cloudwatch-agent/etc"},
        {"name": "agent-logs", "mountPath": "/opt/aws/amazon-cloudwatch-agent/logs"},
        {"name": "agent-var", "mountPath": "/opt/aws/amazon-cloudwatch-agent/var"},
        {"name": "agent-tmp", "mountPath": "/tmp"},
    ]
    egress = [
        {"to": [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "kube-system"}}, "podSelector": {"matchLabels": {"k8s-app": "kube-dns"}}}], "ports": [{"protocol": "UDP", "port": 53}, {"protocol": "TCP", "port": 53}]},
        {"to": [{"ipBlock": {"cidr": "169.254.170.23/32"}}], "ports": [{"protocol": "TCP", "port": 80}]},
        {"to": [{"ipBlock": {"cidr": cidr}} for cidr in endpoint_cidrs], "ports": [{"protocol": "TCP", "port": 443}]},
        {"to": [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "node-operator"}}, "podSelector": {"matchLabels": {"app.kubernetes.io/name": "prysm-beacon"}}}], "ports": [{"protocol": "TCP", "port": 8080}]},
        {"to": [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "node-operator"}}, "podSelector": {"matchLabels": {"app.kubernetes.io/name": "nethermind", "app.kubernetes.io/component": "execution-client"}}}], "ports": [{"protocol": "TCP", "port": 6060}]},
        {"to": [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "validator-operations"}}, "podSelector": {"matchLabels": {"app.kubernetes.io/component": "validator-client", "node-operator.io/validator-set": validator_set}}}], "ports": [{"protocol": "TCP", "port": 8081}]},
    ]
    network_policy = {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {"name": "validator-metrics-collector-egress", "namespace": NAMESPACE, "labels": labels},
        "spec": {"podSelector": {"matchLabels": {"app.kubernetes.io/component": COMPONENT}}, "policyTypes": ["Egress"], "egress": egress},
    }
    return {"apiVersion": "v1", "kind": "List", "items": [config_map, service_account, deployment_object, network_policy]}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Render bounded validator CloudWatch collector Kubernetes JSON")
    parser.add_argument("--deployment", required=True)
    parser.add_argument("--region", required=True)
    parser.add_argument("--account", required=True)
    parser.add_argument("--validator-set", required=True)
    parser.add_argument("--public-key", required=True)
    parser.add_argument("--image", required=True, help="selected-account selected-region ECR digest; receipt review remains required")
    parser.add_argument("--logs-endpoint-ip", action="append", required=True)
    args = parser.parse_args(argv)
    try:
        print(json.dumps(build_manifests(args.deployment, args.region, args.account, args.validator_set, args.public_key, args.image, args.logs_endpoint_ip), sort_keys=True))
    except (CollectorError, ConfigError) as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
