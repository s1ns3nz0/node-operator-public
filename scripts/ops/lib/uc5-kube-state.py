#!/usr/bin/env python3
"""Bounded, read-only Kubernetes snapshots for UC-5 pre-delete guards.

This collector deliberately has a small, fixed Kubernetes read surface.  It
never requests Secrets, ConfigMaps, service-account tokens, exec output, or
Pod logs.  Its two returned objects are the exact baseline/live inputs of
``uc5-live-guards.py``; callers must pass them unmodified to that guard.
"""
import argparse
import json
import pathlib
import re
import subprocess


NAMESPACE = "validator-operations"
ARGO_NAMESPACE = "argocd"
SET = "hoodi-example"
CONTROLLERS = {
    "client": ("statefulset", "validator-hoodi-example-client"),
    "fence": ("deployment", "validator-hoodi-example-signing-fence"),
    "signer": ("deployment", "validator-hoodi-example-remote-signer"),
    "db": ("statefulset", "validator-hoodi-example-slashing-db"),
}
PVC = "data-validator-hoodi-example-slashing-db-0"
LEASE = "validator-hoodi-example-primary"
PUBLIC_SERVICE = "validator-hoodi-example-remote-signer"
DIRECT_SERVICE = "validator-hoodi-example-remote-signer-direct"
SIGNER_POLICY = "validator-hoodi-example-signer-ingress"
FENCE_LABELS = {"app.kubernetes.io/component": "validator-signing-fence",
                "node-operator.io/validator-set": SET}
SIGNER_LABELS = {"app.kubernetes.io/component": "validator-remote-signer",
                 "node-operator.io/validator-set": SET}
PUBKEY = re.compile(r"^0x[0-9a-f]{96}$")
MAX_LIST_ITEMS = 128


class CollectionError(RuntimeError):
    """A non-sensitive refusal from the bounded collector."""


def _fail(message):
    raise CollectionError(message)


def kubectl_runner(args):
    """Default injectable runner.  Tests supply an in-memory equivalent."""
    try:
        result = subprocess.run(["kubectl", "--request-timeout=20s", *args], text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                timeout=25, check=False)
    except subprocess.TimeoutExpired as error:
        raise CollectionError("kubectl collection timed out") from error
    if result.returncode:
        _fail("kubectl collection failed")
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise CollectionError("kubectl response malformed") from error


def _get(runner, *args):
    try:
        value = runner(tuple(args))
    except CollectionError:
        raise
    except subprocess.TimeoutExpired as error:
        raise CollectionError("kubectl collection timed out") from error
    except TimeoutError as error:
        raise CollectionError("kubectl collection timed out") from error
    except Exception as error:
        raise CollectionError("kubectl collection failed") from error
    if not isinstance(value, dict):
        _fail("kubectl response malformed")
    return value


def _named(runner, resource, name, namespace=NAMESPACE):
    value = _get(runner, "-n", namespace, "get", resource, name, "-o", "json")
    _object_identity(value, namespace, name)
    return value


def _list(runner, resource, namespace=NAMESPACE, label_selector=None):
    args = ["-n", namespace, "get", resource]
    if label_selector is not None:
        args.extend(("-l", label_selector))
    value = _get(runner, *args, "-o", "json")
    if not isinstance(value.get("items"), list) or len(value["items"]) > MAX_LIST_ITEMS:
        _fail("kubectl response malformed")
    for item in value["items"]:
        _object_identity(item, namespace)
    return value["items"]


def _metadata(object_):
    metadata = object_.get("metadata") if isinstance(object_, dict) else None
    if not isinstance(metadata, dict):
        _fail("Kubernetes object metadata is malformed")
    return metadata


def _object_identity(object_, namespace, name=None):
    metadata = _metadata(object_)
    if (not isinstance(metadata.get("name"), str) or not metadata["name"] or
            metadata.get("namespace") != namespace or
            not isinstance(metadata.get("uid"), str) or not metadata["uid"] or
            (name is not None and metadata["name"] != name)):
        _fail("Kubernetes object identity is malformed")


def _uid(object_):
    value = _metadata(object_).get("uid")
    if not isinstance(value, str) or not value:
        _fail("Kubernetes object identity is malformed")
    return value


def _integer(value):
    return type(value) is int and value >= 0


def _controller(object_, name):
    metadata = _metadata(object_)
    spec, status = object_.get("spec"), object_.get("status", {})
    if not isinstance(spec, dict) or not isinstance(status, dict):
        _fail("Kubernetes controller is malformed")
    replicas = spec.get("replicas", 1)
    generation = metadata.get("generation")
    observed = status.get("observedGeneration")
    ready = status.get("readyReplicas", 0)
    actual = status.get("replicas", 0)
    if not all(_integer(value) for value in (replicas, generation, observed, ready, actual)):
        _fail("Kubernetes controller status is malformed")
    result = {"uid": _uid(object_), "spec_replicas": replicas, "status_replicas": actual,
              "ready_replicas": ready, "generation": generation,
              "observed_generation": observed,
              "deletion_timestamp_absent": metadata.get("deletionTimestamp") is None}
    if name == "signer":
        template = spec.get("template", {})
        pod_spec = template.get("spec", {}) if isinstance(template, dict) else None
        containers = pod_spec.get("containers", []) if isinstance(pod_spec, dict) else None
        if not isinstance(containers, list):
            _fail("signer container identity is malformed")
        matches = [item.get("image") for item in containers if isinstance(item, dict) and item.get("name") == "web3signer"]
        if len(matches) != 1 or not isinstance(matches[0], str) or not matches[0]:
            _fail("signer container identity is malformed")
        result["image"] = matches[0]
    return result


def _signer_template_labels(object_):
    spec = object_.get("spec") if isinstance(object_, dict) else None
    template = spec.get("template") if isinstance(spec, dict) else None
    metadata = template.get("metadata") if isinstance(template, dict) else None
    labels = metadata.get("labels") if isinstance(metadata, dict) else None
    if not isinstance(labels, dict) or any(labels.get(key) != value for key, value in SIGNER_LABELS.items()):
        _fail("signer template labels are malformed")
    if any(not isinstance(key, str) or not isinstance(value, str) for key, value in labels.items()):
        _fail("signer template labels are malformed")
    return dict(labels)


def _service_snapshot(object_, selector, target, message):
    spec = object_.get("spec") if isinstance(object_, dict) else None
    if (not isinstance(spec, dict) or spec.get("type") != "ClusterIP" or
            spec.get("selector") != selector or spec.get("externalIPs") or
            spec.get("loadBalancerIP") is not None or spec.get("externalName") is not None or
            spec.get("loadBalancerClass") is not None or spec.get("loadBalancerSourceRanges") or
            spec.get("healthCheckNodePort") is not None):
        _fail(message)
    ports = spec.get("ports")
    if not isinstance(ports, list) or len(ports) != 1 or not isinstance(ports[0], dict):
        _fail(message)
    port = ports[0]
    if (port.get("port") != 9000 or port.get("targetPort") != target or
            port.get("protocol", "TCP") != "TCP" or "nodePort" in port):
        _fail(message)
    # Keep every routing-relevant, non-secret Service field so later drift is
    # visible to uc5-live-guards without retaining annotations or cluster data.
    result = {"type": "ClusterIP", "selector": dict(selector),
              "port": {key: port.get(key) for key in ("name", "protocol", "port", "targetPort", "appProtocol") if key in port}}
    for key in ("clusterIP", "clusterIPs", "ipFamilies", "ipFamilyPolicy", "internalTrafficPolicy",
                "publishNotReadyAddresses", "sessionAffinity", "trafficDistribution"):
        if key in spec:
            result[key] = spec[key]
    if "sessionAffinityConfig" in spec:
        result["sessionAffinityConfig"] = spec["sessionAffinityConfig"]
    return result


def _require_public_service(object_):
    return _service_snapshot(object_, FENCE_LABELS, "fence-proxy",
                             "UC5 baseline public signer Service is incompatible")


def _require_direct_service(object_):
    return _service_snapshot(object_, SIGNER_LABELS, "signer-api",
                             "UC5 baseline direct signer Service is incompatible")


def _matches_signer_selector(spec, signer_labels):
    if not isinstance(spec, dict):
        _fail("UC5 signer NetworkPolicy selector is malformed")
    selector = spec.get("podSelector") if isinstance(spec, dict) else None
    if not isinstance(selector, dict):
        _fail("UC5 signer NetworkPolicy selector is malformed")
    labels = selector.get("matchLabels", {})
    if not isinstance(labels, dict) or any(signer_labels.get(key) != value for key, value in labels.items()):
        return False
    expressions = selector.get("matchExpressions", [])
    if not isinstance(expressions, list):
        _fail("UC5 signer NetworkPolicy selector is malformed")
    for expression in expressions:
        if not isinstance(expression, dict) or set(expression) - {"key", "operator", "values"}:
            _fail("UC5 signer NetworkPolicy selector is unsupported")
        key, operator, values = expression.get("key"), expression.get("operator"), expression.get("values", [])
        if not isinstance(key, str) or not isinstance(operator, str) or not isinstance(values, list) or any(not isinstance(value, str) for value in values):
            _fail("UC5 signer NetworkPolicy selector is unsupported")
        actual = signer_labels.get(key)
        if operator == "In":
            if not values or actual not in values: return False
        elif operator == "NotIn":
            if not values or actual in values: return False
        elif operator == "Exists":
            if values or actual is None: return False
        elif operator == "DoesNotExist":
            if values or actual is not None: return False
        else:
            _fail("UC5 signer NetworkPolicy selector is unsupported")
    return True


def _require_signer_ingress(spec):
    if spec.get("podSelector", {}).get("matchLabels") != SIGNER_LABELS or spec.get("policyTypes") != ["Ingress"]:
        _fail("UC5 baseline signer ingress policy is incompatible")
    ingress = spec.get("ingress")
    if not isinstance(ingress, list) or len(ingress) != 1 or not isinstance(ingress[0], dict):
        _fail("UC5 baseline signer ingress policy is incompatible")
    rule = ingress[0]
    sources, ports = rule.get("from"), rule.get("ports")
    if not isinstance(sources, list) or len(sources) != 1 or not isinstance(sources[0], dict):
        _fail("UC5 baseline signer ingress policy is incompatible")
    source_selector = sources[0].get("podSelector")
    if set(sources[0]) != {"podSelector"} or not isinstance(source_selector, dict) or source_selector.get("matchLabels") != FENCE_LABELS:
        _fail("UC5 baseline signer ingress policy is incompatible")
    if ports != [{"protocol": "TCP", "port": 9000}]:
        _fail("UC5 baseline signer ingress policy is incompatible")
    return {"pod_selector": dict(SIGNER_LABELS), "policy_types": ["Ingress"],
            "ingress": [{"from_pod_selector": dict(FENCE_LABELS),
                         "ports": [{"protocol": "TCP", "port": 9000}]}]}


def _policy_snapshot(policy, spec, signer_labels):
    selector = spec.get("podSelector")
    types = spec.get("policyTypes")
    ingress = spec.get("ingress", [])
    if not isinstance(types, list) or any(value not in ("Ingress", "Egress") for value in types) or not isinstance(ingress, list):
        _fail("UC5 baseline signer ingress policy is incompatible")
    normalized = {"name": policy["metadata"]["name"],
                  "pod_selector": {"match_labels": dict(selector.get("matchLabels", {})),
                                   "match_expressions": selector.get("matchExpressions", [])},
                  "policy_types": list(types), "ingress": []}
    # An absent/empty ingress list is a deny-all ingress contribution and is
    # safe even when the same policy also declares Egress.
    if ingress:
        permissive = _require_signer_ingress({"podSelector": {"matchLabels": SIGNER_LABELS},
                                              "policyTypes": ["Ingress"], "ingress": ingress})
        normalized["ingress"] = permissive["ingress"]
    return normalized


def _network_specs(runner, signer_labels):
    public = _require_public_service(_named(runner, "service", PUBLIC_SERVICE))
    direct = _require_direct_service(_named(runner, "service", DIRECT_SERVICE))
    policies = []
    expected = None
    for policy in _list(runner, "networkpolicies"):
        spec = policy.get("spec") if isinstance(policy, dict) else None
        if not _matches_signer_selector(spec, signer_labels):
            continue
        normalized = _policy_snapshot(policy, spec, signer_labels)
        if policy["metadata"]["name"] == SIGNER_POLICY:
            expected = _require_signer_ingress(spec)
        policies.append(normalized)
    if expected is None:
        _fail("UC5 baseline signer ingress policy is incompatible")
    return {"service_specs": {"public": public, "direct": direct},
            "network_policy_specs": {"signer_ingress": expected, "signer_selector_policies": policies}}


def _owned_pods(runner, controller_uids):
    """Return presence sentinels for all Pods owned by our fixed controllers.

    Deployment Pods are attached through their ReplicaSet owner, not labels;
    StatefulSet Pods attach directly.  A terminating Pod remains present.
    """
    replica_sets = _list(runner, "replicasets")
    deployment_uids = {controller_uids["fence"]: "fence", controller_uids["signer"]: "signer"}
    rs_to_deployment = {}
    for replica_set in replica_sets:
        owners = _metadata(replica_set).get("ownerReferences", [])
        if not isinstance(owners, list):
            _fail("Kubernetes owner references are malformed")
        for owner in owners:
            if isinstance(owner, dict) and owner.get("controller") is True and owner.get("uid") in deployment_uids:
                rs_to_deployment[_uid(replica_set)] = deployment_uids[owner["uid"]]
    result = {"client": [], "fence": [], "signer": []}
    workload_labels = {"client": {"app.kubernetes.io/component": "validator-client", "node-operator.io/validator-set": SET},
                       "fence": FENCE_LABELS, "signer": SIGNER_LABELS}
    for pod in _list(runner, "pods"):
        metadata = _metadata(pod)
        owners = metadata.get("ownerReferences", [])
        if not isinstance(owners, list):
            _fail("Kubernetes owner references are malformed")
        owner_uids = {owner.get("uid") for owner in owners if isinstance(owner, dict) and owner.get("controller") is True}
        labels = metadata.get("labels", {})
        if not isinstance(labels, dict):
            _fail("Kubernetes Pod labels are malformed")
        if controller_uids["client"] in owner_uids or all(labels.get(key) == value for key, value in workload_labels["client"].items()):
            result["client"].append("owned")
        if (controller_uids["fence"] in owner_uids or any(rs_to_deployment.get(uid) == "fence" for uid in owner_uids) or
                all(labels.get(key) == value for key, value in workload_labels["fence"].items())):
            result["fence"].append("owned")
        if (controller_uids["signer"] in owner_uids or any(rs_to_deployment.get(uid) == "signer" for uid in owner_uids) or
                all(labels.get(key) == value for key, value in workload_labels["signer"].items())):
            result["signer"].append("owned")
    return result


def _lease(runner):
    spec = _named(runner, "lease", LEASE).get("spec")
    if not isinstance(spec, dict):
        _fail("Lease state is malformed")
    holder, renew, duration = spec.get("holderIdentity", ""), spec.get("renewTime"), spec.get("leaseDurationSeconds")
    if not isinstance(holder, str) or not isinstance(renew, str) or not _integer(duration):
        _fail("Lease state is malformed")
    return {"holder_identity": holder, "renew_time_utc": renew, "duration_seconds": duration}


def _hpas(runner):
    names = []
    expected = {name for _, name in CONTROLLERS.values()}
    for hpa in _list(runner, "hpa"):
        spec = hpa.get("spec") if isinstance(hpa, dict) else None
        target = spec.get("scaleTargetRef") if isinstance(spec, dict) else None
        if isinstance(target, dict) and target.get("name") in expected:
            names.append("competing")
    return names


def _argo(runner):
    active = []
    automated = False
    for application in _list(runner, "applications.argoproj.io", ARGO_NAMESPACE):
        spec = application.get("spec", {}) if isinstance(application, dict) else {}
        destination = spec.get("destination") if isinstance(spec, dict) else None
        status = application.get("status", {}) if isinstance(application, dict) else {}
        resources = status.get("resources", []) if isinstance(status, dict) else None
        if not isinstance(resources, list) or len(resources) > MAX_LIST_ITEMS:
            _fail("Argo application status is malformed")
        resource_targets_namespace = isinstance(resources, list) and any(
            isinstance(resource, dict) and resource.get("namespace") == NAMESPACE for resource in resources)
        if not isinstance(destination, dict) or (destination.get("namespace") != NAMESPACE and not resource_targets_namespace):
            continue
        operation = status.get("operationState") if isinstance(status, dict) else None
        phase = operation.get("phase") if isinstance(operation, dict) else None
        if application.get("operation") is not None or phase in ("Running", "Terminating"):
            active.append("active")
        if isinstance(spec.get("syncPolicy"), dict) and spec["syncPolicy"].get("automated") is not None:
            automated = True
    return {"active_operations": active, "automated_validator_namespace": automated}


def _endpoint(runner):
    slices = _list(runner, "endpointslices.discovery.k8s.io",
                   label_selector="kubernetes.io/service-name=" + PUBLIC_SERVICE)
    count = 0
    for slice_ in slices:
        labels = _metadata(slice_).get("labels", {})
        if not isinstance(labels, dict):
            _fail("public signer endpoint is malformed")
        if labels.get("kubernetes.io/service-name") != PUBLIC_SERVICE:
            continue
        if "endpoints" not in slice_:
            _fail("public signer endpoint is malformed")
        endpoints = slice_["endpoints"]
        # The EndpointSlice controller serializes its empty slice as null
        # after the last backend disappears. Missing/other types are not empty.
        if endpoints is None:
            endpoints = []
        if not isinstance(endpoints, list) or len(endpoints) > MAX_LIST_ITEMS:
            _fail("public signer endpoint is malformed")
        for endpoint in endpoints:
            conditions = endpoint.get("conditions", {}) if isinstance(endpoint, dict) else None
            if (not isinstance(conditions, dict) or
                    any(conditions.get(key) not in (True, False, None) for key in ("ready", "serving", "terminating"))):
                _fail("public signer endpoint is malformed")
            # Unknown readiness and terminating/serving endpoints are not
            # treated as absent: a deletion gate needs the conservative view.
            if (conditions.get("ready") is not False or conditions.get("serving") is True or
                    conditions.get("terminating") is True):
                count += 1
                if count > MAX_LIST_ITEMS:
                    _fail("public signer endpoint is malformed")
    return {"ready_addresses": ["present"] * count}


def collect_baseline(runner, validator_public_key):
    """Collect the immutable, redacted baseline schema expected by UC-5 guards."""
    if not isinstance(validator_public_key, str) or not PUBKEY.fullmatch(validator_public_key):
        _fail("baseline public key is malformed")
    objects = {name: _named(runner, kind, object_name) for name, (kind, object_name) in CONTROLLERS.items()}
    controllers = {name: {"uid": _uid(object_)} for name, object_ in objects.items()}
    controllers["signer"]["image"] = _controller(objects["signer"], "signer")["image"]
    pvc = _named(runner, "pvc", PVC)
    controllers["db"]["pvc_uid"] = _uid(pvc)
    network = _network_specs(runner, _signer_template_labels(objects["signer"]))
    return {"schema_version": 1, "validator_set": SET, "validator_public_key": validator_public_key,
            "controllers": controllers, **network}


def collect_live(runner, baseline):
    """Collect the immutable, redacted live schema expected by UC-5 guards."""
    if not isinstance(baseline, dict) or baseline.get("validator_set") != SET:
        _fail("baseline shape is malformed")
    objects = {name: _named(runner, kind, object_name) for name, (kind, object_name) in CONTROLLERS.items()}
    controllers = {name: _controller(object_, name) for name, object_ in objects.items()}
    pvc = _named(runner, "pvc", PVC)
    phase = pvc.get("status", {}).get("phase") if isinstance(pvc, dict) else None
    if not isinstance(phase, str):
        _fail("database PVC is malformed")
    controllers["db"]["pvc_uid"] = _uid(pvc)
    controllers["db"]["pvc_phase"] = phase
    network = _network_specs(runner, _signer_template_labels(objects["signer"]))
    return {"schema_version": 1, "validator_set": SET, "controllers": controllers,
            "matching_pods": _owned_pods(runner, {name: controllers[name]["uid"] for name in controllers}),
            "lease": _lease(runner), "competing_hpas": _hpas(runner), "argo": _argo(runner),
            **network, "public_endpoint": _endpoint(runner)}


def main():
    parser = argparse.ArgumentParser(description="bounded UC5 Kubernetes state collector")
    parser.add_argument("mode", choices=("baseline", "live"))
    parser.add_argument("--validator-public-key")
    parser.add_argument("--baseline", type=pathlib.Path)
    args = parser.parse_args()
    if args.mode == "baseline":
        if args.baseline is not None or args.validator_public_key is None:
            _fail("baseline collection requires only a validator public key")
        result = collect_baseline(kubectl_runner, args.validator_public_key)
    else:
        if args.validator_public_key is not None or args.baseline is None:
            _fail("live collection requires only a baseline file")
        try:
            baseline = json.loads(args.baseline.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise CollectionError("baseline input is malformed") from error
        result = collect_live(kubectl_runner, baseline)
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    try:
        main()
    except CollectionError as error:
        raise SystemExit(str(error))
