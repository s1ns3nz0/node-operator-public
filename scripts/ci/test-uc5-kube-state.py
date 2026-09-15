#!/usr/bin/env python3
# Check objective: Verify the bounded UC5 Kubernetes state collector with synthetic fixtures.
"""Synthetic-only contract tests for the bounded UC5 Kubernetes collector."""
import copy
import importlib.util
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("uc5_kube_state", ROOT / "scripts/ops/lib/uc5-kube-state.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
GUARD_SPEC = importlib.util.spec_from_file_location("uc5_live_guards", ROOT / "scripts/ops/lib/uc5-live-guards.py")
GUARDS = importlib.util.module_from_spec(GUARD_SPEC)
GUARD_SPEC.loader.exec_module(GUARDS)
KEY = "0x" + "ab" * 48  # synthetic fixture, never a deployed validator key


def object_(uid, spec=None, status=None, owners=None, deletion=None, generation=4, name="fixture", namespace=MODULE.NAMESPACE):
    meta = {"uid": uid, "generation": generation, "name": name, "namespace": namespace}
    if owners is not None: meta["ownerReferences"] = owners
    if deletion is not None: meta["deletionTimestamp"] = deletion
    return {"metadata": meta, "spec": spec or {}, "status": status or {}}


def controller(uid, replicas, component, image=None):
    containers = [{"name": "web3signer", "image": image}] if image else [{"name": component, "image": "fixture"}]
    labels = copy.deepcopy(MODULE.SIGNER_LABELS) if image else {"app.kubernetes.io/component": component, "node-operator.io/validator-set": MODULE.SET}
    return object_(uid, {"replicas": replicas, "template": {"metadata": {"labels": labels}, "spec": {"containers": containers}}},
                   {"replicas": replicas, "readyReplicas": replicas, "observedGeneration": 4})


def service(selector, target):
    return {"metadata": {"uid": "service"}, "spec": {"type": "ClusterIP", "selector": selector, "ports": [{"protocol": "TCP", "port": 9000, "targetPort": target}]}}


def policy():
    return {"metadata": {"uid": "policy", "name": MODULE.SIGNER_POLICY, "namespace": MODULE.NAMESPACE}, "spec": {"podSelector": {"matchLabels": copy.deepcopy(MODULE.SIGNER_LABELS)},
            "policyTypes": ["Ingress"], "ingress": [{"from": [{"podSelector": {"matchLabels": copy.deepcopy(MODULE.FENCE_LABELS)}}],
            "ports": [{"protocol": "TCP", "port": 9000}]}]}}


def fixtures():
    image = "registry.example/signer@sha256:" + "a" * 64
    values = {
        ("-n", MODULE.NAMESPACE, "get", "statefulset", "validator-hoodi-example-client", "-o", "json"): controller("client-uid", 0, "client"),
        ("-n", MODULE.NAMESPACE, "get", "deployment", "validator-hoodi-example-signing-fence", "-o", "json"): controller("fence-uid", 0, "fence"),
        ("-n", MODULE.NAMESPACE, "get", "deployment", "validator-hoodi-example-remote-signer", "-o", "json"): controller("signer-uid", 0, "signer", image),
        ("-n", MODULE.NAMESPACE, "get", "statefulset", "validator-hoodi-example-slashing-db", "-o", "json"): controller("db-uid", 1, "db"),
        ("-n", MODULE.NAMESPACE, "get", "pvc", MODULE.PVC, "-o", "json"): {"metadata": {"uid": "pvc-uid"}, "status": {"phase": "Bound"}},
        ("-n", MODULE.NAMESPACE, "get", "service", MODULE.PUBLIC_SERVICE, "-o", "json"): service(copy.deepcopy(MODULE.FENCE_LABELS), "fence-proxy"),
        ("-n", MODULE.NAMESPACE, "get", "service", MODULE.DIRECT_SERVICE, "-o", "json"): service(copy.deepcopy(MODULE.SIGNER_LABELS), "signer-api"),
        ("-n", MODULE.NAMESPACE, "get", "networkpolicies", "-o", "json"): {"items": [policy()]},
        ("-n", MODULE.NAMESPACE, "get", "replicasets", "-o", "json"): {"items": []},
        ("-n", MODULE.NAMESPACE, "get", "pods", "-o", "json"): {"items": []},
        ("-n", MODULE.NAMESPACE, "get", "lease", MODULE.LEASE, "-o", "json"): {"metadata": {"uid": "lease"}, "spec": {"holderIdentity": "", "renewTime": "2026-09-11T00:00:00Z", "leaseDurationSeconds": 60}},
        ("-n", MODULE.NAMESPACE, "get", "hpa", "-o", "json"): {"items": []},
        ("-n", MODULE.ARGO_NAMESPACE, "get", "applications.argoproj.io", "-o", "json"): {"items": []},
        ("-n", MODULE.NAMESPACE, "get", "endpointslices.discovery.k8s.io", "-l", "kubernetes.io/service-name=" + MODULE.PUBLIC_SERVICE, "-o", "json"): {"items": []},
    }
    for args, value in values.items():
        if len(args) == 7:
            value.setdefault("metadata", {}).update({"name": args[4], "namespace": args[1]})
    return values


def runner(values, calls):
    def get(args):
        calls.append(args)
        return copy.deepcopy(values[args])
    return get


def rejects(fn, message=None):
    try:
        fn()
    except MODULE.CollectionError as error:
        if message is not None: assert str(error) == message
        return
    raise AssertionError("unsafe fixture accepted")


def test_exact_schemas_are_collected_from_only_fixed_reads():
    values, calls = fixtures(), []
    baseline = MODULE.collect_baseline(runner(values, calls), KEY)
    assert set(baseline) == {"schema_version", "validator_set", "validator_public_key", "controllers", "service_specs", "network_policy_specs"}
    assert baseline["controllers"]["signer"]["image"].endswith("a" * 64)
    live = MODULE.collect_live(runner(values, calls), baseline)
    assert set(live) == {"schema_version", "validator_set", "controllers", "matching_pods", "lease", "competing_hpas", "argo", "service_specs", "network_policy_specs", "public_endpoint"}
    assert live["matching_pods"] == {"client": [], "fence": [], "signer": []}
    proof = {"schema_version": 1, "event_type": "signing-proxy-fence", "collected_at_utc": "2026-09-11T00:00:00Z",
             "network": "hoodi", "validator_set": "hoodi-example", "validator_public_key": KEY, "source": "signing-proxy-fence",
             "payload": {"fence_live": True, "lease_enforced": True, "direct_client_to_signer_denied": True,
                         "cached_key_requests_blocked": True, "in_flight_request_bound": True, "fence_live_before_quiesce": True,
                         "client_and_fence_quiesced": True, "direct_probe_pod_uid": "direct", "fence_control_probe_pod_uid": "control",
                         "fence_pod_uid_before_quiesce": "fence-pod", "probe_scope": GUARDS.PROOF_SCOPE}}
    assert GUARDS.verify_predelete(proof, baseline, live, 1_789_084_800)["validator_set"] == "hoodi-example"
    assert all("secret" not in call and "log" not in call and "token" not in call for call in calls)
    assert all(call in values for call in calls)


def test_fixed_public_service_and_fence_only_ingress_are_non_negotiable():
    for mutate, expected in (
        (lambda v: v[("-n", MODULE.NAMESPACE, "get", "service", MODULE.PUBLIC_SERVICE, "-o", "json")]["spec"].update({"selector": {"app.kubernetes.io/component": "validator-remote-signer"}}), "UC5 baseline public signer Service is incompatible"),
        (lambda v: v[("-n", MODULE.NAMESPACE, "get", "networkpolicies", "-o", "json")]["items"][0]["spec"]["ingress"][0].update({"from": [{}]}), "UC5 baseline signer ingress policy is incompatible"),
        (lambda v: v[("-n", MODULE.NAMESPACE, "get", "networkpolicies", "-o", "json")]["items"][0]["spec"].update({"policyTypes": ["Ingress", "Egress"]}), "UC5 baseline signer ingress policy is incompatible"),
    ):
        values, calls = fixtures(), []
        mutate(values)
        rejects(lambda: MODULE.collect_baseline(runner(values, calls), KEY), expected)


def test_deployment_replicaset_and_terminating_pods_are_owned_not_label_matched():
    values, calls = fixtures(), []
    rs = object_("rs-signer", owners=[{"uid": "signer-uid", "controller": True}])
    terminating = object_("pod", owners=[{"uid": "rs-signer", "controller": True}], deletion="2026-09-11T00:00:00Z")
    misleading = object_("other", owners=[], deletion=None)
    misleading["metadata"]["labels"] = dict(MODULE.SIGNER_LABELS)
    values[("-n", MODULE.NAMESPACE, "get", "replicasets", "-o", "json")] = {"items": [rs]}
    values[("-n", MODULE.NAMESPACE, "get", "pods", "-o", "json")] = {"items": [terminating, misleading]}
    baseline = MODULE.collect_baseline(runner(values, calls), KEY)
    live = MODULE.collect_live(runner(values, calls), baseline)
    assert live["matching_pods"] == {"client": [], "fence": [], "signer": ["owned", "owned"]}


def test_additive_policies_endpoint_slices_and_argo_are_conservative():
    values, calls = fixtures(), []
    extra = policy()
    extra["metadata"]["name"] = "unexpected-signer-ingress"
    extra["metadata"]["uid"] = "unexpected-policy"
    extra["spec"]["ingress"][0]["from"] = [{"podSelector": {"matchLabels": {"app.kubernetes.io/component": "validator-signer-upcheck-proxy", "node-operator.io/validator-set": MODULE.SET}}}]
    values[("-n", MODULE.NAMESPACE, "get", "networkpolicies", "-o", "json")]["items"].append(extra)
    rejects(lambda: MODULE.collect_baseline(runner(values, calls), KEY), "UC5 baseline signer ingress policy is incompatible")

    values, calls = fixtures(), []
    values[("-n", MODULE.NAMESPACE, "get", "networkpolicies", "-o", "json")]["items"][0]["spec"]["podSelector"]["matchExpressions"] = [{"key": "role", "operator": "Bogus"}]
    rejects(lambda: MODULE.collect_baseline(runner(values, calls), KEY), "UC5 signer NetworkPolicy selector is unsupported")

    values, calls = fixtures(), []
    signer = values[("-n", MODULE.NAMESPACE, "get", "deployment", "validator-hoodi-example-remote-signer", "-o", "json")]
    signer["spec"]["template"]["metadata"]["labels"]["operator.example/track"] = "active"
    default_deny = object_("deny", name="default-deny-ingress-egress",
                           spec={"podSelector": {}, "policyTypes": ["Ingress", "Egress"]})
    matching_extra = policy()
    matching_extra["metadata"]["name"] = "extra-template-label-policy"
    matching_extra["metadata"]["uid"] = "extra-template"
    matching_extra["spec"]["podSelector"]["matchLabels"]["operator.example/track"] = "active"
    values[("-n", MODULE.NAMESPACE, "get", "networkpolicies", "-o", "json")]["items"].extend([default_deny, matching_extra])
    baseline = MODULE.collect_baseline(runner(values, calls), KEY)
    assert {policy["name"] for policy in baseline["network_policy_specs"]["signer_selector_policies"]} == {MODULE.SIGNER_POLICY, "default-deny-ingress-egress", "extra-template-label-policy"}

    values, calls = fixtures(), []
    slice_ = object_("slice", name="slice", spec={}, status={})
    slice_["metadata"]["labels"] = {"kubernetes.io/service-name": MODULE.PUBLIC_SERVICE}
    slice_["endpoints"] = [{"conditions": {"ready": None, "serving": False, "terminating": False}},
                            {"conditions": {"ready": False, "serving": True, "terminating": True}}]
    values[("-n", MODULE.NAMESPACE, "get", "endpointslices.discovery.k8s.io", "-l", "kubernetes.io/service-name=" + MODULE.PUBLIC_SERVICE, "-o", "json")] = {"items": [slice_]}
    baseline = MODULE.collect_baseline(runner(values, calls), KEY)
    assert MODULE.collect_live(runner(values, calls), baseline)["public_endpoint"] == {"ready_addresses": ["present", "present"]}

    values, calls = fixtures(), []
    app = object_("app", name="app", namespace=MODULE.ARGO_NAMESPACE,
                  spec={"destination": {"namespace": "elsewhere"}, "syncPolicy": {"automated": {}}},
                  status={"resources": [{"namespace": MODULE.NAMESPACE}]})
    app["operation"] = {"sync": {}}
    values[("-n", MODULE.ARGO_NAMESPACE, "get", "applications.argoproj.io", "-o", "json")] = {"items": [app]}
    baseline = MODULE.collect_baseline(runner(values, calls), KEY)
    state = MODULE.collect_live(runner(values, calls), baseline)["argo"]
    assert state == {"active_operations": ["active"], "automated_validator_namespace": True}


def test_list_bounds_and_service_exposure_are_refused():
    values, calls = fixtures(), []
    values[("-n", MODULE.NAMESPACE, "get", "pods", "-o", "json")] = {"items": [object_(str(index), name=str(index)) for index in range(MODULE.MAX_LIST_ITEMS + 1)]}
    baseline = MODULE.collect_baseline(runner(values, calls), KEY)
    rejects(lambda: MODULE.collect_live(runner(values, calls), baseline), "kubectl response malformed")
    values, calls = fixtures(), []
    values[("-n", MODULE.NAMESPACE, "get", "service", MODULE.DIRECT_SERVICE, "-o", "json")]["spec"]["externalIPs"] = ["192.0.2.1"]
    rejects(lambda: MODULE.collect_baseline(runner(values, calls), KEY), "UC5 baseline direct signer Service is incompatible")


def test_empty_endpoint_slice_null_is_not_a_malformed_response():
    values, calls = fixtures(), []
    slice_ = object_("slice", name="slice", spec={}, status={})
    slice_["metadata"]["labels"] = {"kubernetes.io/service-name": MODULE.PUBLIC_SERVICE}
    slice_["endpoints"], slice_["ports"] = None, None
    values[("-n", MODULE.NAMESPACE, "get", "endpointslices.discovery.k8s.io", "-l", "kubernetes.io/service-name=" + MODULE.PUBLIC_SERVICE, "-o", "json")] = {"items": [slice_]}
    baseline = MODULE.collect_baseline(runner(values, calls), KEY)
    assert MODULE.collect_live(runner(values, calls), baseline)["public_endpoint"] == {"ready_addresses": []}
    for invalid in ({}, "", 0, False):
        slice_["endpoints"] = invalid
        rejects(lambda: MODULE.collect_live(runner(values, calls), baseline), "public signer endpoint is malformed")
    del slice_["endpoints"]
    rejects(lambda: MODULE.collect_live(runner(values, calls), baseline), "public signer endpoint is malformed")


def test_timeout_and_runner_failures_have_fixed_non_sensitive_messages():
    rejects(lambda: MODULE.collect_baseline(lambda args: (_ for _ in ()).throw(TimeoutError()), KEY), "kubectl collection timed out")
    rejects(lambda: MODULE.collect_baseline(lambda args: (_ for _ in ()).throw(ValueError("sensitive API error")), KEY), "kubectl collection failed")


if __name__ == "__main__":
    test_exact_schemas_are_collected_from_only_fixed_reads()
    test_fixed_public_service_and_fence_only_ingress_are_non_negotiable()
    test_deployment_replicaset_and_terminating_pods_are_owned_not_label_matched()
    test_additive_policies_endpoint_slices_and_argo_are_conservative()
    test_list_bounds_and_service_exposure_are_refused()
    test_empty_endpoint_slice_null_is_not_a_malformed_response()
    test_timeout_and_runner_failures_have_fixed_non_sensitive_messages()
    print("PASS uc5 kube state")
