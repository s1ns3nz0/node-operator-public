#!/usr/bin/env python3
# Check objective: Verify UC5 immediate pre-delete guards reject unsafe live state.
"""Synthetic-only contract tests for UC-5 immediate pre-delete guards."""
import copy
import importlib.util
import pathlib


ROOT = pathlib.Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "uc5_live_guards", ROOT / "scripts/ops/lib/uc5-live-guards.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
NOW = 1_789_084_800  # 2026-09-11T00:00:00Z
KEY = "0x" + "ab" * 48


def proof():
    return {"schema_version": 1, "event_type": "signing-proxy-fence",
            "collected_at_utc": "2026-09-11T00:00:00Z", "network": "hoodi",
            "validator_set": "hoodi-example", "validator_public_key": KEY,
            "source": "signing-proxy-fence",
            "payload": {"fence_live": True, "lease_enforced": True,
                        "direct_client_to_signer_denied": True, "cached_key_requests_blocked": True,
                        "in_flight_request_bound": True, "fence_live_before_quiesce": True,
                        "client_and_fence_quiesced": True, "direct_probe_pod_uid": "direct-uid",
                        "fence_control_probe_pod_uid": "control-uid", "fence_pod_uid_before_quiesce": "fence-old-uid",
                        "probe_scope": "GET-only public-key endpoint; no signing request, key, token, or raw TLS material"}}


def baseline():
    return {"schema_version": 1, "validator_set": "hoodi-example", "validator_public_key": KEY,
            "controllers": {"client": {"uid": "client-uid"}, "fence": {"uid": "fence-uid"},
                            "signer": {"uid": "signer-uid", "image": "registry/signer@sha256:" + "a" * 64},
                            "db": {"uid": "db-uid", "pvc_uid": "pvc-uid"}},
            "service_specs": {"public": {"selector": {"component": "fence"}}},
            "network_policy_specs": {"signer_ingress": {"allow": "fence-only"}}}


def controller(uid, replicas, ready, image=None, pvc_uid=None):
    out = {"uid": uid, "spec_replicas": replicas, "status_replicas": replicas,
           "ready_replicas": ready, "generation": 4, "observed_generation": 4,
           "deletion_timestamp_absent": True}
    if image is not None: out["image"] = image
    if pvc_uid is not None:
        out["pvc_uid"] = pvc_uid
        out["pvc_phase"] = "Bound"
    return out


def live():
    b = baseline()
    return {"schema_version": 1, "validator_set": "hoodi-example",
            "controllers": {"client": controller("client-uid", 0, 0), "fence": controller("fence-uid", 0, 0),
                            "signer": controller("signer-uid", 0, 0, b["controllers"]["signer"]["image"]),
                            "db": controller("db-uid", 1, 1, pvc_uid="pvc-uid")},
            "matching_pods": {"client": [], "fence": [], "signer": []},
            "lease": {"holder_identity": "", "renew_time_utc": "2026-09-10T23:59:00.670189Z", "duration_seconds": 30},
            "competing_hpas": [], "argo": {"active_operations": [], "automated_validator_namespace": False},
            "service_specs": b["service_specs"], "network_policy_specs": b["network_policy_specs"],
            "public_endpoint": {"ready_addresses": []}}


def rejects(fn):
    try: fn()
    except MODULE.GuardError: return
    raise AssertionError("unsafe fixture accepted")


def test_positive_guard_emits_only_sanitized_identity_and_hashes():
    result = MODULE.verify_predelete(proof(), baseline(), live(), now_epoch=NOW)
    assert result["validator_set"] == "hoodi-example"
    assert result["identities"]["signer_image"].endswith("a" * 64)
    assert set(result) == {"validator_set", "proof_collected_at_utc", "proof_sha256", "baseline_sha256", "live_sha256", "identities"}


def test_stale_future_malformed_and_unsafe_fence_proofs_are_rejected():
    p = proof(); p["collected_at_utc"] = "2026-09-10T23:54:59Z"
    rejects(lambda: MODULE.verify_predelete(p, baseline(), live(), NOW))
    p = proof(); p["collected_at_utc"] = "2026-09-11T00:00:31Z"
    rejects(lambda: MODULE.verify_predelete(p, baseline(), live(), NOW))
    p = proof(); p["payload"].pop("lease_enforced")
    rejects(lambda: MODULE.verify_predelete(p, baseline(), live(), NOW))
    p = proof(); p["validator_public_key"] = "0x" + "cd" * 48
    rejects(lambda: MODULE.verify_predelete(p, baseline(), live(), NOW))
    p = proof(); p["schema_version"] = True
    rejects(lambda: MODULE.verify_predelete(p, baseline(), live(), NOW))
    b = baseline(); b["schema_version"] = True
    rejects(lambda: MODULE.verify_predelete(proof(), b, live(), NOW))


def test_each_live_safety_boundary_rejects_drift_or_activity():
    cases = []
    x = live(); x["controllers"]["client"]["spec_replicas"] = 1; cases.append(x)
    x = live(); x["matching_pods"]["fence"] = ["fence-pod"]; cases.append(x)
    x = live(); x["matching_pods"]["signer"] = ["signer-pod"]; cases.append(x)
    x = live(); x["controllers"]["signer"]["image"] = "registry/signer@sha256:" + "b" * 64; cases.append(x)
    x = live(); x["controllers"]["db"]["pvc_uid"] = "other-pvc"; cases.append(x)
    x = live(); x["controllers"]["db"]["pvc_phase"] = "Pending"; cases.append(x)
    x = live(); x["controllers"]["signer"]["deletion_timestamp_absent"] = False; cases.append(x)
    x = live(); x["lease"]["holder_identity"] = "live-fence"; x["lease"]["renew_time_utc"] = "2026-09-11T00:00:00Z"; cases.append(x)
    x = live(); x["competing_hpas"] = ["client-hpa"]; cases.append(x)
    x = live(); x["argo"]["automated_validator_namespace"] = True; cases.append(x)
    x = live(); x["service_specs"]["public"] = {"selector": {"component": "signer"}}; cases.append(x)
    x = live(); x["network_policy_specs"]["signer_ingress"] = {"allow": "all"}; cases.append(x)
    x = live(); x["public_endpoint"]["ready_addresses"] = ["10.0.0.4"]; cases.append(x)
    x = live(); x["controllers"]["db"]["ready_replicas"] = True; cases.append(x)
    x = live(); x["lease"] = {"holder_identity": "", "duration_seconds": 30}; cases.append(x)
    x = live(); x["schema_version"] = True; cases.append(x)
    for unsafe in cases:
        rejects(lambda unsafe=unsafe: MODULE.verify_predelete(proof(), baseline(), unsafe, NOW))


def test_fractional_freshness_boundaries_do_not_round_to_seconds():
    for timestamp in ("2026-09-11T00:00:30.000000001Z", "2026-09-10T23:54:59.999999999Z"):
        p = proof(); p["collected_at_utc"] = timestamp
        rejects(lambda: MODULE.verify_predelete(p, baseline(), live(), NOW))
    for timestamp in ("2026-09-11T00:00:30.000000000Z", "2026-09-10T23:55:00.000000000Z"):
        p = proof(); p["collected_at_utc"] = timestamp
        MODULE.verify_predelete(p, baseline(), live(), NOW)
    x = live()
    x["lease"] = {"holder_identity": "holder", "renew_time_utc": "2026-09-10T23:59:30.000000001Z", "duration_seconds": 30}
    rejects(lambda: MODULE.verify_predelete(proof(), baseline(), x, NOW))


if __name__ == "__main__":
    test_positive_guard_emits_only_sanitized_identity_and_hashes()
    test_stale_future_malformed_and_unsafe_fence_proofs_are_rejected()
    test_each_live_safety_boundary_rejects_drift_or_activity()
    test_fractional_freshness_boundaries_do_not_round_to_seconds()
    print("PASS uc5 live guards")
