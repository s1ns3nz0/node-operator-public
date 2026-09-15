#!/usr/bin/env python3
"""Pure, fail-closed UC-5 guards for the instant before runtime-role deletion.

The caller supplies already-redacted Kubernetes snapshots.  This module makes
no subprocess, network, filesystem, or Vault calls and returns hashes plus the
minimum non-secret identities needed to bind a later deletion record.
"""
import datetime as dt
import calendar
from decimal import Decimal
import hashlib
import json
import re

SET = "hoodi-example"
PROOF_SCOPE = "GET-only public-key endpoint; no signing request, key, token, or raw TLS material"
PROOF_TOP = frozenset(("schema_version", "event_type", "collected_at_utc", "network", "validator_set",
                       "validator_public_key", "source", "payload"))
PROOF_PAYLOAD = frozenset(("fence_live", "lease_enforced", "direct_client_to_signer_denied",
                           "cached_key_requests_blocked", "in_flight_request_bound",
                           "fence_live_before_quiesce", "client_and_fence_quiesced",
                           "direct_probe_pod_uid", "fence_control_probe_pod_uid",
                           "fence_pod_uid_before_quiesce", "probe_scope"))
UID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
PUBKEY = re.compile(r"^0x[0-9a-f]{96}$")


class GuardError(RuntimeError):
    """Fixed non-sensitive refusal message."""


def _fail(message):
    raise GuardError(message)


def _canonical(value):
    try:
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    except (TypeError, ValueError) as error:
        raise GuardError("guard input is not canonical JSON") from error
    if len(encoded) > 65536:
        _fail("guard input exceeds bounded size")
    return encoded


def _hash(value):
    return hashlib.sha256(_canonical(value).encode("ascii")).hexdigest()


def _integer(value):
    return type(value) is int


def _timestamp(value):
    if not isinstance(value, str) or not re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z", value):
        _fail("fence proof timestamp is malformed")
    try:
        whole, _, fraction = value.removesuffix("Z").partition(".")
        seconds = calendar.timegm(dt.datetime.strptime(whole, "%Y-%m-%dT%H:%M:%S").timetuple())
        return Decimal(seconds) + (Decimal("0." + fraction) if fraction else 0)
    except ValueError as error:
        raise GuardError("fence proof timestamp is malformed") from error


def _uid(value):
    if not isinstance(value, str) or not UID.fullmatch(value):
        _fail("guard identity is malformed")


def verify_fence_proof(proof, expected_public_key, now_epoch):
    """Validate the exact fresh fence-producer schema, key, and five-minute TTL."""
    if (not isinstance(proof, dict) or set(proof) != PROOF_TOP or not _integer(proof["schema_version"]) or
            not _integer(now_epoch)):
        _fail("fence proof shape is malformed")
    if (proof["schema_version"] != 1 or proof["event_type"] != "signing-proxy-fence" or
            proof["network"] != "hoodi" or proof["validator_set"] != SET or
            proof["source"] != "signing-proxy-fence" or proof["validator_public_key"] != expected_public_key or
            not isinstance(expected_public_key, str) or not PUBKEY.fullmatch(expected_public_key)):
        _fail("fence proof identity does not match the fixed Hoodi target")
    observed = _timestamp(proof["collected_at_utc"])
    if observed > now_epoch + 30 or now_epoch - observed > 300:
        _fail("fence proof is stale or future dated")
    payload = proof["payload"]
    if not isinstance(payload, dict) or set(payload) != PROOF_PAYLOAD:
        _fail("fence proof payload is malformed")
    for field in ("fence_live", "lease_enforced", "direct_client_to_signer_denied",
                  "cached_key_requests_blocked", "in_flight_request_bound", "fence_live_before_quiesce",
                  "client_and_fence_quiesced"):
        if payload[field] is not True:
            _fail("fence proof does not establish all required controls")
    for field in ("direct_probe_pod_uid", "fence_control_probe_pod_uid", "fence_pod_uid_before_quiesce"):
        _uid(payload[field])
    if payload["probe_scope"] != PROOF_SCOPE:
        _fail("fence proof scope is not the approved non-signing probe")
    return {"collected_at_utc": proof["collected_at_utc"], "sha256": _hash(proof)}


def _baseline(baseline):
    required = {"schema_version", "validator_set", "validator_public_key", "controllers", "service_specs", "network_policy_specs"}
    if (not isinstance(baseline, dict) or set(baseline) != required or not _integer(baseline["schema_version"]) or
            baseline["schema_version"] != 1 or baseline["validator_set"] != SET):
        _fail("baseline shape is malformed")
    if not isinstance(baseline["validator_public_key"], str) or not PUBKEY.fullmatch(baseline["validator_public_key"]):
        _fail("baseline public key is malformed")
    controllers = baseline["controllers"]
    if not isinstance(controllers, dict) or set(controllers) != {"client", "fence", "signer", "db"}:
        _fail("baseline controller set is malformed")
    for name in ("client", "fence", "db"):
        item = controllers[name]
        if not isinstance(item, dict) or set(item) != ({"uid"} if name != "db" else {"uid", "pvc_uid"}):
            _fail("baseline controller identity is malformed")
        _uid(item["uid"])
        if name == "db": _uid(item["pvc_uid"])
    signer = controllers["signer"]
    if not isinstance(signer, dict) or set(signer) != {"uid", "image"} or not isinstance(signer["image"], str) or not signer["image"]:
        _fail("baseline signer identity is malformed")
    _uid(signer["uid"])
    for name in ("service_specs", "network_policy_specs"):
        if not isinstance(baseline[name], dict) or not baseline[name]:
            _fail("baseline network specifications are malformed")
    return baseline


def _controller(value, expected_uid, replicas, ready, image=None, pvc_uid=None):
    expected_keys = {"uid", "spec_replicas", "status_replicas", "ready_replicas", "generation", "observed_generation", "deletion_timestamp_absent"}
    if image is not None: expected_keys.add("image")
    if pvc_uid is not None: expected_keys.update(("pvc_uid", "pvc_phase"))
    if not isinstance(value, dict) or set(value) != expected_keys or value.get("uid") != expected_uid:
        _fail("live controller identity is malformed or changed")
    _uid(value["uid"])
    if value["deletion_timestamp_absent"] is not True:
        _fail("live controller is terminating")
    if any(not _integer(value[field]) or value[field] < 0 for field in ("spec_replicas", "status_replicas", "ready_replicas", "generation", "observed_generation")):
        _fail("live controller status is malformed")
    if value["generation"] != value["observed_generation"] or value["spec_replicas"] != replicas or value["status_replicas"] != replicas or value["ready_replicas"] != ready:
        _fail("live controller is not in the required pre-delete state")
    if image is not None and value["image"] != image:
        _fail("signer image changed before role deletion")
    if pvc_uid is not None and value["pvc_uid"] != pvc_uid:
        _fail("database PVC changed before role deletion")


def _live(live, baseline, now_epoch):
    required = {"schema_version", "validator_set", "controllers", "matching_pods", "lease", "competing_hpas", "argo", "service_specs", "network_policy_specs", "public_endpoint"}
    if (not isinstance(live, dict) or set(live) != required or not _integer(live["schema_version"]) or
            live["schema_version"] != 1 or live["validator_set"] != SET):
        _fail("live state shape is malformed")
    controllers = live["controllers"]
    if not isinstance(controllers, dict) or set(controllers) != {"client", "fence", "signer", "db"}:
        _fail("live controller set is malformed")
    b = baseline["controllers"]
    _controller(controllers["client"], b["client"]["uid"], 0, 0)
    _controller(controllers["fence"], b["fence"]["uid"], 0, 0)
    _controller(controllers["signer"], b["signer"]["uid"], 0, 0, image=b["signer"]["image"])
    _controller(controllers["db"], b["db"]["uid"], 1, 1, pvc_uid=b["db"]["pvc_uid"])
    if controllers["db"].get("pvc_phase") != "Bound":
        _fail("database PVC is not Bound")
    if not isinstance(live["matching_pods"], dict) or set(live["matching_pods"]) != {"client", "fence", "signer"} or any(live["matching_pods"][name] != [] for name in ("client", "fence", "signer")):
        _fail("client, fence, or signer Pod remains before role deletion")
    lease = live["lease"]
    if not isinstance(lease, dict) or set(lease) != {"holder_identity", "renew_time_utc", "duration_seconds"} or not isinstance(lease["holder_identity"], str) or not _integer(lease["duration_seconds"]) or not 1 <= lease["duration_seconds"] <= 300:
        _fail("Lease state is malformed")
    renewed = _timestamp(lease["renew_time_utc"])
    if lease["holder_identity"] and renewed + lease["duration_seconds"] >= now_epoch:
        _fail("Lease has an unexpired holder")
    if not isinstance(live["competing_hpas"], list) or live["competing_hpas"] != []:
        _fail("competing HPA prevents role deletion")
    argo = live["argo"]
    if not isinstance(argo, dict) or set(argo) != {"active_operations", "automated_validator_namespace"} or not isinstance(argo["active_operations"], list) or argo["active_operations"] != [] or argo["automated_validator_namespace"] is not False:
        _fail("Argo state prevents role deletion")
    if live["service_specs"] != baseline["service_specs"] or live["network_policy_specs"] != baseline["network_policy_specs"]:
        _fail("Service or NetworkPolicy drift prevents role deletion")
    endpoint = live["public_endpoint"]
    if not isinstance(endpoint, dict) or set(endpoint) != {"ready_addresses"} or endpoint["ready_addresses"] != []:
        _fail("public signer endpoint retains ready addresses")


def verify_predelete(proof, baseline, live, now_epoch):
    """Return sanitized proof only after every immediate role-delete guard passes."""
    if not _integer(now_epoch):
        _fail("guard clock is malformed")
    baseline = _baseline(baseline)
    checked_proof = verify_fence_proof(proof, baseline["validator_public_key"], now_epoch)
    _live(live, baseline, now_epoch)
    return {"validator_set": SET, "proof_collected_at_utc": checked_proof["collected_at_utc"],
            "proof_sha256": checked_proof["sha256"], "baseline_sha256": _hash(baseline), "live_sha256": _hash(live),
            "identities": {"client_uid": baseline["controllers"]["client"]["uid"], "fence_uid": baseline["controllers"]["fence"]["uid"],
                           "signer_uid": baseline["controllers"]["signer"]["uid"], "signer_image": baseline["controllers"]["signer"]["image"],
                           "db_uid": baseline["controllers"]["db"]["uid"], "pvc_uid": baseline["controllers"]["db"]["pvc_uid"]}}
