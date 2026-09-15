#!/usr/bin/env python3
"""Pure UC-5-to-activation evidence adapter; never reads caller proof files.

Call inline after successful continuity checks with the in-memory result from
``uc5_beacon_reader.read_ready`` and the concrete mTLS probe result.  This is
not a parser for arbitrary JSON and performs no Kubernetes, Beacon, Vault, or
filesystem operation.
"""
import datetime
import re

SET, INDEX = "hoodi-example", "1559065"
KEY = re.compile(r"^0x[0-9a-f]{96}$")
UTC = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z$")

class ActivationEvidenceError(RuntimeError): pass

def _timestamp(value):
    if not isinstance(value, str) or UTC.fullmatch(value) is None:
        raise ActivationEvidenceError("continuity timestamp malformed")
    try:
        return datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise ActivationEvidenceError("continuity timestamp malformed") from None

def require_continuity(value, baseline, expected_public_key):
    fields = {"result", "collected_at_utc", "validator_public_key", "same_slashing_history", "same_pvc_uid",
              "signer_absent_observed_at", "signer_instance", "mtls_identity_verified", "private_beacon_ready",
              "uc5_complete", "activation_performed"}
    if not isinstance(value, dict) or set(value) != fields:
        raise ActivationEvidenceError("continuity evidence schema invalid")
    if (value["result"] != "PASS_CONTINUITY_GATES" or value["validator_public_key"] != expected_public_key or
            any(value[k] is not True for k in ("same_slashing_history", "mtls_identity_verified", "private_beacon_ready")) or
            value["uc5_complete"] is not False or value["activation_performed"] is not False):
        raise ActivationEvidenceError("continuity evidence incomplete")
    try:
        expected_pvc = baseline["controllers"]["db"]["pvc_uid"]
    except (KeyError, TypeError):
        raise ActivationEvidenceError("continuity storage baseline absent") from None
    if not isinstance(expected_pvc, str) or not expected_pvc or value["same_pvc_uid"] != expected_pvc:
        raise ActivationEvidenceError("continuity storage identity mismatch")
    instance = value["signer_instance"]
    if (not isinstance(instance, list) or len(instance) != 4 or
            not isinstance(instance[0], str) or not re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", instance[0]) or
            not isinstance(instance[1], str) or len(instance[1]) > 2048 or not re.search(r"sha256:[0-9a-f]{64}$", instance[1]) or
            type(instance[2]) is not int or instance[2] < 0):
        raise ActivationEvidenceError("continuity signer identity malformed")
    observed = _timestamp(value["collected_at_utc"])
    if not _timestamp(value["signer_absent_observed_at"]) <= _timestamp(instance[3]) <= observed:
        raise ActivationEvidenceError("continuity ordering invalid")
    return True

def require_completed_ceremony(outcome):
    required = {"schema_version", "scope", "result", "failed_stage", "interrupted", "cleanup", "uc5_complete", "activation_allowed", "remaining"}
    if not isinstance(outcome, dict) or set(outcome) != required or outcome.get("result") != "PROBE_COMPLETE" or outcome.get("failed_stage") is not None or outcome.get("interrupted") is not False or outcome.get("activation_allowed") is not True or outcome.get("uc5_complete") is not False:
        raise ActivationEvidenceError("UC5 ceremony outcome is incomplete")
    cleanup = outcome.get("cleanup")
    if (type(outcome["schema_version"]) is not int or outcome["schema_version"] != 1 or
            outcome["scope"] != "UC-5 role revocation and restoration ceremony"):
        raise ActivationEvidenceError("UC5 ceremony schema or scope is invalid")
    if not isinstance(cleanup, dict) or set(cleanup) != {"administrator", "role", "fenced", "lock"} or cleanup.get("administrator") != "revoked" or cleanup.get("role") != "restored_exact" or cleanup.get("fenced") != "verified" or cleanup.get("lock") != "released":
        raise ActivationEvidenceError("UC5 ceremony cleanup is incomplete")
    return True

def adapt(beacon, tls_probe, collected_at_utc, expected_public_key):
    if not isinstance(expected_public_key, str) or KEY.fullmatch(expected_public_key) is None or not isinstance(collected_at_utc, str) or UTC.fullmatch(collected_at_utc) is None:
        raise ActivationEvidenceError("activation evidence identity or timestamp is malformed")
    try:
        datetime.datetime.strptime(collected_at_utc[:19], "%Y-%m-%dT%H:%M:%S")
    except ValueError:
        raise ActivationEvidenceError("activation evidence timestamp is malformed") from None
    if not isinstance(beacon, dict) or beacon.get("result") != "PASS_PRIVATE_BEACON_READY" or beacon.get("validator_public_key") != expected_public_key or str(beacon.get("validator_index")) != INDEX:
        raise ActivationEvidenceError("private Beacon readiness is not the fixed validator")
    if not isinstance(tls_probe, dict) or tls_probe.get("result") != "PASS" or tls_probe.get("layer") != "tls+http" or tls_probe.get("validator_public_key") != expected_public_key:
        raise ActivationEvidenceError("TLS probe is not the fixed signer identity")
    private = {"schema_version":1,"event_type":"uc-3","network":"hoodi","validator_set":SET,"source":"private-beacon","validator_public_key":expected_public_key,"collected_at_utc":collected_at_utc,"payload":{"syncing":{"is_syncing":False,"is_optimistic":False,"el_offline":False},"validator_http_status":"200","validator":{"status":"active_ongoing","validator":{"pubkey":expected_public_key},"index":INDEX}}}
    signer = {"schema_version":1,"event_type":"signer-public-key","network":"hoodi","validator_set":SET,"source":"vault-injected-mtls-get-only-probe","vault_agent_init_succeeded":True,"validator_public_key":expected_public_key,"collected_at_utc":collected_at_utc,"tls_verified":True,"public_key_count":1,"public_key_match":True}
    return {"private_evidence":private,"signer_evidence":signer}
