"""Pure audit binding. Never returns raw records, tokens, or error messages."""
import calendar
import datetime
from decimal import Decimal
import hashlib
import ipaddress
import json
import re

PATH = "auth/kubernetes/role/hoodi-hoodi-example-runtime"
UID = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}")
HMAC = re.compile(r"hmac-sha256:[0-9a-f]{64}")

class AuditProofError(ValueError):
    pass

def timestamp(value):
    if not isinstance(value, str) or not re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z", value):
        raise AuditProofError("audit timestamp malformed")
    whole, _, fraction = value[:-1].partition(".")
    try:
        seconds = calendar.timegm(datetime.datetime.strptime(whole, "%Y-%m-%dT%H:%M:%S").timetuple())
    except ValueError:
        raise AuditProofError("audit timestamp malformed") from None
    return Decimal(seconds) + (Decimal("0." + fraction) if fraction else 0)

def _context(context, end_name):
    required = {"runtime_role_path", "role_hmac", "pod_uid", "pod_ip", "pod_created_at",
                "deployment_uid", "deployment_generation", "delete_after", end_name}
    if not isinstance(context, dict) or set(context) != required or context["runtime_role_path"] != PATH:
        raise AuditProofError("audit context malformed")
    for key in ("pod_uid", "deployment_uid"):
        if not isinstance(context[key], str) or not UID.fullmatch(context[key]):
            raise AuditProofError("workload identity malformed")
    if not isinstance(context["role_hmac"], str) or not HMAC.fullmatch(context["role_hmac"]):
        raise AuditProofError("device role HMAC malformed")
    if type(context["deployment_generation"]) is not int or context["deployment_generation"] < 1:
        raise AuditProofError("deployment generation malformed")
    try:
        if not isinstance(context["pod_ip"], str): raise ValueError()
        ipaddress.ip_address(context["pod_ip"])
    except ValueError:
        raise AuditProofError("Pod IP malformed") from None
    start, created, end = (timestamp(context[k]) for k in ("delete_after", "pod_created_at", end_name))
    if not start <= created < end or end - start > 900:
        raise AuditProofError("ceremony window invalid")
    return start, created, end

def _paired(records, start, end):
    if not isinstance(records, list) or not 1 <= len(records) <= 256:
        raise AuditProofError("audit record count invalid")
    try:
        if len(json.dumps(records)) > 1048576: raise ValueError()
    except (TypeError, ValueError):
        raise AuditProofError("audit records malformed or oversized") from None
    pairs = {}
    for row in records:
        if not isinstance(row, dict) or row.get("type") not in ("request", "response"):
            raise AuditProofError("audit type malformed")
        request = row.get("request")
        if not isinstance(request, dict) or not isinstance(request.get("id"), str) or not UID.fullmatch(request["id"]):
            raise AuditProofError("request identity malformed")
        timestamp(row.get("time"))
        pair = pairs.setdefault(request["id"], {})
        previous = pair.get(row["type"])
        if previous is not None and previous != row:
            raise AuditProofError("conflicting duplicate audit entry")
        pair[row["type"]] = row
    valid = []
    for ident, pair in pairs.items():
        if set(pair) != {"request", "response"}: continue
        req, res = pair["request"], pair["response"]
        q, r = req["request"], res["request"]
        if any(q.get(k) != r.get(k) for k in ("path", "operation", "remote_address")):
            raise AuditProofError("request response identity mismatch")
        a, b = timestamp(req["time"]), timestamp(res["time"])
        if start <= a <= b <= end: valid.append((ident, req, res, a, b))
    return valid

def prove(records, context):
    start, created, end = _context(context, "restore_before")
    valid = _paired(records, start, end)
    deleted = [x for x in valid if x[1]["request"].get("path") == PATH and
               x[1]["request"].get("operation") == "delete" and not x[2].get("error")]
    restored = [x for x in valid if x[1]["request"].get("path") == PATH and
                x[1]["request"].get("operation") in ("create", "update") and not x[2].get("error")]
    if len(deleted) != 1 or len(restored) != 1:
        raise AuditProofError("role mutation pairs absent or ambiguous")
    deletion, restoration = deleted[0], restored[0]
    if not deletion[4] <= created < restoration[3]:
        raise AuditProofError("new Pod not between deletion and restoration")
    denied = []
    for item in valid:
        q, r = item[1]["request"], item[2]
        data, reply, error = q.get("data"), r.get("response") or {}, r.get("error")
        if (q.get("path") == "auth/kubernetes/login" and q.get("operation") == "update" and
                q.get("remote_address") == context["pod_ip"] and isinstance(data, dict) and
                data.get("role") == context["role_hmac"] and isinstance(error, str) and
                len(error) <= 512 and error.startswith("invalid role name") and not r.get("auth") and
                isinstance(reply, dict) and not reply.get("auth") and
                created <= item[3] <= item[4] < restoration[3]):
            denied.append(item)
    if not denied: raise AuditProofError("new Pod role-specific denial absent")
    selected = min(denied, key=lambda x: x[3])
    def output(kind, item):
        return {"kind": kind, "request_id_sha256": hashlib.sha256(item[0].encode()).hexdigest(),
                "request_timestamp": item[1]["time"], "response_timestamp": item[2]["time"]}
    return {"result": "PASS_AUDIT_BINDING", "scope": "audit binding only; not continuity or UC-5 completion",
            "pod_uid": context["pod_uid"], "deployment_uid": context["deployment_uid"],
            "deployment_generation": context["deployment_generation"],
            "events": [output(k, x) for k, x in zip(("role_deleted", "fresh_pod_denied", "role_restored"),
                                                    (deletion, selected, restoration))]}


def prove_denial(records, context):
    """Bind deletion to a fresh Pod's denied login before any restoration.

    This deliberately has no restore event: it is safe to call only while the
    fixed runtime role remains absent, then hand its metadata-only result to a
    later full-chain proof.
    """
    start, created, end = _context(context, "observation_before")
    valid = _paired(records, start, end)
    deleted = [item for item in valid if item[1]["request"].get("path") == PATH and
               item[1]["request"].get("operation") == "delete" and not item[2].get("error")]
    if len(deleted) != 1:
        raise AuditProofError("role deletion pair absent or ambiguous")
    deletion = deleted[0]
    if any(item[1]["request"].get("path") == PATH and item[1]["request"].get("operation") in ("create", "update") and not item[2].get("error") for item in valid):
        raise AuditProofError("runtime role restoration observed before denial proof")
    if deletion[4] > created:
        raise AuditProofError("new Pod predates completed role deletion")
    denied = []
    for item in valid:
        request, response = item[1]["request"], item[2]
        data, reply, error = request.get("data"), response.get("response") or {}, response.get("error")
        if (request.get("path") == "auth/kubernetes/login" and request.get("operation") == "update" and
                request.get("remote_address") == context["pod_ip"] and isinstance(data, dict) and
                data.get("role") == context["role_hmac"] and isinstance(error, str) and
                len(error) <= 512 and error.startswith("invalid role name") and not response.get("auth") and
                isinstance(reply, dict) and not reply.get("auth") and created <= item[3] <= item[4] <= end):
            denied.append(item)
    if not denied:
        raise AuditProofError("new Pod role-specific denial absent")
    selected = min(denied, key=lambda item: item[3])
    def output(kind, item):
        return {"kind": kind, "request_id_sha256": hashlib.sha256(item[0].encode()).hexdigest(),
                "request_timestamp": item[1]["time"], "response_timestamp": item[2]["time"]}
    return {"result": "PASS_DENIAL_BINDING", "scope": "denial binding only; before restoration",
            "pod_uid": context["pod_uid"], "deployment_uid": context["deployment_uid"],
            "deployment_generation": context["deployment_generation"],
            "events": [output(kind, item) for kind, item in (("role_deleted", deletion), ("fresh_pod_denied", selected))]}
