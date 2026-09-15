#!/usr/bin/env python3
"""Bounded, metadata-only delivery checks through an identity-pinned reader Pod.

This never exports or persists CloudWatch message bodies or S3 object bytes
outside the reader Pod. A successful result only says that every configured
operational route has a fresh metadata record; it is not a Vault, workload,
archive-payload, or installer-completion proof.
"""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from typing import Any

MAX_SOURCES = 32
MAX_PAGES = 4
MAX_TOKEN = 4096
ACCOUNT = re.compile(r"[0-9]{12}\Z")
REGION = re.compile(r"[a-z]{2}-[a-z0-9-]+-[0-9]+\Z")
DEPLOYMENT = re.compile(r"[a-z][a-z0-9-]{1,38}[a-z0-9]\Z")
IDENTIFIER = re.compile(r"[a-z][a-z0-9-]{0,62}\Z")
BUCKET = re.compile(r"[a-z0-9][a-z0-9.-]{2,62}\Z")
SAFE_PREFIX = re.compile(r"[A-Za-z0-9!_.*'()/-]{0,1024}\Z")
SAFE_TEXT = re.compile(r"[^\x00-\x1f\x7f]{1,4096}\Z")

# JMESPath returns null for a projection over a missing field.  Normalize it
# to an empty list so a valid empty page can advance its continuation token.
CW_QUERY = "{events:events[].{event_id:eventId,timestamp:timestamp,ingestion_time:ingestionTime,stream:logStreamName} || `[]`,next_token:nextToken}"
S3_QUERY = "{objects:Contents[].{key:Key,last_modified:LastModified,size:Size} || `[]`,truncated:IsTruncated,next_token:NextContinuationToken}"


class DeliveryError(ValueError):
    """The local delivery contract is unsafe or internally inconsistent."""


def _duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DeliveryError("duplicate JSON key")
        result[key] = value
    return result


def _token(value: Any) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not SAFE_TEXT.fullmatch(value) or len(value) > MAX_TOKEN:
        raise DeliveryError("invalid continuation token")
    return value


def _timestamp(value: Any) -> int:
    if type(value) is not int or value < 0:
        raise DeliveryError("invalid timestamp")
    return value


def _last_modified_ms(value: Any) -> int:
    if not isinstance(value, str) or len(value) > 64:
        raise DeliveryError("invalid object timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise DeliveryError("invalid object timestamp") from error
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise DeliveryError("invalid object timestamp")
    return int(parsed.timestamp() * 1000)


def _scope(contract: dict[str, Any], since_ms: int) -> str:
    encoded = json.dumps({"contract": contract, "since_ms": since_ms}, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def validate_contract(contract: Any) -> dict[str, Any]:
    """Return a normalized contract, or reject an unscoped metadata route."""
    if not isinstance(contract, dict) or set(contract) != {"schema_version", "account_id", "region", "deployment_name", "manage_config_recorder", "cloudwatch", "s3"}:
        raise DeliveryError("invalid delivery contract")
    if (type(contract["schema_version"]) is not int or contract["schema_version"] != 1
            or not isinstance(contract["account_id"], str) or not ACCOUNT.fullmatch(contract["account_id"])
            or not isinstance(contract["region"], str) or not REGION.fullmatch(contract["region"])
            or not isinstance(contract["deployment_name"], str) or not DEPLOYMENT.fullmatch(contract["deployment_name"])
            or type(contract["manage_config_recorder"]) is not bool
            or not isinstance(contract["cloudwatch"], list) or not isinstance(contract["s3"], list)
            or len(contract["cloudwatch"]) > MAX_SOURCES or len(contract["s3"]) > MAX_SOURCES):
        raise DeliveryError("invalid delivery contract")
    deployment = contract["deployment_name"]
    expected_routes = {
        "vpc-flow-logs": (f"/aws/vpc/{deployment}-baseline/flow-logs", ""),
        "eks-api": (f"/aws/eks/{deployment}/cluster", "kube-apiserver-"),
        "eks-audit": (f"/aws/eks/{deployment}/cluster", "kube-apiserver-audit-"),
        "eks-authenticator": (f"/aws/eks/{deployment}/cluster", "authenticator-"),
        "eks-controller-manager": (f"/aws/eks/{deployment}/cluster", "kube-controller-manager-"),
        "eks-scheduler": (f"/aws/eks/{deployment}/cluster", "kube-scheduler-"),
        "cloudtrail-cloudwatch": (f"/aws/cloudtrail/{deployment}-baseline-audit", ""),
        "validator-workloads": (f"/aws/eks/{deployment}/validator-workloads", "fluent-bit-"),
        "vault-security-cloudwatch": (f"/aws/eks/{deployment}/validator-security", "fluent-bit-"),
    }
    ids: set[str] = set()
    routes: set[tuple[str, str]] = set()
    cloudwatch: list[dict[str, str]] = []
    for source in contract["cloudwatch"]:
        if not isinstance(source, dict) or set(source) != {"id", "group", "stream_prefix"}:
            raise DeliveryError("invalid CloudWatch route")
        source_id, group, prefix = source["id"], source["group"], source["stream_prefix"]
        if (not isinstance(source_id, str) or not isinstance(group, str) or not isinstance(prefix, str)
                or not IDENTIFIER.fullmatch(source_id) or source_id in ids
                or not SAFE_PREFIX.fullmatch(prefix) or (group, prefix) in routes
                or expected_routes.get(source_id) != (group, prefix)):
            raise DeliveryError("invalid CloudWatch route")
        ids.add(source_id); routes.add((group, prefix))
        cloudwatch.append({"id": source_id, "group": group, "stream_prefix": prefix})
    if ids != set(expected_routes):
        raise DeliveryError("incomplete CloudWatch route inventory")
    buckets: set[tuple[str, str, str]] = set()
    s3: list[dict[str, str]] = []
    expected_s3 = {
        "validator-archive": ("validator/", False),
        "cloudtrail-s3": (f"AWSLogs/{contract['account_id']}/CloudTrail/{contract['region']}/", False),
        "audit-access-audit": ("audit/", False),
        "audit-access-validator-audit": ("validator-audit/", False),
        "audit-access-vault-snapshot": ("vault-snapshot/", False),
        "cloudtrail-replica": (f"AWSLogs/{contract['account_id']}/CloudTrail/{contract['region']}/", True),
        "audit-replica-access-audit": ("audit/", True),
        "audit-replica-access-validator-audit": ("validator-audit/", True),
        "audit-replica-access-vault-snapshot": ("vault-snapshot/", True),
    }
    if contract["manage_config_recorder"]:
        expected_s3 |= {
            "config": (f"AWSLogs/{contract['account_id']}/Config/", False),
            "config-replica": (f"AWSLogs/{contract['account_id']}/Config/", True),
        }
    s3_by_id: dict[str, dict[str, str]] = {}
    for source in contract["s3"]:
        if not isinstance(source, dict) or set(source) != {"id", "bucket", "prefix", "region"}:
            raise DeliveryError("invalid S3 route")
        source_id, bucket, prefix, region = source["id"], source["bucket"], source["prefix"], source["region"]
        if (not isinstance(source_id, str) or not isinstance(bucket, str) or not isinstance(prefix, str) or not isinstance(region, str)
                or not IDENTIFIER.fullmatch(source_id) or source_id in ids or not BUCKET.fullmatch(bucket)
                or not SAFE_PREFIX.fullmatch(prefix) or not prefix.endswith("/") or not REGION.fullmatch(region)):
            raise DeliveryError("invalid S3 route")
        expected = expected_s3.get(source_id)
        if expected is None or expected[0] != prefix:
            raise DeliveryError("invalid S3 route")
        identity = (bucket, prefix, region)
        if identity in buckets:
            raise DeliveryError("invalid S3 route")
        ids.add(source_id); buckets.add(identity)
        s3.append({"id": source_id, "bucket": bucket, "prefix": prefix, "region": region})
        s3_by_id[source_id] = s3[-1]
    if set(s3_by_id) != set(expected_s3):
        raise DeliveryError("incomplete S3 route inventory")
    replica_regions = {s3_by_id[source_id]["region"] for source_id, (_, replica) in expected_s3.items() if replica}
    primary_regions = {s3_by_id[source_id]["region"] for source_id, (_, replica) in expected_s3.items() if not replica}
    if primary_regions != {contract["region"]} or len(replica_regions) != 1 or contract["region"] in replica_regions:
        raise DeliveryError("inconsistent S3 route regions")
    return {"schema_version": 1, "account_id": contract["account_id"], "region": contract["region"],
            "deployment_name": contract["deployment_name"], "manage_config_recorder": contract["manage_config_recorder"],
            "cloudwatch": cloudwatch, "s3": s3}


def _response(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, bytes) or len(raw) > 1024 * 1024:
        raise DeliveryError("invalid reader response")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise DeliveryError("invalid reader response") from error
    if not isinstance(value, dict):
        raise DeliveryError("invalid reader response")
    return value


def _cursor(cursor: Any, scope: str, cloudwatch_ids: set[str], s3_ids: set[str], since_ms: int, now_ms: int) -> dict[str, dict[str, Any]]:
    empty = {"cloudwatch": {}, "s3": {}}
    if cursor is None:
        return empty
    if not isinstance(cursor, dict) or set(cursor) != {"schema_version", "scope", "cloudwatch", "s3"}:
        raise DeliveryError("invalid delivery cursor")
    if type(cursor["schema_version"]) is not int or cursor["schema_version"] != 1 or cursor["scope"] != scope:
        raise DeliveryError("invalid delivery cursor")
    result: dict[str, dict[str, Any]] = {"cloudwatch": {}, "s3": {}}
    rows = cursor["cloudwatch"]
    if not isinstance(rows, dict) or any(not isinstance(key, str) or key not in cloudwatch_ids for key in rows):
        raise DeliveryError("invalid delivery cursor")
    for source_id, item in rows.items():
        if not isinstance(item, dict) or set(item) != {"token", "end_time"}:
            raise DeliveryError("invalid delivery cursor")
        token, end_time = _token(item["token"]), item["end_time"]
        if token is None or type(end_time) is not int or not since_ms <= end_time <= now_ms:
            raise DeliveryError("invalid delivery cursor")
        result["cloudwatch"][source_id] = {"token": token, "end_time": end_time}
    rows = cursor["s3"]
    if not isinstance(rows, dict) or any(not isinstance(key, str) or key not in s3_ids for key in rows):
        raise DeliveryError("invalid delivery cursor")
    for source_id, token in rows.items():
        value = _token(token)
        if value is None:
            raise DeliveryError("invalid delivery cursor")
        result["s3"][source_id] = value
    return result


def _cw_command(source: dict[str, str], region: str, since_ms: int, now_ms: int, token: str | None) -> list[str]:
    request: dict[str, Any] = {"logGroupName": source["group"], "startTime": since_ms, "endTime": now_ms, "limit": 1}
    if source["stream_prefix"]:
        request["logStreamNamePrefix"] = source["stream_prefix"]
    if token is not None:
        request["nextToken"] = token
    return ["aws", "logs", "filter-log-events", "--region", region, "--cli-input-json",
            json.dumps(request, separators=(",", ":"), sort_keys=True), "--no-paginate", "--no-cli-pager",
            "--output", "json", "--query", CW_QUERY]


def _s3_command(source: dict[str, str], token: str | None) -> list[str]:
    command = ["aws", "s3api", "list-objects-v2", "--bucket", source["bucket"], "--prefix", source["prefix"],
               "--region", source["region"], "--no-paginate", "--no-cli-pager", "--output", "json",
               "--max-keys", "64", "--query", S3_QUERY]
    if token is not None:
        command.extend(["--continuation-token", token])
    return command


def _cloudwatch(source: dict[str, str], region: str, since_ms: int, now_ms: int, start: dict[str, Any] | None, transport: Any) -> tuple[dict[str, Any] | None, dict[str, Any] | None, str | None]:
    """Freshness is inclusive event timestamp membership in ``[since, now]``.

    Ingestion time is retained as metadata and must not be in the future, but
    it is deliberately not substituted for the event's own timestamp.
    """
    token = start["token"] if start is not None else None
    end_time = start["end_time"] if start is not None else now_ms
    seen = set()
    for _ in range(MAX_PAGES):
        try:
            value = _response(transport._exec(_cw_command(source, region, since_ms, end_time, token)))
            if set(value) != {"events", "next_token"} or not isinstance(value["events"], list) or len(value["events"]) > 1:
                raise DeliveryError("invalid CloudWatch response")
            for event in value["events"]:
                if (not isinstance(event, dict) or set(event) != {"event_id", "timestamp", "ingestion_time", "stream"}
                        or not isinstance(event["event_id"], str) or not SAFE_TEXT.fullmatch(event["event_id"])
                        or not isinstance(event["stream"], str) or not SAFE_TEXT.fullmatch(event["stream"])
                        or not event["stream"].startswith(source["stream_prefix"])):
                    raise DeliveryError("invalid CloudWatch response")
                timestamp, ingestion = _timestamp(event["timestamp"]), _timestamp(event["ingestion_time"])
                if ingestion > end_time:
                    raise DeliveryError("invalid CloudWatch response")
                # EKS writes audit and API logs to overlapping stream namespaces.
                # The designated API route must not let an audit stream satisfy it.
                if (source["id"] == "eks-api" and event["stream"].startswith("kube-apiserver-audit-")):
                    continue
                if since_ms <= timestamp <= end_time:
                    return {"id": source["id"], "kind": "cloudwatch", "event_id": event["event_id"], "stream": event["stream"], "timestamp": timestamp, "ingestion_time": ingestion}, None, None
            next_token = _token(value["next_token"])
            if next_token is None:
                return None, None, "no-fresh-metadata"
            if next_token == token or next_token in seen:
                return None, None, "pagination-invalid"
            seen.add(next_token); token = next_token
        except Exception:
            return None, None, "metadata-unavailable"
    return None, {"token": token, "end_time": end_time}, "page-bound-reached"


def _s3(source: dict[str, str], since_ms: int, now_ms: int, start: str | None, transport: Any) -> tuple[dict[str, Any] | None, str | None, str | None]:
    token, seen = start, set()
    for _ in range(MAX_PAGES):
        try:
            value = _response(transport._exec(_s3_command(source, token)))
            if set(value) != {"objects", "truncated", "next_token"} or not isinstance(value["objects"], list) or len(value["objects"]) > 64 or type(value["truncated"]) is not bool:
                raise DeliveryError("invalid S3 response")
            for item in value["objects"]:
                if (not isinstance(item, dict) or set(item) != {"key", "last_modified", "size"}
                        or not isinstance(item["key"], str) or not item["key"].startswith(source["prefix"])
                        or type(item["size"]) is not int or item["size"] <= 0):
                    raise DeliveryError("invalid S3 response")
                modified = _last_modified_ms(item["last_modified"])
                if since_ms <= modified <= now_ms:
                    return {"id": source["id"], "kind": "s3", "key": item["key"], "last_modified_ms": modified, "size": item["size"]}, None, None
            next_token = _token(value["next_token"])
            if not value["truncated"]:
                if next_token is not None:
                    raise DeliveryError("invalid S3 response")
                return None, None, "no-fresh-metadata"
            if next_token is None or next_token == token or next_token in seen:
                return None, None, "pagination-invalid"
            seen.add(next_token); token = next_token
        except Exception:
            return None, None, "metadata-unavailable"
    return None, token, "page-bound-reached"


def verify(contract: Any, since_ms: Any, now_ms: Any, transport: Any, cursor: Any = None) -> dict[str, Any]:
    """Verify only fresh CloudWatch/S3 metadata through a pinned transport.

    ``cursor`` is a scope-bound continuation hint, never accepted proof: each
    call re-queries a source before returning its fresh metadata. A malformed
    or scope-mismatched cursor is discarded and forces a non-passing result.
    """
    normalized = validate_contract(contract)
    since, now = _timestamp(since_ms), _timestamp(now_ms)
    if since > now or not callable(getattr(transport, "_exec", None)):
        raise DeliveryError("invalid delivery verification inputs")
    scope = _scope(normalized, since)
    cloudwatch_ids = {source["id"] for source in normalized["cloudwatch"]}
    s3_ids = {source["id"] for source in normalized["s3"]}
    all_ids = cloudwatch_ids | s3_ids
    try:
        prior = _cursor(cursor, scope, cloudwatch_ids, s3_ids, since, now)
    except DeliveryError:
        prior = {"cloudwatch": {}, "s3": {}}
        cursor_invalid = True
    else:
        cursor_invalid = False
    proofs, pending, next_cursor = [], [], {"schema_version": 1, "scope": scope, "cloudwatch": {}, "s3": {}}
    if not all_ids:
        pending.append({"id": "no-configured-routes", "reason": "no-operational-metadata-routes"})
    for source in normalized["cloudwatch"]:
        proof, token, reason = _cloudwatch(source, normalized["region"], since, now, prior["cloudwatch"].get(source["id"]), transport)
        if proof is not None: proofs.append(proof)
        else:
            pending.append({"id": source["id"], "reason": reason or "metadata-unavailable"})
            if token is not None: next_cursor["cloudwatch"][source["id"]] = token
    for source in normalized["s3"]:
        proof, token, reason = _s3(source, since, now, prior["s3"].get(source["id"]), transport)
        if proof is not None: proofs.append(proof)
        else:
            pending.append({"id": source["id"], "reason": reason or "metadata-unavailable"})
            if token is not None: next_cursor["s3"][source["id"]] = token
    if cursor_invalid:
        pending.append({"id": "cursor", "reason": "cursor-invalid"})
    return {"schema_version": 1, "result": "PASS_OPERATIONAL_METADATA" if not pending else "PENDING",
            "since_ms": since, "now_ms": now, "proofs": proofs,
            "pending_ids": [item["id"] for item in pending], "pending": pending, "cursor": next_cursor}
