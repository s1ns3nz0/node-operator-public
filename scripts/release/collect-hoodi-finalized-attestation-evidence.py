#!/usr/bin/env python3
"""Read immutable validator log archives into observer proof inputs.

This is deliberately a reader.  It invokes only read-only S3 APIs against the
object-locked Firehose archive produced by ``validator-observability.tf``.  It
does not accept activity booleans: qualifying observations require the exact
non-secret Web3Signer ``signing_audit`` record and a separately emitted fence
connection interval from archived log payloads.
"""
from __future__ import annotations

import argparse
import datetime as dt
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
from typing import Any, Callable

KEY = re.compile(r"0x[0-9a-f]{96}\Z")
ROOT = re.compile(r"0x[0-9a-f]{64}\Z")
SHA = re.compile(r"[0-9a-f]{40}\Z")
SET = re.compile(r"hoodi-[a-z0-9][a-z0-9-]*\Z")
NAME = re.compile(r"[a-z][a-z0-9-]{1,18}[a-z0-9]\Z")
UINT = re.compile(r"[0-9]+\Z")
LOG_TOKEN = re.compile(r"[A-Za-z0-9._:-]+\Z")
MAX_OBJECTS, MAX_OBJECT_BYTES = 64, 8 * 1024 * 1024
MAX_LIST_PAGES = 4
MAX_OBJECTS_PER_RUN = MAX_OBJECTS * MAX_LIST_PAGES
MAX_EXPANDED_OBJECT_BYTES = 16 * 1024 * 1024
MAX_LOG_EVENTS_PER_OBJECT = 10_000
MAX_LOG_EVENT_MESSAGE_BYTES = 64 * 1024
MAX_SIGNED_OBSERVATIONS = 256
MAX_FENCE_INTERVALS = 4_096
MAX_ASSIGNMENT_DUTIES = 256
MAX_ASSIGNMENT_SOURCES_PER_DUTY = 8
MAX_FENCE_CLOSE_CLOCK_SKEW_MS = 60_000


class EvidenceError(Exception): pass


class ArchiveUnavailable(EvidenceError): pass


class EvidencePending(EvidenceError): pass


def no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result: raise EvidenceError()
        result[key] = value
    return result


def load(path: Path) -> dict[str, Any]:
    if not path.is_absolute() or path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_OBJECT_BYTES: raise EvidenceError()
    try:
        value = json.loads(path.read_bytes().decode(), object_pairs_hook=no_duplicates)
    except (OSError, UnicodeError, ValueError) as error: raise EvidenceError() from error
    if not isinstance(value, dict): raise EvidenceError()
    return value


def aws(args: list[str], runner: Callable[[list[str]], bytes] | None = None) -> bytes:
    try:
        if runner: return runner(args)
        return subprocess.run(["aws", *args], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=30, check=True).stdout
    except (OSError, subprocess.SubprocessError) as error: raise ArchiveUnavailable() from error


def continuation_token(value: Any) -> str | None:
    if value is None: return None
    if not isinstance(value, str) or not value or len(value) > 4096 or any(character.isspace() or ord(character) < 0x21 or ord(character) > 0x7e for character in value):
        raise EvidenceError()
    return value


def archive_objects(bucket: str, prefix: str, region: str, start_token: str | None = None, runner: Callable[[list[str]], bytes] | None = None) -> tuple[list[dict[str, str]], str | None]:
    token = continuation_token(start_token); seen_tokens: set[str] = set(); result: list[dict[str, str]] = []
    for _ in range(MAX_LIST_PAGES):
        # --max-keys limits the S3 service response, while --no-paginate
        # prevents the AWS CLI from silently following its continuation token.
        command = ["s3api", "list-objects-v2", "--bucket", bucket, "--prefix", prefix, "--region", region, "--output", "json", "--no-cli-pager", "--no-paginate", "--max-keys", str(MAX_OBJECTS)]
        if token is not None: command.extend(["--continuation-token", token])
        raw = aws(command, runner)
        try: value = json.loads(raw.decode(), object_pairs_hook=no_duplicates)
        except (UnicodeError, ValueError) as error: raise EvidenceError() from error
        if not isinstance(value, dict) or set(value) - {"Contents", "IsTruncated", "NextContinuationToken", "KeyCount", "Name", "Prefix", "MaxKeys", "ContinuationToken", "StartAfter", "EncodingType", "Delimiter", "CommonPrefixes"}:
            raise EvidenceError()
        rows = value.get("Contents", [])
        truncated = value.get("IsTruncated", False)
        if not isinstance(rows, list) or len(rows) > MAX_OBJECTS or type(truncated) is not bool:
            raise EvidenceError()
        for row in rows:
            if (not isinstance(row, dict) or not isinstance(row.get("Key"), str) or not row["Key"].startswith(prefix)
                    or type(row.get("Size", 0)) is not int or row.get("Size", 0) < 0):
                raise EvidenceError()
            result.append({"key": row["Key"]})
        if len(result) > MAX_OBJECTS_PER_RUN: raise EvidenceError()
        next_token = continuation_token(value.get("NextContinuationToken"))
        if not truncated:
            if next_token is not None: raise EvidenceError()
            return result, None
        if next_token is None or next_token in seen_tokens or next_token == token:
            raise EvidenceError()
        seen_tokens.add(next_token); token = next_token
    return result, token


def bounded_gzip(path: Path) -> bytes:
    data = bytearray()
    try:
        with gzip.open(path, "rb") as source:
            while True:
                chunk = source.read(min(64 * 1024, MAX_EXPANDED_OBJECT_BYTES + 1 - len(data)))
                if not chunk: break
                data.extend(chunk)
                if len(data) > MAX_EXPANDED_OBJECT_BYTES: raise EvidenceError()
    except (OSError, EOFError) as error:
        raise EvidenceError() from error
    return bytes(data)


def object_payload(bucket: str, key: str, region: str, runner: Callable[[list[str]], bytes] | None = None) -> tuple[dict[str, Any], bytes]:
    with tempfile.NamedTemporaryFile(delete=False) as handle: path = Path(handle.name)
    try:
        raw = aws(["s3api", "head-object", "--bucket", bucket, "--key", key, "--region", region, "--output", "json", "--no-cli-pager"], runner)
        head = json.loads(raw.decode(), object_pairs_hook=no_duplicates)
        if (not isinstance(head, dict) or not isinstance(head.get("VersionId"), str) or not head["VersionId"]
                or not isinstance(head.get("ETag"), str) or type(head.get("ContentLength")) is not int
                or head["ContentLength"] < 0 or head["ContentLength"] > MAX_OBJECT_BYTES): raise EvidenceError()
        aws(["s3api", "get-object", "--bucket", bucket, "--key", key, "--version-id", head["VersionId"], "--region", region, "--no-cli-pager", str(path)], runner)
        payload = path.read_bytes()
        if len(payload) != head["ContentLength"] or len(payload) > MAX_OBJECT_BYTES: raise EvidenceError()
        return {"bucket": bucket, "key": key, "version_id": head["VersionId"], "etag": head["ETag"]}, bounded_gzip(path)
    except (OSError, UnicodeError, ValueError) as error: raise EvidenceError() from error
    finally: path.unlink(missing_ok=True)


def archive_envelopes(decoded: bytes) -> list[dict[str, Any]]:
    """Decode the two gzip layers actually selected by the Firehose IaC.

    CloudWatch subscription records are gzip-compressed and the configured
    Firehose S3 destination applies GZIP again.  Firehose can concatenate
    records, so use JSON raw decoding rather than assuming one envelope.
    """
    for _ in range(2):
        if not decoded.startswith(b"\x1f\x8b"):
            break
        with tempfile.NamedTemporaryFile(delete=False) as handle:
            path = Path(handle.name); handle.write(decoded)
        try:
            decoded = bounded_gzip(path)
        finally:
            path.unlink(missing_ok=True)
    try:
        text_value = decoded.decode()
        decoder = json.JSONDecoder(object_pairs_hook=no_duplicates)
        offset = 0; result: list[dict[str, Any]] = []
        while offset < len(text_value):
            while offset < len(text_value) and text_value[offset].isspace(): offset += 1
            if offset == len(text_value): break
            value, offset = decoder.raw_decode(text_value, offset)
            if not isinstance(value, dict): raise EvidenceError()
            message_type = value.get("messageType")
            if message_type == "CONTROL_MESSAGE": continue
            if message_type != "DATA_MESSAGE" or not isinstance(value.get("logEvents"), list) or len(value["logEvents"]) > MAX_LOG_EVENTS_PER_OBJECT:
                raise EvidenceError()
            result.append(value)
        if not result and text_value.strip(): raise EvidenceError()
        return result
    except (UnicodeError, ValueError) as error:
        raise EvidenceError() from error


def unwrap(message: str) -> tuple[dict[str, str], str] | None:
    """Return Kubernetes labels and the CRI application line from Fluent Bit JSON."""
    try: value: Any = json.loads(message, object_pairs_hook=no_duplicates)
    except ValueError: return None
    for _ in range(3):
        if not isinstance(value, dict): return None
        labels = value.get("kubernetes", {}).get("labels") if isinstance(value.get("kubernetes"), dict) else None
        line = value.get("log")
        if isinstance(labels, dict) and all(isinstance(k, str) and isinstance(v, str) for k, v in labels.items()) and isinstance(line, str):
            return labels, re.sub(r"^\d{4}-\d\d-\d\dT[^ ]+Z\s+(?:stdout|stderr)\s+[FP]\s+", "", line)
        if isinstance(line, str):
            try: value = json.loads(line, object_pairs_hook=no_duplicates)
            except ValueError: return None
        else: return None
    return None


def fields(line: str, event: str) -> dict[str, str] | None:
    if not line.startswith(event + " "): return None
    result: dict[str, str] = {}
    for token in line.split()[1:]:
        if token.count("=") != 1: return None
        key, value = token.split("=", 1)
        if not key or not value or key in result: return None
        result[key] = value
    return result


def fence_interval(value: dict[str, str], event_timestamp: int) -> dict[str, int] | None:
    """Validate one fence-produced, non-TLS connection interval.

    The archived log event is emitted when the interval closes, not when it
    opens. Correlation therefore uses the emitter's UTC bounds; the archive
    timestamp is only a bounded sanity check for that close event.
    """
    required = {"validator_set", "holder", "lease", "connection_id", "opened_at_utc", "closed_at_utc", "opened_at_ms", "closed_at_ms", "result"}
    if set(value) != required or any(not LOG_TOKEN.fullmatch(value[key]) for key in ("validator_set", "holder", "lease", "connection_id", "result")):
        raise EvidenceError()
    if not UINT.fullmatch(value["opened_at_ms"]) or not UINT.fullmatch(value["closed_at_ms"]):
        raise EvidenceError()
    try:
        opened = dt.datetime.fromisoformat(value["opened_at_utc"].replace("Z", "+00:00"))
        closed = dt.datetime.fromisoformat(value["closed_at_utc"].replace("Z", "+00:00"))
    except ValueError as error:
        raise EvidenceError() from error
    if opened.tzinfo != dt.timezone.utc or closed.tzinfo != dt.timezone.utc:
        raise EvidenceError()
    opened_ms, closed_ms = int(value["opened_at_ms"]), int(value["closed_at_ms"])
    if (opened_ms != int(opened.timestamp() * 1000) or closed_ms != int(closed.timestamp() * 1000)
            or closed_ms < opened_ms or abs(event_timestamp - closed_ms) > MAX_FENCE_CLOSE_CLOCK_SKEW_MS):
        raise EvidenceError()
    if value["result"] != "closed":
        return None
    return {"opened_at_ms": opened_ms, "closed_at_ms": closed_ms}


def assignment_rows(path: Path, identity: dict[str, str]) -> dict[tuple[str, str], dict[str, str]]:
    value = load(path)
    try:
        payload = value["payload"]; assignments = payload["assignments"]
        if (value["schema_version"] != 1 or value["event_type"] != "uc-4" or value["network"] != "hoodi"
                or value["source"] != "private-beacon" or value["validator_set"] != identity["validator_set"]
                or value["validator_public_key"] != identity["validator_public_key"] or payload["validator_index"] != identity["validator_index"]
                or payload["observation_status"] != "assignments-observed" or payload["signed_outcomes_observed"] is not False
                or not isinstance(payload["queried_epochs"], list) or len(payload["queried_epochs"]) != 2
                or any(type(epoch) is not int or epoch < 0 for epoch in payload["queried_epochs"])): raise EvidenceError()
    except (KeyError, TypeError): raise EvidenceError()
    result: dict[tuple[str, str], dict[str, str]] = {}
    group_epochs: set[int] = set()
    for group in assignments.values():
        if not isinstance(group, dict) or not isinstance(group.get("epoch"), int) or not isinstance(group.get("attester"), list): raise EvidenceError()
        epoch = str(group["epoch"])
        if group["epoch"] in group_epochs: raise EvidenceError()
        group_epochs.add(group["epoch"])
        for duty in group["attester"]:
            if not isinstance(duty, dict) or set(duty) != {"pubkey", "validator_index", "committee_index", "committee_length", "committees_at_slot", "validator_committee_index", "slot"}: raise EvidenceError()
            if duty["pubkey"] != identity["validator_public_key"] or duty["validator_index"] != identity["validator_index"] or any(not isinstance(duty[x], str) or not UINT.fullmatch(duty[x]) for x in ("committee_index", "slot")): raise EvidenceError()
            if int(duty["slot"]) // 32 != int(epoch) or (epoch, duty["slot"]) in result: raise EvidenceError()
            result[(epoch, duty["slot"])] = {"committee_index": duty["committee_index"]}
    if group_epochs != set(payload["queried_epochs"]): raise EvidenceError()
    return result


def collect(identity: dict[str, str], assignment: Path, bucket: str, prefix: str, region: str, cursor: str | None = None,
            prior_signed: list[dict[str, Any]] | None = None, prior_fences: list[dict[str, Any]] | None = None,
            prior_accepted: list[dict[str, Any]] | None = None, runner: Callable[[list[str]], bytes] | None = None,
            include_state: bool = False, assignments_override: dict[tuple[str, str], dict[str, str]] | None = None) -> Any:
    assignments = assignments_override if assignments_override is not None else assignment_rows(assignment, identity)
    signed: dict[tuple[str, str], dict[str, Any]] = {}
    for row in prior_signed or []:
        if not isinstance(row, dict) or set(row) != {"epoch", "attestation_slot", "committee_index", "signing_root", "signer_event", "archive", "timestamp"}:
            raise EvidenceError()
        key = (row["epoch"], row["attestation_slot"])
        if key not in assignments or row["committee_index"] != assignments[key]["committee_index"] or key in signed:
            raise EvidenceError()
        signed[key] = row
    fences = list(prior_fences or [])
    if len(signed) > MAX_SIGNED_OBSERVATIONS or len(fences) > MAX_FENCE_INTERVALS: raise EvidenceError()
    objects, next_cursor = archive_objects(bucket, prefix, region, cursor, runner)
    for item in objects:
        reference, decoded = object_payload(bucket, item["key"], region, runner)
        for envelope in archive_envelopes(decoded):
          for event in envelope["logEvents"]:
            if not isinstance(event, dict) or not isinstance(event.get("id"), str) or not isinstance(event.get("timestamp"), int) or not isinstance(event.get("message"), str) or len(event["message"].encode()) > MAX_LOG_EVENT_MESSAGE_BYTES: raise EvidenceError()
            parsed = unwrap(event["message"])
            if parsed is None: continue
            labels, line = parsed
            if labels.get("node-operator.io/validator-set") != identity["validator_set"] or labels.get("node-operator.io/deployment-name") != identity["deployment_name"] or labels.get("node-operator.io/release-revision") != identity["release_revision"]: continue
            signing = fields(line, "signing_audit")
            if signing is not None and labels.get("app.kubernetes.io/component") == "validator-remote-signer":
                # Web3Signer deliberately emits this reduced audit record for
                # rejected requests.  It is non-evidence, not malformed
                # success evidence and must not abort later records.
                if set(signing) == {"audit_request_id", "result"} and signing["result"] == "INVALID_REQUEST":
                    continue
                required = {"audit_request_id", "result", "public_key", "artifact_type", "signing_root", "slot", "source_epoch", "target_epoch"}
                if set(signing) != required: raise EvidenceError()
                key = (signing["target_epoch"], signing["slot"])
                if signing["result"] != "SUCCESS" or signing["public_key"] != identity["validator_public_key"] or signing["artifact_type"] != "ATTESTATION" or not ROOT.fullmatch(signing["signing_root"]) or any(not UINT.fullmatch(signing[x]) for x in ("slot", "source_epoch", "target_epoch")) or key not in assignments or int(signing["slot"]) // 32 != int(signing["target_epoch"]): continue
                immutable_event = reference["bucket"] + "/" + reference["key"] + "#" + reference["version_id"] + ":" + event["id"]
                observation = {"epoch": key[0], "attestation_slot": key[1], "committee_index": assignments[key]["committee_index"], "signing_root": signing["signing_root"], "signer_event": {"source": "web3signer-signing-audit", "evidence_id": immutable_event}, "archive": reference, "timestamp": event["timestamp"]}
                if key in signed:
                    if signed[key] != observation: raise EvidenceError()
                    continue  # An unchanged archive page may be read again.
                signed[key] = observation
                if len(signed) > MAX_SIGNED_OBSERVATIONS: raise EvidenceError()
            fence = fields(line, "fence_connection")
            if fence is not None and labels.get("app.kubernetes.io/component") == "validator-signing-fence":
                interval = fence_interval(fence, event["timestamp"])
                if interval is not None:
                    observation = {"fields": fence, "interval": interval, "event_id": event["id"], "timestamp": event["timestamp"], "archive": reference}
                    existing = [row for row in fences if row["archive"] == reference and row["event_id"] == event["id"]]
                    if existing:
                        if len(existing) != 1 or existing[0] != observation: raise EvidenceError()
                        continue
                    fences.append(observation)
                    if len(fences) > MAX_FENCE_INTERVALS: raise EvidenceError()
    accepted: dict[tuple[str, str], tuple[dict[str, Any], dict[str, Any]]] = {}
    if prior_accepted:
        for pair in prior_accepted:
            if not isinstance(pair, dict) or set(pair) != {"workload", "delivery"} or not isinstance(pair["workload"], dict) or not isinstance(pair["delivery"], dict): raise EvidenceError()
            key = (pair["workload"].get("epoch"), pair["workload"].get("attestation_slot"))
            if key not in assignments or pair["delivery"].get("epoch") != key[0] or pair["delivery"].get("attestation_slot") != key[1]: raise EvidenceError()
            accepted[key] = (pair["workload"], pair["delivery"])
    workload, deliveries = [], []
    for key, row in sorted(signed.items(), key=lambda pair: tuple(map(int, pair[0]))):
        # A fence record is intentionally a temporal lease-path correlation, never a TLS inspection claim.
        matching = [event for event in fences if event["fields"]["validator_set"] == identity["validator_set"] and event["interval"]["opened_at_ms"] <= row["timestamp"] <= event["interval"]["closed_at_ms"]]
        if len(matching) != 1: continue
        fence = matching[0]
        fence_ref = fence["archive"]["bucket"] + "/" + fence["archive"]["key"] + "#" + fence["archive"]["version_id"] + ":" + fence["event_id"]
        work = {k: row[k] for k in ("epoch", "attestation_slot", "committee_index", "signing_root", "signer_event")} | {"fence_interval": {"source": "signing-fence-lease-interval", "evidence_id": fence_ref}}
        delivery = {"epoch": row["epoch"], "attestation_slot": row["attestation_slot"], "delivery_observed": True, "delivery_source": "s3-object-lock-firehose", "delivery_evidence_id": row["archive"]["bucket"] + "/" + row["archive"]["key"] + "#" + row["archive"]["version_id"]}
        accepted[key] = (work, delivery)
    # Preserve only current-assignment identities and hard-cap every retained
    # class.  This permits cross-page correlation without carrying evidence
    # into another selected release/assignment.
    paired = [{"workload": work, "delivery": delivery} for _, (work, delivery) in sorted(accepted.items(), key=lambda item: tuple(map(int, item[0])))]
    if len(paired) > MAX_SIGNED_OBSERVATIONS: raise EvidenceError()
    for pair in paired:
        workload.append(pair["workload"]); deliveries.append(pair["delivery"])
    matched_keys = set(accepted)
    retained_signed = [row for key, row in signed.items() if key not in matched_keys]
    retained_fences = fences[-MAX_FENCE_INTERVALS:]
    retained = {"signed": retained_signed, "fences": retained_fences, "accepted": paired}
    return (workload, deliveries, next_cursor, retained) if include_state else (workload, deliveries, next_cursor)


def secure_parent(path: Path, create: bool = False) -> None:
    if not path.is_absolute() or path.is_symlink(): raise EvidenceError()
    if create: path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if not path.parent.is_dir() or path.parent.is_symlink(): raise EvidenceError()
    info = path.parent.lstat()
    if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700: raise EvidenceError()


def write(path: Path, value: dict[str, Any]) -> None:
    """Atomically refresh a fixed proof path in an owner-only directory."""
    secure_parent(path, create=True)
    if path.exists():
        info = path.lstat()
        if not path.is_file() or path.is_symlink() or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600: raise EvidenceError()
    temp: Path | None = None
    try:
        with tempfile.NamedTemporaryFile("w", dir=path.parent, delete=False) as handle:
            json.dump(value, handle, sort_keys=True, separators=(",", ":")); handle.write("\n"); handle.flush(); os.fsync(handle.fileno()); temp = Path(handle.name)
        temp.chmod(0o600); os.replace(temp, path)
    finally:
        if temp is not None: temp.unlink(missing_ok=True)


def assignment_source(path: Path, identity: dict[str, str]) -> tuple[dict[tuple[str, str], dict[str, str]], dict[str, str]]:
    rows = assignment_rows(path, identity)
    if not path.is_absolute() or path.is_symlink() or not path.is_file(): raise EvidenceError()
    return rows, {"path": str(path.resolve()), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}


def ledger_key(key: tuple[str, str]) -> str:
    return key[0] + ":" + key[1]


def ledger_rows(ledger: dict[str, Any]) -> dict[tuple[str, str], dict[str, str]]:
    if not isinstance(ledger, dict) or len(ledger) > MAX_ASSIGNMENT_DUTIES: raise EvidenceError()
    rows: dict[tuple[str, str], dict[str, str]] = {}
    for encoded, entry in ledger.items():
        if not isinstance(encoded, str) or encoded.count(":") != 1: raise EvidenceError()
        epoch, slot = encoded.split(":")
        if not UINT.fullmatch(epoch) or not UINT.fullmatch(slot) or int(slot) // 32 != int(epoch): raise EvidenceError()
        if not isinstance(entry, dict) or set(entry) != {"committee_index", "sources"} or not isinstance(entry["committee_index"], str) or not UINT.fullmatch(entry["committee_index"]) or not isinstance(entry["sources"], list) or not 1 <= len(entry["sources"]) <= MAX_ASSIGNMENT_SOURCES_PER_DUTY: raise EvidenceError()
        seen: set[tuple[str, str]] = set()
        for source in entry["sources"]:
            if not isinstance(source, dict) or set(source) != {"path", "sha256"} or not isinstance(source["path"], str) or not source["path"].startswith("/") or not re.fullmatch(r"[0-9a-f]{64}", source["sha256"]): raise EvidenceError()
            pair = (source["path"], source["sha256"])
            if pair in seen: raise EvidenceError()
            seen.add(pair)
        rows[(epoch, slot)] = {"committee_index": entry["committee_index"]}
    return rows


def merge_assignment_ledger(ledger: dict[str, Any], snapshot: dict[tuple[str, str], dict[str, str]], source: dict[str, str], activation_slot: str) -> dict[str, Any]:
    rows = ledger_rows(ledger)
    if not UINT.fullmatch(activation_slot): raise EvidenceError()
    activation_epoch = int(activation_slot) // 32
    for key, duty in snapshot.items():
        if int(key[0]) < activation_epoch: raise EvidenceError()
        encoded = ledger_key(key)
        existing = ledger.get(encoded)
        if existing is None:
            if len(ledger) >= MAX_ASSIGNMENT_DUTIES: raise EvidencePending()
            ledger[encoded] = {"committee_index": duty["committee_index"], "sources": [source]}
        elif existing["committee_index"] != duty["committee_index"]:
            raise EvidenceError()
        elif source not in existing["sources"]:
            if len(existing["sources"]) >= MAX_ASSIGNMENT_SOURCES_PER_DUTY: raise EvidencePending()
            existing["sources"].append(source)
    return ledger


def validate_retained(state: dict[str, Any], identity: dict[str, str], assignments: dict[tuple[str, str], dict[str, str]]) -> None:
    for row in state["signed"]:
        if not isinstance(row, dict) or set(row) != {"epoch", "attestation_slot", "committee_index", "signing_root", "signer_event", "archive", "timestamp"}:
            raise EvidenceError()
        key = (row["epoch"], row["attestation_slot"])
        archive = row["archive"]; signer = row["signer_event"]
        if (key not in assignments or row["committee_index"] != assignments[key]["committee_index"] or not ROOT.fullmatch(row["signing_root"])
                or not isinstance(row["timestamp"], int) or not isinstance(archive, dict) or set(archive) != {"bucket", "key", "version_id", "etag"}
                or not all(isinstance(archive[k], str) and archive[k] for k in archive) or not isinstance(signer, dict)
                or signer.get("source") != "web3signer-signing-audit" or not isinstance(signer.get("evidence_id"), str) or not signer["evidence_id"]):
            raise EvidenceError()
    for row in state["fences"]:
        if not isinstance(row, dict) or set(row) != {"fields", "interval", "event_id", "timestamp", "archive"} or not isinstance(row["fields"], dict) or not isinstance(row["timestamp"], int) or not isinstance(row["event_id"], str): raise EvidenceError()
        interval = fence_interval(row["fields"], row["timestamp"])
        if interval is None or interval != row["interval"] or row["fields"]["validator_set"] != identity["validator_set"]: raise EvidenceError()
    for pair in state["accepted"]:
        if not isinstance(pair, dict) or set(pair) != {"workload", "delivery"} or not isinstance(pair["workload"], dict) or not isinstance(pair["delivery"], dict): raise EvidenceError()
        work, delivery = pair["workload"], pair["delivery"]
        key = (work.get("epoch"), work.get("attestation_slot"))
        if (key not in assignments or work.get("committee_index") != assignments[key]["committee_index"] or delivery.get("epoch") != key[0]
                or delivery.get("attestation_slot") != key[1] or work.get("signer_event", {}).get("source") != "web3signer-signing-audit"
                or work.get("fence_interval", {}).get("source") != "signing-fence-lease-interval" or delivery.get("delivery_source") != "s3-object-lock-firehose"
                or delivery.get("delivery_observed") is not True): raise EvidenceError()


def read_cursor(path: Path, bucket: str, prefix: str, region: str, identity: dict[str, str]) -> dict[str, Any]:
    secure_parent(path)
    if not path.exists(): return {"continuation_token": None, "assignment_ledger": {}, "signed": [], "fences": [], "accepted": []}
    info = path.lstat()
    if not path.is_file() or stat.S_IMODE(info.st_mode) != 0o600 or info.st_uid != os.geteuid(): raise EvidenceError()
    value = load(path)
    expected = {"schema_version", "bucket", "prefix", "region", "identity", "continuation_token", "assignment_ledger", "signed", "fences", "accepted"}
    if (set(value) != expected or value["schema_version"] != 3 or value["bucket"] != bucket or value["prefix"] != prefix or value["region"] != region
            or value["identity"] != identity or not isinstance(value["assignment_ledger"], dict) or not isinstance(value["signed"], list)
            or not isinstance(value["fences"], list) or not isinstance(value["accepted"], list)):
        raise EvidenceError()
    value["continuation_token"] = continuation_token(value["continuation_token"])
    if len(value["signed"]) > MAX_SIGNED_OBSERVATIONS or len(value["fences"]) > MAX_FENCE_INTERVALS or len(value["accepted"]) > MAX_SIGNED_OBSERVATIONS: raise EvidenceError()
    assignments = ledger_rows(value["assignment_ledger"])
    validate_retained(value, identity, assignments)
    return value


def write_cursor(path: Path, bucket: str, prefix: str, region: str, identity: dict[str, str], state: dict[str, Any]) -> None:
    secure_parent(path)
    parent = path.parent
    if path.exists():
        info = path.lstat()
        if not path.is_file() or stat.S_IMODE(info.st_mode) != 0o600 or info.st_uid != os.geteuid(): raise EvidenceError()
    if set(state) != {"continuation_token", "assignment_ledger", "signed", "fences", "accepted"}: raise EvidenceError()
    assignments = ledger_rows(state["assignment_ledger"])
    validate_retained(state, identity, assignments)
    value = {"schema_version": 3, "bucket": bucket, "prefix": prefix, "region": region, "identity": identity, **state}
    with tempfile.NamedTemporaryFile("w", dir=parent, delete=False) as handle:
        json.dump(value, handle, sort_keys=True, separators=(",", ":")); handle.write("\n"); handle.flush(); os.fsync(handle.fileno()); temporary = Path(handle.name)
    try:
        temporary.chmod(0o600); os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def main(argv: list[str] | None = None, runner: Callable[[list[str]], bytes] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--assignment-proof", required=True); parser.add_argument("--archive-bucket", required=True); parser.add_argument("--archive-prefix", default="validator/"); parser.add_argument("--aws-region", required=True)
    parser.add_argument("--validator-set", required=True); parser.add_argument("--validator-public-key", required=True); parser.add_argument("--validator-index", required=True); parser.add_argument("--deployment-name", required=True); parser.add_argument("--release-revision", required=True); parser.add_argument("--activation-slot", required=True)
    parser.add_argument("--workload-output", required=True); parser.add_argument("--log-delivery-output", required=True); parser.add_argument("--archive-cursor", required=True)
    args = parser.parse_args(argv)
    try:
        identity = {"validator_set": args.validator_set, "validator_public_key": args.validator_public_key.lower(), "validator_index": args.validator_index, "deployment_name": args.deployment_name, "release_revision": args.release_revision}
        if not SET.fullmatch(identity["validator_set"]) or not KEY.fullmatch(identity["validator_public_key"]) or not UINT.fullmatch(identity["validator_index"]) or not NAME.fullmatch(identity["deployment_name"]) or not SHA.fullmatch(identity["release_revision"]) or not UINT.fullmatch(args.activation_slot) or not re.fullmatch(r"[a-z]{2}-[a-z0-9-]+-[0-9]+", args.aws_region) or not re.fullmatch(r"[a-z0-9][a-z0-9.-]{2,62}", args.archive_bucket) or not args.archive_prefix.startswith("validator/") or ".." in args.archive_prefix:
            raise EvidenceError()
        workload_path, delivery_path, cursor_path = Path(args.workload_output), Path(args.log_delivery_output), Path(args.archive_cursor)
        if workload_path == delivery_path or cursor_path in (workload_path, delivery_path):
            raise EvidenceError()
        assignment_path = Path(args.assignment_proof)
        cursor_identity = identity | {"activation_slot": args.activation_slot}
        state = read_cursor(cursor_path, args.archive_bucket, args.archive_prefix, args.aws_region, cursor_identity)
        snapshot, source = assignment_source(assignment_path, identity)
        ledger = merge_assignment_ledger(state["assignment_ledger"], snapshot, source, args.activation_slot)
        assignments = ledger_rows(ledger)
        validate_retained(state, identity, assignments)
        workload, deliveries, next_cursor, retained = collect(identity, assignment_path, args.archive_bucket, args.archive_prefix, args.aws_region,
                                                               state["continuation_token"], state["signed"], state["fences"], state["accepted"], runner, True, assignments)
        common = {"schema_version": 1, "network": "hoodi", **identity}
        write(workload_path, {**common, "event_type": "validator-attestation-workload-proof", "observations": workload})
        write(delivery_path, {**common, "event_type": "validator-log-delivery-proof", "observations": deliveries})
        write_cursor(cursor_path, args.archive_bucket, args.archive_prefix, args.aws_region, cursor_identity,
                     {"continuation_token": next_cursor, "assignment_ledger": ledger, **retained})
        # A collector pass without a real archived signer/fence correlation is
        # intentionally pending, never a success signal for activation.
        if not workload:
            print("PENDING: no qualifying delivered signer/fence interval was found", file=os.sys.stderr)
            return 75
        return 0
    except ArchiveUnavailable:
        print("finalized-attestation archive is unavailable; no observation was accepted", file=os.sys.stderr); return 70
    except EvidencePending:
        print("PENDING: finalized-attestation evidence retention limit reached; no records were discarded", file=os.sys.stderr); return 75
    except (EvidenceError, OSError, ValueError):
        print("finalized-attestation evidence collection failed", file=os.sys.stderr); return 65


if __name__ == "__main__": raise SystemExit(main())
