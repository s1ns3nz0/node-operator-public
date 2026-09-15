#!/usr/bin/env python3
"""Bounded in-memory CloudWatch reader for the fixed Vault audit relay.

It never writes or prints audit messages.  Returned records are intended only
for immediate consumption by ``uc5-audit-proof.py``.
"""
import calendar
import datetime as dt
from decimal import Decimal
import json
import re
import os
import selectors
import subprocess
import time

GROUP = "/aws/eks/node-operator/validator-security"
REGION = "ap-northeast-2"
MAX_WINDOW_SECONDS = 900
MAX_PAGES = 8
MAX_EVENTS = 256
MAX_EVENT_BYTES = 16384
MAX_TOTAL_BYTES = 1048576
CRI = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z\s+(?:stdout|stderr)\s+[FP]\s+(.*)$")
STAMP = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z$")


class AuditReaderError(RuntimeError):
    pass


def _epoch(value):
    if not isinstance(value, str) or STAMP.fullmatch(value) is None:
        raise AuditReaderError("audit reader window timestamp is malformed")
    try:
        whole, _, fraction = value[:-1].partition(".")
        seconds = calendar.timegm(dt.datetime.strptime(whole, "%Y-%m-%dT%H:%M:%S").timetuple())
        return Decimal(seconds) + (Decimal("0." + fraction) if fraction else 0)
    except ValueError as error:
        raise AuditReaderError("audit reader window timestamp is malformed") from error


def _default_runner(args):
    process = None
    try:
        process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        deadline, raw = time.monotonic() + 30, bytearray()
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not selector.select(remaining):
                    raise AuditReaderError("audit reader request timed out")
                chunk = os.read(process.stdout.fileno(), 16384)
                if not chunk: break
                raw.extend(chunk)
                if len(raw) > MAX_TOTAL_BYTES:
                    raise AuditReaderError("audit reader response exceeds limit")
        if process.wait(timeout=max(0.01, deadline - time.monotonic())):
            raise AuditReaderError("audit reader request failed")
        return raw.decode("utf-8")
    except (OSError, UnicodeError, subprocess.TimeoutExpired):
        raise AuditReaderError("audit reader request failed") from None
    finally:
        if process is not None:
            if process.poll() is None: process.kill()
            process.wait()
            if process.stdout is not None: process.stdout.close()


def _decode(message):
    if not isinstance(message, str) or len(message.encode("utf-8")) > MAX_EVENT_BYTES:
        raise AuditReaderError("audit reader event is malformed or oversized")
    # Fluent/CRI relays can wrap JSON strings in one or two {log: ...} layers.
    # Parse a structured Fluent Bit envelope before interpreting its ``log``
    # field as CRI.  A compact outer JSON object may otherwise put ``stdout F``
    # after its first whitespace and be mistaken for a CRI prefix.
    payload, source = message, None
    for _ in range(3):
        try:
            value = json.loads(payload)
        except json.JSONDecodeError:
            stripped = CRI.sub(r"\1", payload)
            if stripped == payload:
                return None
            try:
                value = json.loads(stripped)
            except json.JSONDecodeError:
                return None
        if not isinstance(value, dict):
            return None
        if "schema_version" in value or "audit_source" in value:
            if (set(value) != {"schema_version", "audit_source", "log"} or
                    type(value["schema_version"]) is not int or value["schema_version"] != 1 or
                    value["audit_source"] not in ("socket", "file") or
                    not isinstance(value["log"], str) or source is not None):
                raise AuditReaderError("audit reader relay envelope is malformed")
            # The file and socket devices can emit the same request ID with
            # different device HMACs. UC5 binds only the socket device.
            if value["audit_source"] != "socket":
                return None
            source, payload = "socket", value["log"]
            continue
        if isinstance(value.get("log"), str):
            payload = value["log"]
            continue
        if (source == "socket" and value.get("type") in ("request", "response") and
                isinstance(value.get("request"), dict)):
            return value
        return None
    raise AuditReaderError("audit reader envelope nesting exceeded")


def read_records(start_utc, end_utc, runner=_default_runner):
    """Read only the fixed relay group within one bounded UTC window."""
    start, end = _epoch(start_utc), _epoch(end_utc)
    if end < start or end - start > MAX_WINDOW_SECONDS:
        raise AuditReaderError("audit reader window exceeds fixed limit")
    start_ms, end_ms = int(start * 1000), int(end * 1000)
    token = None
    seen_tokens, seen_records = set(), set()
    records = []
    total = 0
    event_bytes = 0
    for _ in range(MAX_PAGES):
        args = ["aws", "logs", "filter-log-events", "--region", REGION, "--log-group-name", GROUP,
                "--start-time", str(start_ms), "--end-time", str(end_ms + 1), "--output", "json",
                "--no-paginate", "--no-cli-pager", "--limit", str(MAX_EVENTS),
                "--filter-pattern", '"vault-validator-audit-relay"']
        if token is not None: args.extend(("--next-token", token))
        try:
            raw = runner(tuple(args))
            if isinstance(raw, bytes): raw = raw.decode("utf-8")
            response = json.loads(raw)
        except AuditReaderError:
            raise
        except Exception as error:
            raise AuditReaderError("audit reader request failed") from error
        if not isinstance(response, dict) or set(response) - {"events", "nextToken", "searchedLogStreams"}:
            raise AuditReaderError("audit reader response is malformed")
        events = response.get("events", [])
        if not isinstance(events, list) or len(events) > MAX_EVENTS:
            raise AuditReaderError("audit reader response is malformed")
        for event in events:
            if not isinstance(event, dict) or set(event) - {"eventId", "timestamp", "ingestionTime", "message", "logStreamName"}:
                raise AuditReaderError("audit reader event is malformed or oversized")
            message = event.get("message")
            if not isinstance(message, str):
                raise AuditReaderError("audit reader event is malformed or oversized")
            event_bytes += len(message.encode("utf-8"))
            if event_bytes > MAX_TOTAL_BYTES:
                raise AuditReaderError("audit reader record budget exceeded")
            record = _decode(message)
            if record is None: continue
            encoded = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
            total += len(encoded)
            if total > MAX_TOTAL_BYTES:
                raise AuditReaderError("audit reader record budget exceeded")
            if encoded not in seen_records:
                seen_records.add(encoded)
                records.append(record)
                if len(records) > MAX_EVENTS:
                    raise AuditReaderError("audit reader record budget exceeded")
        token = response.get("nextToken")
        if token is None: return records
        if not isinstance(token, str) or not token or len(token) > 2048 or token in seen_tokens:
            raise AuditReaderError("audit reader pagination is malformed")
        seen_tokens.add(token)
    raise AuditReaderError("audit reader pagination budget exceeded")
