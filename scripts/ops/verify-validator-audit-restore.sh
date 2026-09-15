#!/usr/bin/env bash
set -euo pipefail

# Verify a locally restored Object-Lock archive copy before using it for audit
# or reindexing. It never changes the original archive or any workload.
usage() { printf '%s\n' "Usage: ${0##*/} (--manifest <absolute-json> --evidence-dir <absolute-dir> | --firehose-archive <absolute-gzip>)" >&2; exit 64; }
manifest=''; evidence_dir=''; firehose_archive=''
while [ "$#" -gt 0 ]; do case "$1" in --manifest) manifest="${2:-}"; shift 2 ;; --evidence-dir) evidence_dir="${2:-}"; shift 2 ;; --firehose-archive) firehose_archive="${2:-}"; shift 2 ;; *) usage ;; esac; done

if [ -n "$firehose_archive" ]; then
  [ -z "$manifest" ] && [ -z "$evidence_dir" ] || usage
  case "$firehose_archive" in /*) ;; *) usage ;; esac
  [ -r "$firehose_archive" ] || { printf '%s\n' 'Firehose archive is not readable' >&2; exit 66; }
  command -v python3 >/dev/null 2>&1 || { printf '%s\n' 'missing command: python3' >&2; exit 69; }

  # This adapter retains no decompressed data: bounded layers and normalized
  # metadata exist only in the Python process. The limits deliberately reject
  # oversized archive objects rather than risking a restore-time decompression
  # or JSON parsing denial of service.
  python3 - "$firehose_archive" <<'PY'
import gzip
import io
import json
import os
import re
import stat
import sys

MAX_COMPRESSED_BYTES = 8 * 1024 * 1024
MAX_UNCOMPRESSED_LAYER_BYTES = 16 * 1024 * 1024
MAX_GZIP_LAYERS = 2
MAX_BATCH_OBJECTS = 1024
MAX_LOG_EVENTS = 10_000
MAX_EVENT_MESSAGE_BYTES = 64 * 1024
MAX_LOG_BYTES = 16 * 1024
MAX_METADATA_STRING_BYTES = 1024
GZIP_MAGIC = b"\x1f\x8b"

FORBIDDEN_KEY = re.compile(
    r"(?:mnemonic|keystore|pass(?:word|phrase)?|token|secret|credential|"
    r"authori[sz]ation|access[_-]?key|private[_-]?key|kubeconfig|session[_-]?key|api[_-]?key)",
    re.IGNORECASE,
)
FORBIDDEN_VALUE = re.compile(
    r"(?:-----BEGIN(?: [A-Z]+)? PRIVATE KEY-----|"
    r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b|"
    r"\b(?:xox[baprs]-|gh[pousr]_|github_pat_|hvs\.|s\.)|"
    r"\bBearer\s+[A-Za-z0-9._~+/-]+=*|"
    r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}|"
    r"(?:password|passphrase|token|secret|credential|api[_-]?key)\s*[:=])",
    re.IGNORECASE,
)


class Rejected(Exception):
    pass


def reject_if_credential_like(value, maximum=MAX_METADATA_STRING_BYTES):
    """Inspect input without retaining or emitting its values."""
    pending = [value]
    while pending:
        item = pending.pop()
        if isinstance(item, dict):
            for key, nested in item.items():
                if not isinstance(key, str) or FORBIDDEN_KEY.search(key):
                    raise Rejected()
                pending.append(nested)
        elif isinstance(item, list):
            pending.extend(item)
        elif isinstance(item, str):
            if len(item.encode("utf-8")) > maximum or FORBIDDEN_VALUE.search(item):
                raise Rejected()
        elif item is None or isinstance(item, bool) or isinstance(item, (int, float)):
            continue
        else:
            raise Rejected()


def decompress_once(layer):
    if not layer.startswith(GZIP_MAGIC):
        raise Rejected()
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(layer), mode="rb") as stream:
            restored = stream.read(MAX_UNCOMPRESSED_LAYER_BYTES + 1)
    except (EOFError, OSError, gzip.BadGzipFile):
        raise Rejected() from None
    if len(restored) > MAX_UNCOMPRESSED_LAYER_BYTES:
        raise Rejected()
    return restored


def normalized_log_event(event):
    if not isinstance(event, dict) or set(event) != {"id", "timestamp", "message"}:
        raise Rejected()
    if isinstance(event["timestamp"], bool) or not isinstance(event["timestamp"], int):
        raise Rejected()
    reject_if_credential_like({"id": event["id"]})
    message = event["message"]
    if not isinstance(message, str) or len(message.encode("utf-8")) > MAX_EVENT_MESSAGE_BYTES:
        raise Rejected()
    try:
        payload = json.loads(message)
    except (json.JSONDecodeError, RecursionError):
        raise Rejected() from None
    if not isinstance(payload, dict) or set(payload) != {"kubernetes", "log"}:
        raise Rejected()
    if not isinstance(payload["kubernetes"], dict) or not isinstance(payload["log"], str):
        raise Rejected()
    if len(payload["log"].encode("utf-8")) > MAX_LOG_BYTES:
        raise Rejected()
    reject_if_credential_like(payload, maximum=MAX_LOG_BYTES)

    # Keep only this allowlist in memory. Raw message/log text, CloudWatch IDs,
    # labels, container IDs, and other unbounded metadata are not retained.
    kubernetes = payload["kubernetes"]
    metadata = {"event_timestamp": event["timestamp"]}
    for field in ("namespace_name", "pod_name", "container_name"):
        value = kubernetes.get(field)
        if value is not None:
            if not isinstance(value, str) or len(value.encode("utf-8")) > 256:
                raise Rejected()
            reject_if_credential_like(value, maximum=256)
            metadata[field] = value
    return metadata


def normalized_batch(batch):
    expected = {"owner", "logGroup", "logStream", "subscriptionFilters", "messageType", "logEvents"}
    if not isinstance(batch, dict) or set(batch) != expected or batch["messageType"] != "DATA_MESSAGE":
        raise Rejected()
    if not isinstance(batch["owner"], str) or not re.fullmatch(r"[0-9]{12}", batch["owner"]):
        raise Rejected()
    if not isinstance(batch["logGroup"], str) or not isinstance(batch["logStream"], str):
        raise Rejected()
    if not isinstance(batch["subscriptionFilters"], list) or not isinstance(batch["logEvents"], list):
        raise Rejected()
    if not batch["logEvents"] or len(batch["logEvents"]) > MAX_LOG_EVENTS:
        raise Rejected()
    reject_if_credential_like({
        "owner": batch["owner"],
        "logGroup": batch["logGroup"],
        "logStream": batch["logStream"],
        "subscriptionFilters": batch["subscriptionFilters"],
    })
    return [normalized_log_event(event) for event in batch["logEvents"]]


def parse_concatenated_batches(document):
    try:
        text = document.decode("utf-8")
    except UnicodeDecodeError:
        raise Rejected() from None
    decoder = json.JSONDecoder()
    position = 0
    batches = 0
    normalized = []
    while True:
        while position < len(text) and text[position].isspace():
            position += 1
        if position == len(text):
            break
        if batches >= MAX_BATCH_OBJECTS:
            raise Rejected()
        try:
            batch, position = decoder.raw_decode(text, position)
        except (json.JSONDecodeError, RecursionError):
            raise Rejected() from None
        normalized.extend(normalized_batch(batch))
        batches += 1
    if batches == 0 or not normalized:
        raise Rejected()
    return batches, len(normalized)


try:
    archive = sys.argv[1]
    archive_stat = os.stat(archive)
    if stat.S_ISREG(archive_stat.st_mode) and archive_stat.st_size > MAX_COMPRESSED_BYTES:
        raise Rejected()
    with open(archive, "rb") as source:
        compressed = source.read(MAX_COMPRESSED_BYTES + 1)
    if len(compressed) > MAX_COMPRESSED_BYTES:
        raise Rejected()
    layers = 0
    restored = compressed
    while restored.startswith(GZIP_MAGIC):
        if layers == MAX_GZIP_LAYERS:
            raise Rejected()
        restored = decompress_once(restored)
        layers += 1
    if layers == 0:
        raise Rejected()
    batch_count, event_count = parse_concatenated_batches(restored)
except (IndexError, OSError, Rejected, ValueError, TypeError, RecursionError):
    print("Firehose archive adapter rejected unsafe, malformed, or oversized input", file=sys.stderr)
    sys.exit(65)

print(f"PASS: Firehose archive adapter verified {batch_count} batches and {event_count} normalized non-secret metadata records.")
PY
  exit 0
fi

case "$manifest" in /*) ;; *) usage ;; esac
case "$evidence_dir" in /*) ;; *) usage ;; esac
for command in jq shasum basename dirname awk; do command -v "$command" >/dev/null 2>&1 || { printf 'missing command: %s\n' "$command" >&2; exit 69; }; done
[ -r "$manifest" ] && [ -d "$evidence_dir" ] || { printf '%s\n' 'manifest or restored evidence directory is not readable' >&2; exit 66; }
jq -e '.schema_version == 1 and .event_type == "archive-manifest" and (.records | type == "array" and length > 0)' "$manifest" >/dev/null || { printf '%s\n' 'invalid audit manifest' >&2; exit 65; }
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"; validator="$root/scripts/ops/validate-validator-evidence-envelope.sh"
while IFS=$'\t' read -r filename expected_sha; do
  case "$filename" in ''|*/*|.*) printf '%s\n' 'unsafe manifest file name' >&2; exit 65 ;; esac
  restored="$evidence_dir/$filename"
  [ -r "$restored" ] || { printf 'missing restored evidence file: %s\n' "$filename" >&2; exit 65; }
  actual_sha="$(shasum -a 256 "$restored" | awk '{print $1}')"
  [ "$actual_sha" = "$expected_sha" ] || { printf 'restore SHA mismatch: %s\n' "$filename" >&2; exit 65; }
  "$validator" --file "$restored" >/dev/null
done < <(jq -r '.records[] | [.file,.sha256] | @tsv' "$manifest")
printf '%s\n' 'PASS: restored validator evidence matches its manifest and non-secret schema.'
