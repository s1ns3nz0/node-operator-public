#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
verifier="$root/scripts/ops/verify-validator-audit-restore.sh"
tmp="$(mktemp -d /private/tmp/node-operator-audit-restore-contract.XXXXXX)"
cleanup() { rm -rf "$tmp"; }
trap cleanup EXIT INT TERM

python3 - "$tmp" <<'PY'
import gzip
import json
import os
import sys

directory = sys.argv[1]


def batch(log):
    return {
        "owner": "123456789012",
        "logGroup": "/aws/eks/node-operator/validator",
        "logStream": "private-validator-stream",
        "subscriptionFilters": ["validator-audit"],
        "messageType": "DATA_MESSAGE",
        "logEvents": [{
            "id": "event-1",
            "timestamp": 1_789_000_000_000,
            "message": json.dumps({
                "kubernetes": {
                    "namespace_name": "node-operator",
                    "pod_name": "prysm-validator-0",
                    "container_name": "validator",
                    "labels": {"app": "prysm-validator"},
                },
                "log": log,
            }),
        }],
    }


def write_nested(path, content, layers=2):
    encoded = content.encode("utf-8")
    for _ in range(layers):
        encoded = gzip.compress(encoded)
    with open(path, "wb") as destination:
        destination.write(encoded)


write_nested(os.path.join(directory, "valid.gz"), "".join(json.dumps(batch(f"audit request {number}")) for number in range(186)))
write_nested(os.path.join(directory, "secret.gz"), json.dumps(batch("token=synthetic-test-value")))
write_nested(os.path.join(directory, "malformed.gz"), "{not-json}")
write_nested(os.path.join(directory, "third-layer.gz"), json.dumps(batch("too deeply compressed")), layers=3)
with open(os.path.join(directory, "uncompressed-too-large.gz"), "wb") as destination:
    destination.write(gzip.compress(gzip.compress(b"x" * ((16 * 1024 * 1024) + 1))))
with open(os.path.join(directory, "too-large.gz"), "wb") as destination:
    destination.write(os.urandom((8 * 1024 * 1024) + 1))
PY

"$verifier" --firehose-archive "$tmp/valid.gz" >/dev/null
"$verifier" --firehose-archive <(cat "$tmp/valid.gz") >/dev/null
for rejected in secret.gz malformed.gz third-layer.gz uncompressed-too-large.gz too-large.gz; do
  if "$verifier" --firehose-archive "$tmp/$rejected" >/dev/null 2>&1; then
    printf 'archive adapter accepted unsafe fixture: %s\n' "$rejected" >&2
    exit 1
  fi
done
grep -Fq -- '--firehose-archive' "$verifier"
grep -Fq 'MAX_GZIP_LAYERS = 2' "$verifier"
grep -Fq 'MAX_BATCH_OBJECTS = 1024' "$verifier"
grep -Fq 'MAX_COMPRESSED_BYTES' "$verifier"
grep -Fq 'MAX_UNCOMPRESSED_LAYER_BYTES' "$verifier"
grep -Fq 'normalized non-secret metadata records' "$verifier"
printf '%s\n' 'PASS: Firehose archive adapter accepts only bounded, normalized synthetic batches and rejects unsafe input.'
