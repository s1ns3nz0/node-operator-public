#!/usr/bin/env python3
"""Emit a non-mutating, bound recovery plan for a missing slashing history.

This utility deliberately does not connect to Kubernetes, PostgreSQL, Vault, or
Web3Signer.  An empty EIP-3076 document is only a synthetic registration guard;
it is never described as recovered historical signing evidence.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import stat
import sys
from typing import Any

PUBKEY = re.compile(r"0x[0-9a-f]{96}\Z")
ROOT = re.compile(r"0x[0-9a-f]{64}\Z")
SET = re.compile(r"hoodi-[a-z0-9][a-z0-9-]*\Z")
UID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")
OPERATION = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{7,127}\Z")
IMAGE = re.compile(r"[0-9]{12}\.dkr\.ecr\.ap-northeast-2\.amazonaws\.com/[a-z0-9][a-z0-9._/-]*-validator-runtime-web3signer@sha256:([0-9a-f]{64})\Z")
SOURCE_COMMIT = "221996a5ddf6ab7648a8102ee029d9723762c116"


class RecoveryError(RuntimeError):
    pass


def _object(path: Path, message: str) -> dict[str, Any]:
    try:
        info = path.lstat()
        if path.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_size > 64 * 1024:
            raise OSError
        value = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as error:
        raise RecoveryError(message) from error
    if not isinstance(value, dict):
        raise RecoveryError(message)
    return value


def _source_digest(source_root: Path) -> str:
    value = _object(source_root / ".ci/validator/approved-runtime-images.json", "approved runtime inventory is unavailable")
    try:
        image = value["images"]["web3signer"]
        source = image["source"]
        reference = image["reference"]
        lock = _object(source_root / ".ci/web3signer-hardened/source.lock.json", "Web3Signer source lock is unavailable")
    except (KeyError, TypeError) as error:
        raise RecoveryError("selected-release Web3Signer source authority is malformed") from error
    found = re.fullmatch(r"consensys/web3signer@sha256:([0-9a-f]{64})", source) if isinstance(source, str) else None
    if (found is None or reference != "26.4.2" or lock.get("tag") != "26.4.2" or lock.get("commit") != SOURCE_COMMIT):
        raise RecoveryError("selected-release Web3Signer source is not pinned to 26.4.2 source commit")
    return found.group(1)


def plan(args: argparse.Namespace) -> dict[str, Any]:
    root = Path(args.source_root).resolve()
    source_digest = _source_digest(root)
    image_match = IMAGE.fullmatch(args.web3signer_image)
    if image_match is None:
        raise RecoveryError("Web3Signer image is not a private immutable validator runtime reference")
    if not SET.fullmatch(args.validator_set) or not PUBKEY.fullmatch(args.validator_public_key) or not ROOT.fullmatch(args.gvr):
        raise RecoveryError("validator identity or genesis validators root is invalid")
    if not UID.fullmatch(args.database_uid):
        raise RecoveryError("retained slashing database UID is invalid")
    expected_db = f"data-validator-{args.validator_set}-slashing-db-0"
    if args.database_pvc != expected_db:
        raise RecoveryError("retained database PVC is not exactly bound to the selected validator set")
    if min(args.slot, args.epoch) < 1:
        raise RecoveryError("watermark floor slot and epoch must be positive")
    stopped = _object(Path(args.stopped_paths), "stopped signing-path proof is unavailable")
    expected_paths = {"schema_version", "validator_set", "validator_public_key", "database_pvc", "database_uid", "client_stopped", "signer_stopped", "fence_stopped", "lease_holder_absent"}
    if set(stopped) != expected_paths or stopped["schema_version"] != 1 or stopped["validator_set"] != args.validator_set or stopped["validator_public_key"] != args.validator_public_key or stopped["database_pvc"] != args.database_pvc or stopped["database_uid"] != args.database_uid or any(stopped[x] is not True for x in ("client_stopped", "signer_stopped", "fence_stopped", "lease_holder_absent")):
        raise RecoveryError("stopped-path proposal does not bind this validator identity and database")
    return {
        "schema_version": 1,
        "event_type": "missing-slashing-history-recovery-plan",
        "mode": "dry-run",
        "historical_evidence_recovered": False,
        "validator": {"network": "hoodi", "validator_set": args.validator_set, "public_key": args.validator_public_key, "genesis_validators_root": args.gvr},
        "database": {"pvc": args.database_pvc, "uid": args.database_uid},
        "web3signer_authority": {"private_image": args.web3signer_image, "runtime_destination_verified": False, "selected_release_source_digest": source_digest, "version": "26.4.2", "source_commit": SOURCE_COMMIT},
        "watermark_repair": {"slot": args.slot, "epoch": args.epoch, "source_target_epoch_equality_is_native_precondition": True},
        "stopped_path_proposal_verified": False,
        "synthetic_eip3076_guard": {"metadata": {"interchange_format_version": "5", "genesis_validators_root": args.gvr}, "data": [{"pubkey": args.validator_public_key, "signed_blocks": [], "signed_attestations": []}]},
        "execution": {"available": False, "requires": ["separate explicit exception approval", "operation identity", "fresh native Web3Signer 26.4.2 help/version verification", "independent historical-recovery decision"]},
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", required=True)
    parser.add_argument("--validator-set", required=True)
    parser.add_argument("--validator-public-key", required=True)
    parser.add_argument("--gvr", required=True)
    parser.add_argument("--database-pvc", required=True)
    parser.add_argument("--database-uid", required=True)
    parser.add_argument("--web3signer-image", required=True)
    parser.add_argument("--slot", required=True, type=int)
    parser.add_argument("--epoch", required=True, type=int)
    parser.add_argument("--stopped-paths", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--exception-approval-id")
    parser.add_argument("--operation-id")
    args = parser.parse_args()
    if args.execute:
        if not (isinstance(args.exception_approval_id, str) and OPERATION.fullmatch(args.exception_approval_id)
                and isinstance(args.operation_id, str) and OPERATION.fullmatch(args.operation_id)):
            raise RecoveryError("execution requires explicit exception approval and operation identity")
        raise RecoveryError("execution is unavailable in this recovery-planning build; obtain a separate approved operation")
    output = Path(args.output)
    if not output.is_absolute() or output.exists() or output.is_symlink() or output.parent.is_symlink():
        raise RecoveryError("output must be a new regular path under a non-symlink directory")
    try:
        value = plan(args)
        fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as handle:
            json.dump(value, handle, sort_keys=True)
            handle.write("\n")
    except OSError as error:
        raise RecoveryError("recovery plan could not be written safely") from error
    print(f"PASS: dry-run recovery plan written; no slashing database, key, or signer was changed: {output}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RecoveryError as error:
        print(f"REFUSED: {error}", file=sys.stderr)
        raise SystemExit(65)
