#!/usr/bin/env python3
"""Read-only, resumable evidence collector for finalized Hoodi attestations.

This is deliberately an observer, not an activation or retry controller.  It
requires separately collected, non-secret workload and log-delivery evidence,
then independently checks actual attestation inclusion against a private
Beacon node and a public HTTPS Beacon API.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
import time
from typing import Any, Callable
from urllib.parse import quote, urlparse
from urllib.request import Request, urlopen

KEY = re.compile(r"0x[0-9a-f]{96}\Z")
SHA = re.compile(r"[0-9a-f]{40}\Z")
ROOT = re.compile(r"0x[0-9a-f]{64}\Z")
UINT = re.compile(r"[0-9]+\Z")
SET = re.compile(r"hoodi-[a-z0-9][a-z0-9-]*\Z")
NAME = re.compile(r"[a-z][a-z0-9-]{1,18}[a-z0-9]\Z")
MAX_JSON = 4 * 1024 * 1024
MAX_HTTP = 8 * 1024 * 1024
MAX_ANCESTRY_STEPS = 512


class ObservationError(Exception):
    pass


def pairs(pairs_: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs_:
        if key in value:
            raise ObservationError()
        value[key] = item
    return value


def obj(value: Any, fields: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise ObservationError()
    return value


def text(value: Any, pattern: re.Pattern[str]) -> str:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise ObservationError()
    return value


def integer(value: Any) -> int:
    raw = text(value, UINT)
    result = int(raw)
    if result > 2**64 - 1:
        raise ObservationError()
    return result


def regular_file(path: Path, limit: int = MAX_JSON) -> bytes:
    if not path.is_absolute() or path.is_symlink() or not path.is_file():
        raise ObservationError()
    stat = path.stat()
    if stat.st_size < 1 or stat.st_size > limit:
        raise ObservationError()
    with path.open("rb") as handle:
        data = handle.read(limit + 1)
    if len(data) != stat.st_size or len(data) > limit:
        raise ObservationError()
    return data


def load_json(path: Path) -> tuple[dict[str, Any], str]:
    raw = regular_file(path)
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs)
    except (UnicodeError, ValueError) as exc:
        raise ObservationError() from exc
    if not isinstance(value, dict):
        raise ObservationError()
    return value, hashlib.sha256(raw).hexdigest()


def validate_url(value: str, public: bool) -> str:
    parsed = urlparse(value)
    allowed = {"https"} if public else {"http", "https"}
    if parsed.scheme not in allowed or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ObservationError()
    return value.rstrip("/")


class Beacon:
    def __init__(self, base: str, timeout: float, fetch: Callable[[str, float], Any] | None = None):
        self.base, self.timeout, self.fetch = base, timeout, fetch
        self._headers: dict[str, tuple[int, str, str]] = {}

    def get(self, path: str) -> dict[str, Any]:
        url = self.base + path
        try:
            if self.fetch is not None:
                value = self.fetch(url, self.timeout)
            else:
                request = Request(url, headers={"Accept": "application/json", "User-Agent": "node-operator/1.0 (Hoodi read-only evidence observer)"})
                with urlopen(request, timeout=self.timeout) as response:  # nosec B310: validated operator endpoint
                    if response.status != 200:
                        raise ObservationError()
                    raw = response.read(MAX_HTTP + 1)
                if len(raw) > MAX_HTTP:
                    raise ObservationError()
                value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs)
        except (ObservationError, OSError, TimeoutError, UnicodeError, ValueError) as exc:
            raise ObservationError() from exc
        if not isinstance(value, dict):
            raise ObservationError()
        return value

    def validator_index(self, public_key: str) -> str:
        value = self.get("/eth/v1/beacon/states/head/validators/" + quote(public_key, safe=""))
        try:
            data = value["data"]
            index = data["index"]
            key = data["validator"]["pubkey"].lower()
        except (KeyError, TypeError) as exc:
            raise ObservationError() from exc
        if key != public_key or not UINT.fullmatch(index):
            raise ObservationError()
        return index

    def finality(self) -> tuple[int, str]:
        value = self.get("/eth/v1/beacon/states/head/finality_checkpoints")
        try:
            checkpoint = value["data"]["finalized"]
            epoch, root = integer(checkpoint["epoch"]), text(checkpoint["root"], ROOT)
        except (KeyError, TypeError) as exc:
            raise ObservationError() from exc
        return epoch, root

    def genesis_validators_root(self) -> str:
        value = self.get("/eth/v1/beacon/genesis")
        try:
            return text(value["data"]["genesis_validators_root"], ROOT)
        except (KeyError, TypeError) as exc:
            raise ObservationError() from exc

    def fork(self, state_root: str) -> tuple[int, str, str]:
        value = self.get("/eth/v1/beacon/states/" + state_root + "/fork")
        try:
            data = value["data"]
            version = re.compile(r"0x[0-9a-f]{8}\Z")
            return integer(data["epoch"]), text(data["previous_version"], version), text(data["current_version"], version)
        except (KeyError, TypeError) as exc:
            raise ObservationError() from exc

    def header(self, block_root: str) -> tuple[int, str, str]:
        if block_root in self._headers:
            return self._headers[block_root]
        value = self.get("/eth/v1/beacon/headers/" + block_root)
        try:
            # getBlockHeader returns one object; only getBlockHeaders returns
            # an array. State endpoints require the header's state_root, not
            # this block root (Beacon API StateId and BlockId are distinct).
            entry = value["data"]
            if not isinstance(entry, dict) or value.get("execution_optimistic") is not False:
                raise ObservationError()
            if entry["canonical"] is not True or text(entry["root"], ROOT) != block_root:
                raise ObservationError()
            header = entry["header"]["message"]
            result = integer(header["slot"]), text(header["parent_root"], ROOT), text(header["state_root"], ROOT)
            self._headers[block_root] = result
            return result
        except (KeyError, TypeError) as exc:
            raise ObservationError() from exc

    def block(self, block_root: str) -> dict[str, Any]:
        value = self.get("/eth/v2/beacon/blocks/" + block_root)
        try:
            message = value["data"]["message"]
            if not isinstance(message, dict):
                raise ObservationError()
            return message
        except (KeyError, TypeError) as exc:
            raise ObservationError() from exc

    def committee(self, state_root: str, slot: int, committee_index: int) -> list[str]:
        # Committee API otherwise defaults epoch to the (possibly newer) inclusion
        # state.  The duty is defined by the attestation slot.
        epoch = slot // 32
        value = self.get(f"/eth/v1/beacon/states/{state_root}/committees?slot={slot}&index={committee_index}&epoch={epoch}")
        try:
            rows = value["data"]
            if not isinstance(rows, list) or len(rows) != 1:
                raise ObservationError()
            row = rows[0]
            if integer(row["slot"]) != slot or integer(row["index"]) != committee_index:
                raise ObservationError()
            members = row["validators"]
            if not isinstance(members, list) or not members:
                raise ObservationError()
            return [text(member, UINT) for member in members]
        except (KeyError, TypeError) as exc:
            raise ObservationError() from exc


def bitlist(hex_value: Any) -> list[bool]:
    if not isinstance(hex_value, str) or not re.fullmatch(r"0x(?:[0-9a-fA-F]{2})+", hex_value):
        raise ObservationError()
    raw = bytes.fromhex(hex_value[2:])
    # SSZ BitList has a mandatory terminal delimiter bit in the last byte.
    if not raw or raw[-1] == 0:
        raise ObservationError()
    terminal = raw[-1].bit_length() - 1
    length = (len(raw) - 1) * 8 + terminal
    if length == 0:
        raise ObservationError()
    return [bool(raw[index // 8] & (1 << (index % 8))) for index in range(length)]


def bitvector_indices(hex_value: Any) -> list[int]:
    if not isinstance(hex_value, str) or not re.fullmatch(r"0x(?:[0-9a-fA-F]{2})+", hex_value):
        raise ObservationError()
    raw = bytes.fromhex(hex_value[2:])
    return [index for index in range(len(raw) * 8) if raw[index // 8] & (1 << (index % 8))]


def attestation_data(attestation: dict[str, Any]) -> dict[str, Any]:
    try:
        data = attestation["data"]
        return {
            "slot": integer(data["slot"]),
            "index": integer(data["index"]),
            "beacon_block_root": text(data["beacon_block_root"], ROOT),
            "source_epoch": integer(data["source"]["epoch"]),
            "source_root": text(data["source"]["root"], ROOT),
            "target_epoch": integer(data["target"]["epoch"]),
            "target_root": text(data["target"]["root"], ROOT),
        }
    except (KeyError, TypeError) as exc:
        raise ObservationError() from exc


def hash_pair(left: bytes, right: bytes) -> bytes:
    if len(left) != 32 or len(right) != 32:
        raise ObservationError()
    return hashlib.sha256(left + right).digest()


def uint64_root(value: int) -> bytes:
    if value < 0 or value > 2**64 - 1:
        raise ObservationError()
    return value.to_bytes(8, "little") + b"\0" * 24


def root_bytes(value: str) -> bytes:
    return bytes.fromhex(text(value, ROOT)[2:])


def checkpoint_root(epoch: int, root: str) -> bytes:
    # SSZ Container[Epoch, Root], padded to two leaves.
    return hash_pair(uint64_root(epoch), root_bytes(root))


def attestation_data_root(data: dict[str, Any]) -> str:
    """SSZ hash_tree_root(AttestationData), fixed five-field Phase0 container.

    AttestationData has not changed its SSZ shape through Electra.  The
    consensus spec defines it as slot, index, beacon_block_root, source, and
    target; containers are Merkleized to the next power-of-two leaf count.
    """
    leaves = [
        uint64_root(data["slot"]), uint64_root(data["index"]), root_bytes(data["beacon_block_root"]),
        checkpoint_root(data["source_epoch"], data["source_root"]),
        checkpoint_root(data["target_epoch"], data["target_root"]), b"\0" * 32, b"\0" * 32, b"\0" * 32,
    ]
    while len(leaves) > 1:
        leaves = [hash_pair(leaves[index], leaves[index + 1]) for index in range(0, len(leaves), 2)]
    return "0x" + leaves[0].hex()


def signing_root(data_root: str, fork_version: str, genesis_validators_root: str) -> str:
    """SSZ compute_signing_root(data, DOMAIN_BEACON_ATTESTER)."""
    version = text(fork_version, re.compile(r"0x[0-9a-f]{8}\Z"))
    fork_data_root = hash_pair(bytes.fromhex(version[2:]) + b"\0" * 28, root_bytes(genesis_validators_root))
    domain = bytes.fromhex("01000000") + fork_data_root[:28]
    return "0x" + hash_pair(root_bytes(data_root), domain).hex()


def finalized_ancestor(api: Beacon, inclusion_root: str, inclusion_slot: int, finalized_root: str) -> bool:
    """Prove the inclusion root is on this source's finalized parent chain."""
    cursor = finalized_root
    for _ in range(MAX_ANCESTRY_STEPS):
        slot, parent, _ = api.header(cursor)
        if cursor == inclusion_root:
            return True
        if slot <= inclusion_slot:
            return False
        cursor = parent
    raise ObservationError()


def source_inclusion(api: Beacon, validator_index: str, expected_epoch: int,
                     expected_slot: int, expected_committee: int) -> dict[str, Any] | None:
    """Find canonical inclusion without letting a supplied block root choose it."""
    finalized_epoch, finalized_root = api.finality()
    cursor, matches = finalized_root, []
    for _ in range(MAX_ANCESTRY_STEPS):
        inclusion_slot, parent_root, state_root = api.header(cursor)
        if inclusion_slot <= expected_slot:
            break
        if inclusion_slot > expected_slot + 32:
            cursor = parent_root
            continue
        block = api.block(cursor)
        if (integer(block.get("slot")) != inclusion_slot or text(block.get("parent_root"), ROOT) != parent_root
                or text(block.get("state_root"), ROOT) != state_root):
            raise ObservationError()
        try:
            attestations = block["body"]["attestations"]
        except (KeyError, TypeError) as exc:
            raise ObservationError() from exc
        if not isinstance(attestations, list):
            raise ObservationError()
        wanted = int(validator_index)
        for candidate in attestations:
            if not isinstance(candidate, dict):
                raise ObservationError()
            data = attestation_data(candidate)
            if data["slot"] != expected_slot or data["target_epoch"] != expected_epoch:
                continue
            bits = bitlist(candidate.get("aggregation_bits"))
            if "committee_bits" in candidate:  # Electra: concatenated committee bits in committee order.
                committees = bitvector_indices(candidate["committee_bits"])
                if expected_committee not in committees:
                    continue
                offset = 0
                own_members: list[str] | None = None
                for committee_index in committees:
                    members = api.committee(state_root, expected_slot, committee_index)
                    if committee_index == expected_committee:
                        own_members = members
                        break
                    offset += len(members)
                if own_members is None or wanted not in map(int, own_members):
                    continue
                member_position = list(map(int, own_members)).index(wanted)
                position = offset + member_position
            else:  # pre-Electra: data.index selects one committee.
                if data["index"] != expected_committee:
                    continue
                members = api.committee(state_root, expected_slot, expected_committee)
                if wanted not in map(int, members):
                    continue
                position = list(map(int, members)).index(wanted)
            if position >= len(bits) or not bits[position]:
                continue
            matches.append({"inclusion_block_root": cursor, "inclusion_block_slot": inclusion_slot,
                            "inclusion_parent_root": parent_root, "finalized_epoch": finalized_epoch,
                            "finalized_root": finalized_root, "attestation": data,
                            "attestation_data_root": attestation_data_root(data), "aggregation_bit_index": position})
        cursor = parent_root
    # The same vote can be included through multiple aggregates or blocks.
    # Repeated inclusion is not a second vote; choose the earliest canonical
    # inclusion deterministically on both sources. Conflicting vote data for
    # this validator/epoch remains an error rather than silently choosing one.
    if len({item["attestation_data_root"] for item in matches}) > 1:
        raise ObservationError()
    if not matches:
        return None
    return min(matches, key=lambda item: (item["inclusion_block_slot"], item["inclusion_block_root"], item["aggregation_bit_index"]))


def proof_inputs(workload_path: Path, log_path: Path, identity: dict[str, str]) -> tuple[dict[int, dict[str, Any]], dict[int, dict[str, Any]], str, str]:
    workload, workload_hash = load_json(workload_path)
    log, log_hash = load_json(log_path)
    common = {"schema_version", "network", "event_type", "deployment_name", "release_revision", "validator_set", "validator_public_key", "validator_index", "observations"}
    for value, event in ((workload, "validator-attestation-workload-proof"), (log, "validator-log-delivery-proof")):
        obj(value, common)
        if value["schema_version"] != 1 or value["network"] != "hoodi" or value["event_type"] != event:
            raise ObservationError()
        for field in ("validator_set", "validator_public_key", "validator_index", "deployment_name", "release_revision"):
            expected = identity[field]
            if value.get(field) != expected:
                raise ObservationError()
        if not isinstance(value["observations"], list):
            raise ObservationError()
    def index(rows: list[Any], workload_rows: bool) -> dict[int, dict[str, Any]]:
        result: dict[int, dict[str, Any]] = {}
        for row in rows:
            if not isinstance(row, dict):
                raise ObservationError()
            fields = {"epoch", "attestation_slot", "committee_index", "signing_root", "signer_event", "fence_interval"} if workload_rows else {"epoch", "attestation_slot", "delivery_observed", "delivery_source", "delivery_evidence_id"}
            obj(row, fields)
            epoch, slot = integer(row["epoch"]), integer(row["attestation_slot"])
            if slot // 32 != epoch or epoch in result:
                raise ObservationError()
            if workload_rows:
                integer(row["committee_index"])
                text(row["signing_root"], ROOT)
                for ref in (row["signer_event"], row["fence_interval"]):
                    obj(ref, {"source", "evidence_id"})
                    if not all(isinstance(ref[field], str) and ref[field] for field in ref):
                        raise ObservationError()
            elif row["delivery_observed"] is not True or not isinstance(row["delivery_source"], str) or not isinstance(row["delivery_evidence_id"], str) or not row["delivery_source"] or not row["delivery_evidence_id"]:
                raise ObservationError()
            result[epoch] = row
        return result
    return index(workload["observations"], True), index(log["observations"], False), workload_hash, log_hash


def checkpoint_path(directory: Path) -> Path:
    if not directory.is_absolute() or directory.is_symlink() or not directory.is_dir():
        raise ObservationError()
    return directory / "finalized-attestation-observer.json"


def read_checkpoint(directory: Path, identity: dict[str, str]) -> dict[str, Any]:
    path = checkpoint_path(directory)
    if not path.exists():
        return {"schema_version": 1, "identity": identity, "proofs": []}
    value, _ = load_json(path)
    obj(value, {"schema_version", "identity", "proofs"})
    if value["schema_version"] != 1 or value["identity"] != identity or not isinstance(value["proofs"], list):
        raise ObservationError()
    return value


def save_checkpoint(directory: Path, value: dict[str, Any]) -> None:
    path = checkpoint_path(directory)
    encoded = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    with tempfile.NamedTemporaryFile("wb", dir=directory, prefix=".finalized-attestation.", delete=False) as handle:
        handle.write(encoded); handle.flush(); os.fsync(handle.fileno()); temporary = Path(handle.name)
    try:
        temporary.chmod(0o600)
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def source_signing_root(api: Beacon, fact: dict[str, Any]) -> str:
    data = fact["attestation"]
    # The signing domain is selected for the attestation's target epoch, not
    # blindly from the current head. Use the canonical inclusion's state so a
    # vote after a fork with an older (skipped-slot) beacon_block_root still
    # sees that fork. A next-epoch inclusion selects previous_version when
    # its fork epoch is later than the vote's target epoch.
    _, _, state_root = api.header(fact["inclusion_block_root"])
    fork_epoch, previous_version, current_version = api.fork(state_root)
    fork_version = previous_version if data["target_epoch"] < fork_epoch else current_version
    return signing_root(fact["attestation_data_root"], fork_version, api.genesis_validators_root())


def observed_proof(private: Beacon, public: Beacon, identity: dict[str, str], epoch: int, slot: int,
                   committee: int, expected_signing_root: str, workload_hash: str, log_hash: str, delivery: dict[str, Any], signer_ref: dict[str, Any], fence_ref: dict[str, Any]) -> dict[str, Any] | None:
    private_fact = source_inclusion(private, identity["validator_index"], epoch, slot, committee)
    public_fact = source_inclusion(public, identity["validator_index"], epoch, slot, committee)
    if private_fact is None or public_fact is None:
        return None
    equality = ("inclusion_block_root", "inclusion_block_slot", "inclusion_parent_root", "attestation", "attestation_data_root", "aggregation_bit_index")
    if any(private_fact[field] != public_fact[field] for field in equality):
        raise ObservationError()
    if source_signing_root(private, private_fact) != expected_signing_root or source_signing_root(public, public_fact) != expected_signing_root:
        raise ObservationError()
    return {"epoch": str(epoch), "attestation_slot": str(slot), "committee_index": str(committee), "workload_sha256": workload_hash,
            "log_delivery_sha256": log_hash, "private": private_fact, "public": public_fact,
            "signer_event": signer_ref, "fence_interval": fence_ref,
            "log_delivery": {"source": delivery["delivery_source"], "evidence_id": delivery["delivery_evidence_id"]}}


def observe(directory: Path, identity: dict[str, str], private_url: str, public_url: str,
            workload_path: Path, log_path: Path, timeout: float, fetch: Callable[[str, float], Any] | None = None,
            required_count: int = 3) -> tuple[int, dict[str, Any]]:
    if type(required_count) is not int or required_count not in (1, 2, 3):
        raise ObservationError()
    workload, logs, workload_hash, log_hash = proof_inputs(workload_path, log_path, identity)
    checkpoint_identity = identity | {"private_beacon_url": private_url, "public_beacon_url": public_url,
                                      "workload_proof_path": str(workload_path), "log_delivery_proof_path": str(log_path)}
    state = read_checkpoint(directory, checkpoint_identity)
    private, public = Beacon(private_url, timeout, fetch), Beacon(public_url, timeout, fetch)
    private_index, public_index = private.validator_index(identity["validator_public_key"]), public.validator_index(identity["validator_public_key"])
    if private_index != identity["validator_index"] or public_index != identity["validator_index"]:
        raise ObservationError()
    existing: dict[int, dict[str, Any]] = {}
    for proof in state["proofs"]:
        if not isinstance(proof, dict):
            raise ObservationError()
        required = {"epoch", "attestation_slot", "committee_index", "workload_sha256", "log_delivery_sha256", "private", "public", "signer_event", "fence_interval", "log_delivery"}
        if set(proof) != required:
            raise ObservationError()
        epoch = integer(proof["epoch"])
        if epoch in existing or integer(proof["attestation_slot"]) // 32 != epoch or not ROOT.fullmatch(proof["private"].get("inclusion_block_root", "")):
            raise ObservationError()
        existing[epoch] = proof
    accepted: list[dict[str, Any]] = []
    for epoch in sorted(set(existing) | (set(workload) & set(logs))):
        if epoch in workload and epoch in logs:
            work, delivery = workload[epoch], logs[epoch]
            if work["attestation_slot"] != delivery["attestation_slot"]:
                continue
            if integer(work["attestation_slot"]) <= integer(identity["activation_slot"]):
                continue
            proof = observed_proof(private, public, identity, epoch, integer(work["attestation_slot"]), integer(work["committee_index"]), work["signing_root"], workload_hash, log_hash, delivery, work["signer_event"], work["fence_interval"])
        else:
            prior = existing[epoch]
            if integer(prior["attestation_slot"]) <= integer(identity["activation_slot"]):
                raise ObservationError()
            delivery = prior["log_delivery"]
            if not isinstance(delivery, dict) or set(delivery) != {"source", "evidence_id"} or not all(isinstance(delivery[item], str) and delivery[item] for item in delivery):
                raise ObservationError()
            signer, fence = prior["signer_event"], prior["fence_interval"]
            for ref in (signer, fence):
                if not isinstance(ref, dict) or set(ref) != {"source", "evidence_id"} or not all(isinstance(ref[item], str) and ref[item] for item in ref):
                    raise ObservationError()
            expected = source_signing_root(private, prior["private"])
            proof = observed_proof(private, public, identity, epoch, integer(prior["attestation_slot"]), integer(prior["committee_index"]), expected, prior["workload_sha256"], prior["log_delivery_sha256"], {"delivery_source": delivery["source"], "delivery_evidence_id": delivery["evidence_id"]}, signer, fence)
        if proof is not None:
            accepted.append(proof)
    accepted.sort(key=lambda item: integer(item["epoch"]))
    consecutive: list[dict[str, Any]] = []
    for proof in accepted:
        if not consecutive or integer(proof["epoch"]) == integer(consecutive[-1]["epoch"]) + 1:
            consecutive.append(proof)
        else:
            consecutive = [proof]
    state["proofs"] = consecutive
    save_checkpoint(directory, state)
    result = {"schema_version": 1, "identity": checkpoint_identity, "consecutive_finalized_epochs": [item["epoch"] for item in consecutive], "required_finalized_epochs": required_count, "complete": len(consecutive) >= required_count}
    return (0 if result["complete"] else 75), result


def main() -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("operation", choices=("observe",))
    parser.add_argument("--checkpoint-dir", required=True)
    parser.add_argument("--validator-set", required=True)
    parser.add_argument("--validator-public-key", required=True)
    parser.add_argument("--validator-index", required=True)
    parser.add_argument("--deployment-name", required=True)
    parser.add_argument("--release-revision", required=True)
    parser.add_argument("--activation-slot", required=True)
    parser.add_argument("--private-beacon-url", required=True)
    parser.add_argument("--public-beacon-url", required=True)
    parser.add_argument("--workload-proof", required=True)
    parser.add_argument("--log-delivery-proof", required=True)
    parser.add_argument("--timeout-seconds", type=float, default=10.0)
    parser.add_argument("--required-finalized-epochs", type=int, choices=(1, 2, 3), default=3)
    args = parser.parse_args()
    try:
        if not 1 <= args.timeout_seconds <= 30:
            raise ObservationError()
        identity = {"validator_set": text(args.validator_set, SET), "validator_public_key": text(args.validator_public_key.lower(), KEY),
                    "validator_index": text(args.validator_index, UINT), "deployment_name": text(args.deployment_name, NAME),
                    "release_revision": text(args.release_revision, SHA), "activation_slot": text(args.activation_slot, UINT)}
        private = validate_url(args.private_beacon_url, False); public = validate_url(args.public_beacon_url, True)
        if private == public:
            raise ObservationError()
        rc, result = observe(Path(args.checkpoint_dir), identity, private, public, Path(args.workload_proof), Path(args.log_delivery_proof), args.timeout_seconds, required_count=args.required_finalized_epochs)
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return rc
    except (ObservationError, OSError, ValueError):
        print("finalized attestation observation is pending or invalid", file=os.sys.stderr)
        return 65


if __name__ == "__main__":
    raise SystemExit(main())
