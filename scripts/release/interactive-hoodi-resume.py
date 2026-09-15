#!/usr/bin/env python3
"""Private, non-secret interactive recovery receipt and continuation helper."""

from __future__ import annotations
import argparse, hashlib, json, os, re, secrets, stat, sys, tempfile
from pathlib import Path


class ResumeError(ValueError):
    pass


BASE_PHASES = (
    "infrastructure",
    "infrastructure-complete",
    "platform-started",
    "platform-complete",
)
CONTINUATION_PHASES = (
    "vault-started", "vault-complete", "collector-complete", "audit-started", "audit-complete", "custody-started", "custody-complete",
    "runtime-complete", "activation-pending", "activation-started", "activated",
    "observing", "complete",
)
ALL_PHASES = BASE_PHASES + CONTINUATION_PHASES
PUBLIC_KEY = re.compile(r"0x[0-9a-f]{96}\Z")
VALIDATOR_SET = re.compile(r"hoodi-[a-z0-9][a-z0-9-]*\Z")
UID_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,255}\Z")
CUSTODY_RESULT_REL = "custody/custody-completion.json"
ACTIVATION_RECEIPT_REL = "evidence/activation-receipt.json"
AUDIT_RECEIPT_REL = "audit/audit-challenge.json"
AUDIT_COMPLETION_KEY = "audit_completion_sha256"
AUDIT_CONTINUATION_KEYS = {"audit_operation_id", "audit_receipt_rel"}
CONTINUATION_KEYS = {
    "keystore_dir", "keystore_device", "keystore_inode", "public_key",
    "deposit_attestation_rel", "deposit_attestation_sha256",
    "runtime_receipt_rel", "runtime_receipt_sha256",
}
CUSTODY_CONTINUATION_KEYS = {
    "validator_set", "custody_operation_id", "custody_result_rel",
}
CUSTODY_COMPLETION_KEY = "custody_result_sha256"
ACTIVATION_CONTINUATION_KEYS = {"activation_operation_id", "activation_receipt_rel"}
ACTIVATION_COMPLETION_KEY = "activation_receipt_sha256"


def manifest_identity(manifest: Path):
    try:
        value = json.loads(manifest.read_text())
    except (OSError, json.JSONDecodeError) as e:
        raise ResumeError("release manifest is invalid") from e
    revision = value.get("source_revision") if isinstance(value, dict) else None
    if not isinstance(revision, str) or not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise ResumeError("release manifest identity is invalid")
    return hashlib.sha256(manifest.read_bytes()).hexdigest(), revision


def strict_json(raw: bytes, label: str):
    def no_duplicate_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ResumeError(f"{label} has duplicate JSON keys")
            result[key] = value
        return result
    try:
        return json.loads(raw, object_pairs_hook=no_duplicate_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        raise ResumeError(f"{label} is invalid") from e


def safe_dir(path: Path):
    if not path.is_absolute():
        raise ResumeError("WORK_DIR must be absolute")
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700:
        raise ResumeError("WORK_DIR must be an existing private 0700 directory")


def rel(path: Path, root: Path):
    value = path.resolve()
    try:
        return str(value.relative_to(root.resolve()))
    except ValueError as e:
        raise ResumeError("saved path escapes WORK_DIR") from e


def child(root: Path, relative: str, required: bool):
    path = root / relative
    for parent in (path.parent, *path.parent.parents):
        if parent == root.parent:
            break
        if parent.is_symlink():
            raise ResumeError("saved path has a symlink ancestor")
    if required and not path.exists():
        raise ResumeError("saved infrastructure input is missing")
    return path


def write(path: Path, value: dict):
    fd, tmp = tempfile.mkstemp(prefix=".interactive-resume-", dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w") as out:
            json.dump(value, out, sort_keys=True)
            out.write("\n")
            out.flush()
            os.fsync(out.fileno())
        if path.exists():
            os.replace(tmp, path)
        else:
            os.link(tmp, path)
            os.unlink(tmp)
    finally:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass


def read(root: Path, manifest: Path):
    safe_dir(root)
    path = root / "interactive-resume.json"
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600:
        raise ResumeError("resume receipt must be private regular 0600")
    value = json.loads(path.read_text())
    base_keys = {
        "schema_version",
        "bundle_manifest_sha256",
        "inputs_sha256",
        "aws_account_id",
        "aws_region",
        "deployment_name",
        "inputs_rel",
        "work_rel",
        "session_rel",
        "phase",
    }
    if not isinstance(value, dict) or value.get("schema_version") not in (1, 2):
        raise ResumeError("resume receipt schema is invalid")
    if value["schema_version"] == 1:
        if set(value) != base_keys or value.get("phase") not in BASE_PHASES:
            raise ResumeError("resume receipt schema is invalid")
    else:
        if set(value) != base_keys | {"release_revision", "continuation"} or value.get("phase") not in ALL_PHASES:
            raise ResumeError("resume receipt schema is invalid")
    manifest_hash = hashlib.sha256(manifest.read_bytes()).hexdigest()
    if value["bundle_manifest_sha256"] != manifest_hash:
        raise ResumeError("saved work belongs to a different release bundle")
    if value["schema_version"] == 2:
        _, revision = manifest_identity(manifest)
        if value.get("release_revision") != revision:
            raise ResumeError("saved work belongs to a different release identity")
    if not (
        isinstance(value["aws_account_id"], str)
        and value["aws_account_id"].isdigit()
        and len(value["aws_account_id"]) == 12
    ):
        raise ResumeError("resume account is invalid")
    for key in (
        "aws_region",
        "deployment_name",
        "inputs_rel",
        "work_rel",
        "session_rel",
    ):
        if (
            not isinstance(value[key], str)
            or not value[key]
            or Path(value[key]).is_absolute()
            or ".." in Path(value[key]).parts
        ):
            raise ResumeError("resume path or context is invalid")
    if (value["inputs_rel"], value["work_rel"], value["session_rel"]) != (
        "inputs/hoodi-zero-release-inputs.json",
        "deployment-work",
        "private-eks-session.json",
    ):
        raise ResumeError("resume paths are not the fixed infrastructure paths")
    inputs = child(root, value["inputs_rel"], True)
    work = child(root, value["work_rel"], False)
    session = child(root, value["session_rel"], False)
    if (
        inputs.is_symlink()
        or not inputs.is_file()
        or work.is_symlink()
        or session.is_symlink()
    ):
        raise ResumeError("saved infrastructure paths are unavailable or unsafe")
    if value.get("inputs_sha256") != hashlib.sha256(inputs.read_bytes()).hexdigest():
        raise ResumeError("saved infrastructure inputs changed")
    inputs_value = json.loads(inputs.read_text())
    if (
        not isinstance(inputs_value, dict)
        or inputs_value.get("aws_account_id") != value["aws_account_id"]
        or inputs_value.get("aws_region") != value["aws_region"]
    ):
        raise ResumeError(
            "saved infrastructure inputs do not bind selected account and region"
        )
    continuation = value.get("continuation")
    if value["schema_version"] == 1:
        return value
    if continuation is None:
        if value["phase"] not in BASE_PHASES:
            raise ResumeError("continuation context is required after platform completion")
        return value
    allowed_continuation_keys = {
        frozenset(CONTINUATION_KEYS),
        frozenset(CONTINUATION_KEYS | AUDIT_CONTINUATION_KEYS),
        frozenset(CONTINUATION_KEYS | AUDIT_CONTINUATION_KEYS | {AUDIT_COMPLETION_KEY}),
        frozenset(CONTINUATION_KEYS | CUSTODY_CONTINUATION_KEYS),
        frozenset(CONTINUATION_KEYS | AUDIT_CONTINUATION_KEYS | CUSTODY_CONTINUATION_KEYS),
        frozenset(CONTINUATION_KEYS | AUDIT_CONTINUATION_KEYS | {AUDIT_COMPLETION_KEY} | CUSTODY_CONTINUATION_KEYS),
        frozenset(CONTINUATION_KEYS | CUSTODY_CONTINUATION_KEYS | {CUSTODY_COMPLETION_KEY}),
        frozenset(CONTINUATION_KEYS | AUDIT_CONTINUATION_KEYS | CUSTODY_CONTINUATION_KEYS | {CUSTODY_COMPLETION_KEY}),
        frozenset(CONTINUATION_KEYS | AUDIT_CONTINUATION_KEYS | {AUDIT_COMPLETION_KEY} | CUSTODY_CONTINUATION_KEYS | {CUSTODY_COMPLETION_KEY}),
        frozenset(CONTINUATION_KEYS | CUSTODY_CONTINUATION_KEYS | {CUSTODY_COMPLETION_KEY} | ACTIVATION_CONTINUATION_KEYS),
        frozenset(CONTINUATION_KEYS | AUDIT_CONTINUATION_KEYS | CUSTODY_CONTINUATION_KEYS | {CUSTODY_COMPLETION_KEY} | ACTIVATION_CONTINUATION_KEYS),
        frozenset(CONTINUATION_KEYS | AUDIT_CONTINUATION_KEYS | {AUDIT_COMPLETION_KEY} | CUSTODY_CONTINUATION_KEYS | {CUSTODY_COMPLETION_KEY} | ACTIVATION_CONTINUATION_KEYS),
        frozenset(CONTINUATION_KEYS | CUSTODY_CONTINUATION_KEYS | {CUSTODY_COMPLETION_KEY} | ACTIVATION_CONTINUATION_KEYS | {ACTIVATION_COMPLETION_KEY}),
        frozenset(CONTINUATION_KEYS | AUDIT_CONTINUATION_KEYS | CUSTODY_CONTINUATION_KEYS | {CUSTODY_COMPLETION_KEY} | ACTIVATION_CONTINUATION_KEYS | {ACTIVATION_COMPLETION_KEY}),
        frozenset(CONTINUATION_KEYS | AUDIT_CONTINUATION_KEYS | {AUDIT_COMPLETION_KEY} | CUSTODY_CONTINUATION_KEYS | {CUSTODY_COMPLETION_KEY} | ACTIVATION_CONTINUATION_KEYS | {ACTIVATION_COMPLETION_KEY}),
    }
    if not isinstance(continuation, dict) or frozenset(continuation) not in allowed_continuation_keys:
        raise ResumeError("resume continuation context is invalid")
    if (not isinstance(continuation["keystore_dir"], str)
            or not isinstance(continuation["public_key"], str)):
        raise ResumeError("resume continuation context is invalid")
    key_dir = Path(continuation["keystore_dir"])
    if (not key_dir.is_absolute() or key_dir.is_symlink() or not key_dir.is_dir()
            or not PUBLIC_KEY.fullmatch(continuation["public_key"])
            or type(continuation["keystore_device"]) is not int
            or type(continuation["keystore_inode"]) is not int):
        raise ResumeError("resume continuation context is invalid")
    info = key_dir.stat()
    if (info.st_dev, info.st_ino) != (continuation["keystore_device"], continuation["keystore_inode"]):
        raise ResumeError("saved keystore directory identity changed")
    for path_key, hash_key, fixed in (
        ("deposit_attestation_rel", "deposit_attestation_sha256", None),
        ("runtime_receipt_rel", "runtime_receipt_sha256", "custody-verifier-runtime/receipt.json"),
    ):
        relative = continuation[path_key]
        if (not isinstance(relative, str) or Path(relative).is_absolute() or ".." in Path(relative).parts
                or (fixed is not None and relative != fixed)):
            raise ResumeError("resume continuation path is invalid")
        bound = child(root, relative, True)
        if (bound.is_symlink() or not bound.is_file()
                or not isinstance(continuation[hash_key], str)
                or not re.fullmatch(r"[0-9a-f]{64}", continuation[hash_key])):
            raise ResumeError("resume continuation evidence is invalid")
        if hashlib.sha256(bound.read_bytes()).hexdigest() != continuation[hash_key]:
            raise ResumeError("resume continuation evidence changed")
    has_audit = AUDIT_CONTINUATION_KEYS <= set(continuation)
    if has_audit:
        if (not re.fullmatch(r"[0-9a-f]{32}", continuation["audit_operation_id"])
                or continuation["audit_receipt_rel"] != AUDIT_RECEIPT_REL):
            raise ResumeError("resume audit operation context is invalid")
    elif value["phase"] in ALL_PHASES[ALL_PHASES.index("audit-started"):]:
        raise ResumeError("resume audit operation context is required")
    has_audit_completion = AUDIT_COMPLETION_KEY in continuation
    if has_audit_completion:
        if (not re.fullmatch(r"[0-9a-f]{64}", continuation[AUDIT_COMPLETION_KEY]) or ALL_PHASES.index(value["phase"]) < ALL_PHASES.index("audit-complete")):
            raise ResumeError("resume audit completion context is invalid")
        validate_audit_completion(root, value, continuation)
    elif value["phase"] == "audit-complete":
        raise ResumeError("resume audit completion receipt is required")
    has_custody = CUSTODY_CONTINUATION_KEYS <= set(continuation)
    has_completion = CUSTODY_COMPLETION_KEY in continuation
    if has_custody:
        if (not isinstance(continuation["validator_set"], str)
                or not VALIDATOR_SET.fullmatch(continuation["validator_set"])
                or not isinstance(continuation["custody_operation_id"], str)
                or not re.fullmatch(r"[0-9a-f]{32}", continuation["custody_operation_id"])
                or continuation["custody_result_rel"] != CUSTODY_RESULT_REL):
            raise ResumeError("resume custody operation context is invalid")
    elif value["phase"] in ALL_PHASES[ALL_PHASES.index("custody-started"):]:
        raise ResumeError("resume custody operation context is required")
    if has_completion:
        if (not re.fullmatch(r"[0-9a-f]{64}", continuation[CUSTODY_COMPLETION_KEY])
                or ALL_PHASES.index(value["phase"]) < ALL_PHASES.index("custody-complete")):
            raise ResumeError("resume custody completion context is invalid")
    if ALL_PHASES.index(value["phase"]) >= ALL_PHASES.index("custody-complete"):
        if not has_completion:
            raise ResumeError("resume custody completion receipt is required")
        validate_custody_completion(root, continuation)
    has_activation = ACTIVATION_CONTINUATION_KEYS <= set(continuation)
    has_activation_completion = ACTIVATION_COMPLETION_KEY in continuation
    if has_activation:
        if (not isinstance(continuation["activation_operation_id"], str)
                or not re.fullmatch(r"[0-9a-f]{32}", continuation["activation_operation_id"])
                or continuation["activation_receipt_rel"] != ACTIVATION_RECEIPT_REL):
            raise ResumeError("resume activation operation context is invalid")
    if value["phase"] in ("activation-started", "activated", "observing", "complete") and not has_activation:
        raise ResumeError("resume activation operation context is required")
    if has_activation_completion:
        if (not has_activation or not re.fullmatch(r"[0-9a-f]{64}", continuation[ACTIVATION_COMPLETION_KEY])
                or ALL_PHASES.index(value["phase"]) < ALL_PHASES.index("activated")):
            raise ResumeError("resume activation completion context is invalid")
    if ALL_PHASES.index(value["phase"]) >= ALL_PHASES.index("activated"):
        if not has_activation_completion:
            raise ResumeError("resume activation receipt is required")
        validate_activation_completion(root, value, continuation)
    return value


def validate_custody_completion(root: Path, continuation: dict):
    result = child(root, CUSTODY_RESULT_REL, True)
    info = result.lstat()
    if (result.is_symlink() or not stat.S_ISREG(info.st_mode)
            or stat.S_IMODE(info.st_mode) != 0o600):
        raise ResumeError("custody completion receipt is unsafe")
    raw = result.read_bytes()
    if (CUSTODY_COMPLETION_KEY in continuation
            and hashlib.sha256(raw).hexdigest() != continuation[CUSTODY_COMPLETION_KEY]):
        raise ResumeError("custody completion receipt changed")
    try:
        receipt = json.loads(raw)
    except (OSError, json.JSONDecodeError) as e:
        raise ResumeError("custody completion receipt is invalid") from e
    expected = {
        "schema_version": 1,
        "operation_id": continuation["custody_operation_id"],
        "validator_set": continuation["validator_set"],
        "expected_public_key": continuation["public_key"],
        "result": "onboarding-complete",
    }
    outputs = receipt.get("public_outputs") if isinstance(receipt, dict) else None
    if (not isinstance(receipt, dict) or set(receipt) != set(expected) | {"public_outputs"}
            or type(receipt.get("schema_version")) is not int
            or not isinstance(outputs, dict)
            or set(outputs) != {"signer_ca_sha256", "known_clients_sha256"}
            or receipt.get("schema_version") != expected["schema_version"]
            or any(receipt.get(key) != expected[key] for key in expected if key != "schema_version")):
        raise ResumeError("custody completion receipt does not match the bound operation")
    for relative, key in (
        ("ceremony/signer-ca.crt", "signer_ca_sha256"),
        ("ceremony/known-clients.txt", "known_clients_sha256"),
    ):
        output = child(root, relative, True)
        if (output.is_symlink() or not output.is_file()
                or not isinstance(outputs.get(key), str)
                or not re.fullmatch(r"[0-9a-f]{64}", outputs[key])
                or hashlib.sha256(output.read_bytes()).hexdigest() != outputs[key]):
            raise ResumeError("custody public output does not match completion receipt")
    return hashlib.sha256(raw).hexdigest()

def validate_audit_completion(root: Path, value: dict, continuation: dict):
    receipt = child(root, AUDIT_RECEIPT_REL, True); info = receipt.lstat()
    if receipt.is_symlink() or not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600: raise ResumeError("audit completion receipt is unsafe")
    raw = receipt.read_bytes()
    if hashlib.sha256(raw).hexdigest() != continuation[AUDIT_COMPLETION_KEY]: raise ResumeError("audit completion receipt changed")
    record = strict_json(raw, "audit completion receipt")
    expected = {"schema_version":1,"result":"socket-audit-challenge-emitted-and-root-revoked","aws_account_id":value["aws_account_id"],"aws_region":value["aws_region"],"deployment_name":value["deployment_name"],"release_revision":value["release_revision"],"operation_id":continuation["audit_operation_id"]}
    if (not isinstance(record, dict) or set(record) != set(expected) | {"marker_hmac","request_id","after_ms"} or any(record.get(key) != wanted for key,wanted in expected.items()) or not re.fullmatch(r"hmac-sha256:[0-9a-f]{64}", record.get("marker_hmac", "")) or not re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", record.get("request_id", "")) or type(record.get("after_ms")) is not int or record["after_ms"] < 0): raise ResumeError("audit completion receipt is invalid")
    return hashlib.sha256(raw).hexdigest()


def validate_activation_completion(root: Path, value: dict, continuation: dict, require_bound_hash=True):
    receipt_path = child(root, ACTIVATION_RECEIPT_REL, True)
    parent_info = receipt_path.parent.lstat()
    if (receipt_path.parent.is_symlink() or not stat.S_ISDIR(parent_info.st_mode)
            or stat.S_IMODE(parent_info.st_mode) != 0o700
            or parent_info.st_uid != os.geteuid()
            or receipt_path.parent.resolve() != root.resolve() / "evidence"):
        raise ResumeError("activation receipt parent is unsafe")
    info = receipt_path.lstat()
    if (receipt_path.is_symlink() or not stat.S_ISREG(info.st_mode)
            or stat.S_IMODE(info.st_mode) != 0o600 or info.st_uid != os.geteuid()):
        raise ResumeError("activation receipt is unsafe")
    raw = receipt_path.read_bytes()
    if require_bound_hash and hashlib.sha256(raw).hexdigest() != continuation[ACTIVATION_COMPLETION_KEY]:
        raise ResumeError("activation receipt changed")
    receipt = strict_json(raw, "activation receipt")
    expected = {
        "schema_version": 1,
        "result": "activation-post-ready-head-bound",
        "scope": "post-Ready private Beacon head lower bound only; not duty, finalization, signature, or end-to-end proof",
        "validator_set": continuation["validator_set"],
        "validator_public_key": continuation["public_key"],
        "deployment_name": value["deployment_name"],
        "release_revision": value["release_revision"],
        "operation_id": continuation["activation_operation_id"],
    }
    if not isinstance(receipt, dict) or set(receipt) != set(expected) | {"controllers", "pods", "lease", "private_beacon"}:
        raise ResumeError("activation receipt does not match the bound operation")
    if (type(receipt.get("schema_version")) is not int
            or any(receipt.get(key) != wanted for key, wanted in expected.items())):
        raise ResumeError("activation receipt does not match the bound operation")
    controllers, pods, lease, beacon = (receipt.get(key) for key in ("controllers", "pods", "lease", "private_beacon"))
    if (not isinstance(controllers, dict) or set(controllers) != {"client_statefulset_uid", "fence_deployment_uid"}
            or not isinstance(pods, dict) or set(pods) != {"client_uid", "fence_uid"}
            or not isinstance(lease, dict) or set(lease) != {"uid", "holder_identity"}
            or not isinstance(beacon, dict) or set(beacon) != {"pod_uid", "validator_index", "head_slot"}):
        raise ResumeError("activation receipt identity is invalid")
    uid_values = (*controllers.values(), *pods.values(), *lease.values(), beacon["pod_uid"])
    if (any(not isinstance(item, str) or UID_TOKEN.fullmatch(item) is None for item in uid_values)
            or lease["holder_identity"] != pods["fence_uid"]
            or not isinstance(beacon["validator_index"], str)
            or not beacon["validator_index"].isdigit()
            or type(beacon["head_slot"]) is not int or beacon["head_slot"] < 0):
        raise ResumeError("activation receipt identity is invalid")
    return hashlib.sha256(raw).hexdigest()


def validator_handoff(root: Path, inputs: dict, public_key: str, validator_set: str):
    reference = inputs.get("validator_deployment_handoff")
    if not isinstance(reference, str) or not Path(reference).is_absolute():
        raise ResumeError("saved validator handoff is invalid")
    relative = rel(Path(reference), root)
    if relative != "inputs/validator-deployment/validator-deployment-handoff.json":
        raise ResumeError("saved validator handoff path is invalid")
    handoff = child(root, relative, True)
    if handoff.is_symlink() or not handoff.is_file():
        raise ResumeError("saved validator handoff is unavailable or unsafe")
    try:
        value = json.loads(handoff.read_text())
    except (OSError, json.JSONDecodeError) as e:
        raise ResumeError("saved validator handoff is invalid") from e
    handoff_key = value.get("validator_public_key") if isinstance(value, dict) else None
    if (not isinstance(handoff_key, str) or handoff_key.lower() != public_key
            or value.get("validator_set") != validator_set):
        raise ResumeError("custody validator set does not match the bound handoff")


def main():
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="op", required=True)
    r = sub.add_parser("record")
    r.add_argument("--work-dir", type=Path, required=True)
    r.add_argument("--manifest", type=Path, required=True)
    r.add_argument("--account", required=True)
    r.add_argument("--region", required=True)
    r.add_argument("--deployment", required=True)
    r.add_argument("--inputs", type=Path, required=True)
    r.add_argument("--work", type=Path, required=True)
    r.add_argument("--session", type=Path, required=True)
    q = sub.add_parser("read")
    q.add_argument("--work-dir", type=Path, required=True)
    q.add_argument("--manifest", type=Path, required=True)
    u = sub.add_parser("phase")
    u.add_argument("--work-dir", type=Path, required=True)
    u.add_argument("--manifest", type=Path, required=True)
    u.add_argument(
        "--phase",
        choices=(
            "infrastructure-complete",
            "platform-started",
            "platform-complete",
            "vault-started",
            "vault-complete",
            "collector-complete",
            "audit-started",
            "audit-complete",
            "custody-started",
            "custody-complete",
            "runtime-complete",
            "activation-pending",
            "activation-started",
            "activated",
            "observing",
            "complete",
        ),
        required=True,
    )
    b = sub.add_parser("bind-continuation")
    b.add_argument("--work-dir", type=Path, required=True)
    b.add_argument("--manifest", type=Path, required=True)
    b.add_argument("--keystore-dir", type=Path, required=True)
    b.add_argument("--public-key", required=True)
    b.add_argument("--deposit-attestation", type=Path, required=True)
    c = sub.add_parser("prepare-custody")
    c.add_argument("--work-dir", type=Path, required=True)
    c.add_argument("--manifest", type=Path, required=True)
    c.add_argument("--validator-set", required=True)
    z = sub.add_parser("reconcile-custody-complete")
    z.add_argument("--work-dir", type=Path, required=True)
    z.add_argument("--manifest", type=Path, required=True)
    ac = sub.add_parser("reconcile-audit-complete")
    ac.add_argument("--work-dir", type=Path, required=True)
    ac.add_argument("--manifest", type=Path, required=True)
    aa = sub.add_parser("prepare-audit")
    aa.add_argument("--work-dir", type=Path, required=True)
    aa.add_argument("--manifest", type=Path, required=True)
    ap = sub.add_parser("prepare-activation")
    ap.add_argument("--work-dir", type=Path, required=True)
    ap.add_argument("--manifest", type=Path, required=True)
    ar = sub.add_parser("reconcile-activation")
    ar.add_argument("--work-dir", type=Path, required=True)
    ar.add_argument("--manifest", type=Path, required=True)
    a = p.parse_args()
    try:
        if a.op == "record":
            safe_dir(a.work_dir)
            if (a.work_dir / "interactive-resume.json").exists():
                raise ResumeError("resume receipt already exists; refusing reset")
            input_value = json.loads(a.inputs.read_text())
            if (
                not isinstance(input_value, dict)
                or input_value.get("aws_account_id") != a.account
                or input_value.get("aws_region") != a.region
            ):
                raise ResumeError("inputs do not bind selected account and region")
            manifest_hash, revision = manifest_identity(a.manifest)
            value = {
                "schema_version": 2,
                "bundle_manifest_sha256": manifest_hash,
                "release_revision": revision,
                "inputs_sha256": hashlib.sha256(a.inputs.read_bytes()).hexdigest(),
                "aws_account_id": a.account,
                "aws_region": a.region,
                "deployment_name": a.deployment,
                "inputs_rel": rel(a.inputs, a.work_dir),
                "work_rel": rel(a.work, a.work_dir),
                "session_rel": rel(a.session, a.work_dir),
                "phase": "infrastructure",
                "continuation": None,
            }
            if (value["inputs_rel"], value["work_rel"], value["session_rel"]) != (
                "inputs/hoodi-zero-release-inputs.json",
                "deployment-work",
                "private-eks-session.json",
            ):
                raise ResumeError("record paths must be fixed infrastructure paths")
            write(a.work_dir / "interactive-resume.json", value)
        elif a.op == "read":
            print(json.dumps(read(a.work_dir, a.manifest), sort_keys=True))
        elif a.op == "bind-continuation":
            value = read(a.work_dir, a.manifest)
            if value.get("schema_version") != 2 or value["phase"] != "platform-complete" or value.get("continuation") is not None:
                raise ResumeError("continuation context cannot be implicitly replaced or bound at this phase")
            public_key = a.public_key.lower()
            if not PUBLIC_KEY.fullmatch(public_key):
                raise ResumeError("continuation public key is invalid")
            if not a.keystore_dir.is_absolute() or a.keystore_dir.is_symlink() or not a.keystore_dir.is_dir():
                raise ResumeError("continuation keystore directory is invalid")
            keystore_dir = a.keystore_dir.resolve(strict=True)
            attestation_rel = rel(a.deposit_attestation, a.work_dir)
            attestation = child(a.work_dir, attestation_rel, True)
            if attestation.is_symlink() or not attestation.is_file():
                raise ResumeError("continuation deposit attestation is invalid")
            runtime_rel = "custody-verifier-runtime/receipt.json"
            runtime_receipt = child(a.work_dir, runtime_rel, True)
            if runtime_receipt.is_symlink() or not runtime_receipt.is_file():
                raise ResumeError("continuation custody runtime receipt is invalid")
            metadata = keystore_dir.stat()
            value["continuation"] = {
                "keystore_dir": str(keystore_dir), "keystore_device": metadata.st_dev,
                "keystore_inode": metadata.st_ino, "public_key": public_key,
                "deposit_attestation_rel": attestation_rel,
                "deposit_attestation_sha256": hashlib.sha256(attestation.read_bytes()).hexdigest(),
                "runtime_receipt_rel": runtime_rel,
                "runtime_receipt_sha256": hashlib.sha256(runtime_receipt.read_bytes()).hexdigest(),
            }
            write(a.work_dir / "interactive-resume.json", value)
        elif a.op == "prepare-custody":
            value = read(a.work_dir, a.manifest)
            if (value.get("schema_version") != 2
                    or value["phase"] not in ("platform-complete", "vault-complete", "audit-complete")
                    or not isinstance(value.get("continuation"), dict)):
                raise ResumeError("custody operation cannot be prepared at this phase")
            continuation = value["continuation"]
            validator_handoff(
                a.work_dir, json.loads(child(a.work_dir, value["inputs_rel"], True).read_text()),
                continuation["public_key"], a.validator_set,
            )
            result = child(a.work_dir, CUSTODY_RESULT_REL, False)
            parent_info = result.parent.lstat()
            if (result.parent.is_symlink() or not stat.S_ISDIR(parent_info.st_mode)
                    or stat.S_IMODE(parent_info.st_mode) != 0o700):
                raise ResumeError("custody completion receipt parent is unavailable or unsafe")
            if result.exists() or result.is_symlink():
                raise ResumeError("custody completion receipt already exists")
            existing = CUSTODY_CONTINUATION_KEYS <= set(continuation)
            if existing:
                if continuation["validator_set"] != a.validator_set:
                    raise ResumeError("custody operation cannot be implicitly replaced")
            else:
                continuation.update({
                    "validator_set": a.validator_set,
                    "custody_operation_id": secrets.token_hex(16),
                    "custody_result_rel": CUSTODY_RESULT_REL,
                })
                write(a.work_dir / "interactive-resume.json", value)
            print(json.dumps({
                "operation_id": continuation["custody_operation_id"],
                "public_key": continuation["public_key"],
                "result_output": str(a.work_dir / CUSTODY_RESULT_REL),
                "validator_set": continuation["validator_set"],
            }, sort_keys=True))
        elif a.op == "prepare-audit":
            value = read(a.work_dir, a.manifest)
            if value["phase"] != "collector-complete" or not isinstance(value.get("continuation"), dict):
                raise ResumeError("audit operation cannot be prepared at this phase")
            continuation = value["continuation"]
            receipt = child(a.work_dir, AUDIT_RECEIPT_REL, False)
            parent_info = receipt.parent.lstat()
            if (receipt.parent.is_symlink() or not stat.S_ISDIR(parent_info.st_mode)
                    or stat.S_IMODE(parent_info.st_mode) != 0o700 or receipt.exists() or receipt.is_symlink()):
                raise ResumeError("audit completion receipt target is unavailable or unsafe")
            if AUDIT_CONTINUATION_KEYS <= set(continuation):
                if (not re.fullmatch(r"[0-9a-f]{32}", continuation["audit_operation_id"])
                        or continuation["audit_receipt_rel"] != AUDIT_RECEIPT_REL):
                    raise ResumeError("resume audit operation context is invalid")
            else:
                continuation.update({"audit_operation_id": secrets.token_hex(16), "audit_receipt_rel": AUDIT_RECEIPT_REL})
                write(a.work_dir / "interactive-resume.json", value)
            print(json.dumps({"operation_id": continuation["audit_operation_id"], "receipt_output": str(receipt)}, sort_keys=True))
        elif a.op == "reconcile-audit-complete":
            value = read(a.work_dir, a.manifest)
            if value["phase"] != "audit-started": raise ResumeError("audit completion cannot be reconciled at this phase")
            continuation = value.get("continuation")
            if not isinstance(continuation, dict) or not AUDIT_CONTINUATION_KEYS <= set(continuation): raise ResumeError("resume audit operation context is required")
            receipt = child(a.work_dir, AUDIT_RECEIPT_REL, True)
            continuation[AUDIT_COMPLETION_KEY] = hashlib.sha256(receipt.read_bytes()).hexdigest()
            validate_audit_completion(a.work_dir, value, continuation)
            value["phase"] = "audit-complete"; write(a.work_dir / "interactive-resume.json", value)
        elif a.op == "reconcile-custody-complete":
            value = read(a.work_dir, a.manifest)
            if value["phase"] != "custody-started":
                raise ResumeError("custody completion cannot be reconciled at this phase")
            continuation = value.get("continuation")
            if not isinstance(continuation, dict) or not CUSTODY_CONTINUATION_KEYS <= set(continuation):
                raise ResumeError("resume custody operation context is required")
            completion_hash = validate_custody_completion(a.work_dir, continuation)
            continuation[CUSTODY_COMPLETION_KEY] = completion_hash
            value["phase"] = "custody-complete"
            write(a.work_dir / "interactive-resume.json", value)
        elif a.op == "prepare-activation":
            value = read(a.work_dir, a.manifest)
            if value["phase"] != "activation-pending":
                raise ResumeError("activation operation cannot be prepared at this phase")
            continuation = value.get("continuation")
            if not isinstance(continuation, dict) or not CUSTODY_CONTINUATION_KEYS <= set(continuation):
                raise ResumeError("resume custody operation context is required before activation")
            receipt = child(a.work_dir, ACTIVATION_RECEIPT_REL, False)
            parent_info = receipt.parent.lstat()
            if (receipt.parent.is_symlink() or not stat.S_ISDIR(parent_info.st_mode)
                    or stat.S_IMODE(parent_info.st_mode) != 0o700
                    or parent_info.st_uid != os.geteuid()
                    or receipt.parent.resolve() != a.work_dir.resolve() / "evidence"):
                raise ResumeError("activation receipt parent is unavailable or unsafe")
            if receipt.exists() or receipt.is_symlink():
                raise ResumeError("activation receipt already exists; reconcile it instead")
            existing = ACTIVATION_CONTINUATION_KEYS <= set(continuation)
            if not existing:
                continuation.update({
                    "activation_operation_id": secrets.token_hex(16),
                    "activation_receipt_rel": ACTIVATION_RECEIPT_REL,
                })
                write(a.work_dir / "interactive-resume.json", value)
            print(json.dumps({
                "deployment_name": value["deployment_name"],
                "operation_id": continuation["activation_operation_id"],
                "receipt_output": str(a.work_dir / ACTIVATION_RECEIPT_REL),
                "release_revision": value["release_revision"],
            }, sort_keys=True))
        elif a.op == "reconcile-activation":
            value = read(a.work_dir, a.manifest)
            if value["phase"] != "activation-started":
                raise ResumeError("activation cannot be reconciled at this phase")
            continuation = value.get("continuation")
            if not isinstance(continuation, dict) or not ACTIVATION_CONTINUATION_KEYS <= set(continuation):
                raise ResumeError("resume activation operation context is required")
            completion_hash = validate_activation_completion(a.work_dir, value, continuation, require_bound_hash=False)
            continuation[ACTIVATION_COMPLETION_KEY] = completion_hash
            value["phase"] = "activated"
            write(a.work_dir / "interactive-resume.json", value)
        else:
            value = read(a.work_dir, a.manifest)
            current = value["phase"]
            if current not in ALL_PHASES or ALL_PHASES.index(a.phase) != ALL_PHASES.index(current) + 1:
                raise ResumeError(
                    "resume phase transition is uncertain or already complete"
                )
            if a.phase in CONTINUATION_PHASES and value.get("continuation") is None:
                raise ResumeError("continuation context is required before custody lifecycle transitions")
            if a.phase == "custody-complete":
                raise ResumeError("custody completion requires its bound completion receipt")
            if a.phase == "audit-started":
                continuation = value.get("continuation")
                if not isinstance(continuation, dict) or not AUDIT_CONTINUATION_KEYS <= set(continuation):
                    raise ResumeError("audit operation must be prepared before it starts")
            if a.phase == "audit-complete":
                raise ResumeError("audit completion requires its bound completion receipt")
            if a.phase == "activated":
                raise ResumeError("activation completion requires its bound lower-bound receipt")
            if a.phase == "activation-started":
                continuation = value.get("continuation")
                if not isinstance(continuation, dict) or not ACTIVATION_CONTINUATION_KEYS <= set(continuation):
                    raise ResumeError("activation operation must be prepared before it starts")
            value["phase"] = a.phase
            write(a.work_dir / "interactive-resume.json", value)
    except (OSError, json.JSONDecodeError, ResumeError) as e:
        print("resume: " + str(e), file=sys.stderr)
        return 65
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
