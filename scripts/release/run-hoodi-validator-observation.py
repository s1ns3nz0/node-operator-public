#!/usr/bin/env python3
"""Resume post-activation duty observation; never initialize, deposit or activate.

Internal entrypoint: the release caller verifies its bundle and live private
EKS session before invoking this program inside the selected tunnel. A zero
exit proves the requested finalized-duty threshold, configured AWS delivery metadata, and the
resume-bound Vault audit challenge correlation; deployment completion remains
the caller's lifecycle decision.
"""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import tempfile
import time
from urllib.request import Request, build_opener, ProxyHandler, HTTPRedirectHandler

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from validator_observation_context import load_context, ContextError
from validator_audit_reader_pod import ReaderPod, ReaderPodError


def module(filename):
    spec = importlib.util.spec_from_file_location(filename, HERE / filename)
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value)
    return value


collector = module("collect-hoodi-finalized-attestation-evidence.py")
observer = module("observe-hoodi-finalized-attestations.py")
operational_delivery = module("operational_log_delivery.py")
registration = module("verify-existing-hoodi-validator.py")
chain_emf = module("validator_monitoring_chain.py")
vault_audit_reader = module("vault_audit_archive_reader.py")


class Pending(RuntimeError): pass


_AUDIT_MARKER = re.compile(r"hmac-sha256:[0-9a-f]{64}\Z")
_AUDIT_REQUEST = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\Z")
_AUDIT_LOG_GROUP = re.compile(r"/aws/eks/[a-z][a-z0-9-]{1,38}[a-z0-9]/validator-security\Z")


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise Pending("private Beacon redirect refused")


class PrivateBeaconSession:
    """Own a localhost forward; callers recheck Pod UID around observations.

    The kubectl announcement establishes tunnel setup only. Beacon health and
    chain identity are checked by subsequent API reads. UID readbacks bracket
    a pass; they are not continuous monitoring or container-restart detection.
    The entrypoint validates the port and its caller supplies the verified
    private-cluster kubeconfig.
    """
    def __init__(self, port):
        self.port, self.process, self.log = port, None, None
        self.url = f"http://127.0.0.1:{port}"

    def pod_uid(self):
        result = subprocess.run(["kubectl", "-n", "node-operator", "get", "pod", "prysm-beacon-0", "-o", "json"],
                                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=20, check=True)
        pod = json.loads(result.stdout)
        meta = pod.get("metadata", {})
        if (meta.get("name") != "prysm-beacon-0" or meta.get("namespace") != "node-operator"
                or not isinstance(meta.get("uid"), str) or not meta["uid"]
                or not any(row.get("type") == "Ready" and row.get("status") == "True" for row in pod.get("status", {}).get("conditions", []))):
            raise Pending("private Beacon Pod is not Ready")
        return meta["uid"]

    def __enter__(self):
        self.uid = self.pod_uid()
        self.log = tempfile.TemporaryFile()
        try:
            self.process = subprocess.Popen(["kubectl", "-n", "node-operator", "port-forward", "--address=127.0.0.1", "pod/prysm-beacon-0", f"{self.port}:3500"],
                                            stdin=subprocess.DEVNULL, stdout=self.log, stderr=subprocess.DEVNULL)
            deadline = time.monotonic() + 15
            expected = f"Forwarding from 127.0.0.1:{self.port} -> 3500".encode()
            while time.monotonic() < deadline:
                if self.process.poll() is not None: raise Pending("private Beacon tunnel exited")
                self.log.seek(0)
                if expected in self.log.read(4096):
                    self.verify(); return self
                time.sleep(.2)
            raise Pending("private Beacon tunnel readiness timed out")
        except BaseException:
            self.close(); raise

    def verify(self):
        if self.process.poll() is not None or self.pod_uid() != self.uid:
            raise Pending("private Beacon identity changed during observation")

    def request(self, path, payload=None):
        data = None if payload is None else json.dumps(payload).encode()
        request = Request(self.url + path, data=data, headers={"Accept":"application/json", "Content-Type":"application/json"})
        with build_opener(ProxyHandler({}), NoRedirect()).open(request, timeout=10) as response:
            if response.status != 200: raise Pending("private Beacon request was unavailable")
            raw = response.read(1024 * 1024 + 1)
        if len(raw) > 1024 * 1024: raise Pending("private Beacon response exceeded bound")
        return json.loads(raw, object_pairs_hook=collector.no_duplicates)

    def close(self):
        try:
            if self.process is not None:
                self.process.terminate()
                try: self.process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self.process.kill(); self.process.wait(timeout=5)
        finally:
            if self.log is not None: self.log.close()

    def __exit__(self, kind, error, trace):
        self.close()


def private_directory(path):
    if path.is_symlink(): raise Pending("observation directory is unsafe")
    path.mkdir(mode=0o700, exist_ok=True)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700 or info.st_uid != os.geteuid():
        raise Pending("observation directory is unsafe")


def assignments(session, identity, directory):
    sync = session.request("/eth/v1/node/syncing")["data"]
    if any(sync.get(key) is not False for key in ("is_syncing", "is_optimistic", "el_offline")):
        raise Pending("private execution/consensus pair is not synchronized")
    head = sync.get("head_slot")
    if not isinstance(head, str) or not head.isdigit(): raise Pending("private Beacon head is invalid")
    current = int(head) // 32
    groups = {}
    fields = {"pubkey", "validator_index", "committee_index", "committee_length", "committees_at_slot", "validator_committee_index", "slot"}
    for epoch in (current, current + 1):
        response = session.request(f"/eth/v1/validator/duties/attester/{epoch}", [identity["validator_index"]])
        if response.get("execution_optimistic") is not False or not isinstance(response.get("data"), list):
            raise Pending("private attester assignments unavailable")
        rows = response["data"]
        if len(rows) > 1: raise Pending("private attester assignments ambiguous")
        selected = []
        for row in rows:
            if (not isinstance(row, dict) or not fields <= set(row)
                    or row["pubkey"] != identity["validator_public_key"] or row["validator_index"] != identity["validator_index"]
                    or any(not isinstance(row[key], str) or not row[key].isdigit() for key in fields - {"pubkey"})
                    or int(row["slot"]) // 32 != epoch):
                raise Pending("private attester assignment identity mismatch")
            selected.append({key:row[key] for key in fields})
        groups[str(epoch)] = {"epoch":epoch, "attester":selected}
    record = {"schema_version":1, "event_type":"uc-4", "network":"hoodi", "source":"private-beacon",
              "validator_set":identity["validator_set"], "validator_public_key":identity["validator_public_key"],
              "payload":{"validator_index":identity["validator_index"], "observation_status":"assignments-observed",
                         "signed_outcomes_observed":False, "queried_epochs":[current,current + 1], "assignments":groups}}
    session.verify()
    path = directory / f"assignments-{current}.json"
    # Reuse identical epoch snapshots, avoiding a new provenance entry on
    # every poll. Conflicting snapshots are not silently overwritten.
    if path.exists():
        if collector.load(path) != record: raise Pending("private assignments changed; preserve prior snapshot")
    else: collector.write(path, record)
    return path


def verify_reader_role(transport, role_arn, account, region):
    raw = transport._exec(["aws", "sts", "get-caller-identity", "--region", region, "--output", "json", "--no-cli-pager"])
    value = json.loads(raw, object_pairs_hook=collector.no_duplicates)
    expected = f"arn:aws:sts::{account}:assumed-role/{role_arn.rsplit('/', 1)[-1]}/"
    if value.get("Account") != account or not isinstance(value.get("Arn"), str) or not value["Arn"].startswith(expected):
        raise Pending("reader PodIdentity does not match the deployment reader role")


def verify_vault_audit(transport, context, reader, directory, verifier=vault_audit_reader.verify):
    """Correlate the resume-bound Vault challenge through the existing reader Pod.

    The cursor retains only a hash of the challenge binding plus opaque archive
    continuation state. It is never accepted across a new challenge receipt.
    """
    challenge, log_group = context.get("audit_challenge"), context.get("vault_security_log_group")
    if (not isinstance(challenge, dict) or set(challenge) != {"marker_hmac", "after_ms", "request_id"}
            or not isinstance(challenge["marker_hmac"], str) or not _AUDIT_MARKER.fullmatch(challenge["marker_hmac"])
            or type(challenge["after_ms"]) is not int or challenge["after_ms"] < 0
            or not isinstance(challenge["request_id"], str) or not _AUDIT_REQUEST.fullmatch(challenge["request_id"])
            or not isinstance(log_group, str) or not _AUDIT_LOG_GROUP.fullmatch(log_group)):
        raise Pending("validated Vault audit challenge context is unavailable")
    scope = hashlib.sha256(json.dumps(challenge, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    cursor_path = directory / "vault-audit-cursor.json"
    token, matches = None, None
    if cursor_path.exists():
        try:
            cursor = collector.load(cursor_path)
            if not isinstance(cursor, dict) or set(cursor) != {"schema_version", "scope", "continuation_token", "matches"}:
                raise ValueError()
            if cursor["schema_version"] == 1 and cursor["scope"] == scope:
                token, matches = cursor["continuation_token"], cursor["matches"]
        except (OSError, ValueError, KeyError, TypeError):
            pass
    try:
        result = verifier(transport, reader["bucket"], reader["prefix"], context["aws_region"], context["aws_account_id"],
                          log_group, challenge["marker_hmac"], challenge["after_ms"], reader["kms_key_arn"], token, matches)
    except Exception as error:
        raise Pending("Vault audit archive correlation is unavailable") from error
    if not isinstance(result, dict) or result.get("state") not in {"pending", "matched"}:
        raise Pending("Vault audit archive correlation is invalid")
    if result["state"] == "pending":
        if set(result) != {"state", "continuation_token", "matches"}:
            raise Pending("Vault audit archive correlation is invalid")
        collector.write(cursor_path, {"schema_version": 1, "scope": scope,
                                      "continuation_token": result["continuation_token"], "matches": result["matches"]})
        return {"state": "pending", "reason": "archive-correlation-pending"}
    required = {"state", "bucket", "key", "version_id", "event_id", "request_id", "timestamp_ms"}
    if set(result) != required or result["request_id"] != challenge["request_id"]:
        return {"state": "pending", "reason": "request-id-mismatch"}
    proof = {key: result[key] for key in ("bucket", "key", "version_id", "event_id", "request_id", "timestamp_ms")}
    collector.write(directory / "vault-audit-correlation.json", {"schema_version": 1, **proof})
    return {"state": "matched", **proof}


def observe_once(context, work_dir, public_url, port, beacon_factory=PrivateBeaconSession, reader_factory=ReaderPod,
                 observer_function=observer.observe, emit_emf=None, vault_audit_verifier=vault_audit_reader.verify):
    identity, reader = context["identity"], context["reader"]
    directory = work_dir / "evidence/observation"; private_directory(directory)
    workload, delivery = directory / "workload.json", directory / "delivery.json"
    with beacon_factory(port) as beacon:
        assignment = assignments(beacon, identity, directory)
        with reader_factory(image=reader["image"], bucket=reader["bucket"], region=context["aws_region"],
                            namespace=reader["namespace"], service_account=reader["service_account"], prefix=reader["prefix"], active_deadline=600) as transport:
            verify_reader_role(transport, reader["role_arn"], context["aws_account_id"], context["aws_region"])
            arguments = ["--assignment-proof", str(assignment), "--archive-bucket", reader["bucket"], "--archive-prefix", reader["prefix"],
                         "--aws-region", context["aws_region"], "--workload-output", str(workload), "--log-delivery-output", str(delivery),
                         "--archive-cursor", str(directory / "archive-cursor.json")]
            for key, value in identity.items(): arguments += ["--" + key.replace("_", "-"), value]
            result = collector.main(arguments, runner=transport)
            if result not in (0, 75): raise Pending("archive collection failed; no duty accepted")
            cursor_path = directory / "operational-delivery-cursor.json"
            cursor = collector.load(cursor_path) if cursor_path.exists() else None
            since_ms = (registration.HOODI_GENESIS_TIME + int(identity["activation_slot"]) * 12) * 1000
            metadata = operational_delivery.verify(context["operational_log_delivery"], since_ms, int(time.time() * 1000), transport, cursor)
            collector.write(directory / "operational-delivery.json", metadata)
            collector.write(cursor_path, metadata["cursor"])
            vault_audit = verify_vault_audit(transport, context, reader, directory, vault_audit_verifier)
        beacon.verify()
        if result == 75:
            if emit_emf is not None:
                emit_emf(context, None, False)
            return 75, {"reason":"waiting for delivered signer/fence logs", "consecutive_finalized_epochs":[],
                        "operational_log_delivery":metadata}
        rc, proof = observer_function(directory, identity, beacon.url, public_url, workload, delivery, 10)
        # The second identity/readiness bracket must succeed before a fresh
        # result is eligible for local EMF emission.
        beacon.verify()
        if emit_emf is not None:
            emit_emf(context, proof, True)
        proof["duties_complete"] = rc == 0
        proof["operational_log_delivery"] = metadata
        proof["vault_audit"] = vault_audit
        if metadata["result"] != "PASS_OPERATIONAL_METADATA" or vault_audit["state"] != "matched": rc = 75
        return rc, proof


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--bundle-root", required=True, type=Path)
    parser.add_argument("--work-dir", required=True, type=Path)
    parser.add_argument("--public-beacon-url", required=True)
    parser.add_argument("--private-beacon-port", type=int, default=19501)
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--continuous", action="store_true")
    parser.add_argument("--required-finalized-epochs", type=int, choices=(1, 2, 3), default=3)
    parser.add_argument("--emit-emf", action="store_true", help="print local EMF JSON; does not ingest CloudWatch")
    args = parser.parse_args()
    def interrupted(signum, frame):
        raise KeyboardInterrupt()
    for signum in (signal.SIGTERM, signal.SIGHUP): signal.signal(signum, interrupted)
    try:
        if args.once and args.continuous:
            raise Pending("--once and --continuous cannot be combined")
        if os.environ.get("PRIVATE_EKS_SESSION") != "1" or not 1024 <= args.private_beacon_port <= 65535:
            raise Pending("verified private EKS session is required")
        public = observer.validate_url(args.public_beacon_url, True)
        def emit(result_context, result, available):
            if args.emit_emf:
                print(json.dumps(chain_emf.render(result_context, result, available, int(time.time() * 1000)), sort_keys=True), flush=True)
        while True:
            context = load_context(args.bundle_root, args.work_dir)
            try:
                rc, result = observe_once(context, args.work_dir, public, args.private_beacon_port,
                                          observer_function=lambda *values: observer.observe(*values, required_count=args.required_finalized_epochs),
                                          emit_emf=emit)
            except (Pending, ReaderPodError, observer.ObservationError, OSError, ValueError, KeyError, subprocess.SubprocessError):
                if not args.continuous:
                    raise
                emit(context, None, False)
                # Never repeat a prior PASS on a failed fresh collection. The
                # redacted state is intentionally not a finalized-duty claim.
                print(json.dumps({"scope":"finalized duties, Vault audit correlation, and AWS delivery metadata; deployment completion is separate",
                                  "epochs":[], "pending_log_sources":[], "complete":False, "state":"unavailable"}), flush=True)
                time.sleep(30)
                continue
            epochs = result.get("consecutive_finalized_epochs", [])
            print(json.dumps({"scope":"finalized duties, Vault audit correlation, and AWS delivery metadata; deployment completion is separate",
                              "epochs":epochs, "pending_log_sources":result.get("operational_log_delivery", {}).get("pending", []),
                              "complete":rc == 0, "state":"verified" if rc == 0 else "pending",
                              "timestamp_ms":int(time.time() * 1000), "required_finalized_epochs":args.required_finalized_epochs}), flush=True)
            if not args.continuous and (rc == 0 or args.once): return rc
            print(f"PENDING: waiting for {args.required_finalized_epochs} consecutive finalized duties, archived signer/fence logs, Vault audit correlation and AWS delivery metadata; retrying in 30 seconds", file=sys.stderr, flush=True)
            time.sleep(30)
    except KeyboardInterrupt:
        print("PENDING: observation interrupted; resume this WORK_DIR without reactivation", file=sys.stderr); return 75
    except ContextError as error:
        # A rejected bundle/work-directory contract is not a transient health
        # state and must not be hidden by continuous retry.
        print(f"PENDING: {error}; retain this WORK_DIR and reconcile configuration", file=sys.stderr); return 75
    except (Pending, ReaderPodError) as error:
        print(f"PENDING: {error}; retain this WORK_DIR and retry without reactivation", file=sys.stderr); return 75
    except (observer.ObservationError, OSError, ValueError, KeyError, subprocess.SubprocessError):
        print("PENDING: observation could not be verified; retain this WORK_DIR and retry without reactivation", file=sys.stderr); return 75


if __name__ == "__main__": raise SystemExit(main())
