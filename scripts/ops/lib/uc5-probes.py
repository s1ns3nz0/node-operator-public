"""Concrete bounded UC-5 probe operations. Imported code performs no live work.

Only fixed GET/TCP diagnostics, read-only slashing-table fingerprints and
metadata-only audit evidence are supported. No signing request is generated.
"""
import datetime as dt
import importlib.util
import ipaddress
import json
import os
import pathlib
import re
import stat
import time
import uuid

HERE = pathlib.Path(__file__).resolve().parent
def module(name, path=None):
    spec = importlib.util.spec_from_file_location(name, path or HERE / (name + ".py"))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value
STATE = module("uc5-kube-state")
GUARDS = module("uc5-live-guards")
CONTROL = module("uc5-kube-control")
AUDIT = module("uc5-audit-proof")
RENDER = module("renderer", HERE.parent / "render-validator-runtime-probes.py")
NS = "validator-operations"
TLS_IMAGE = "123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/node-operator-baseline-validator-signer-identity-probe@sha256:11212189c98afaeb719eaaa8ac7d3c86179884c84986c97c9c1a35b6b4f4ec8f"
TCP_IMAGE = "123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/node-operator-baseline-node-runtime-upcheck-python@sha256:fb305627ba331d70f8cc82509a4fae4be858422fd257e170543fbbefcefb9588"
TABLES = ("validators", "signed_attestations", "signed_blocks", "low_watermarks", "metadata", "database_version")
TCP_CODE = '''import socket,json,sys,ipaddress
mode=sys.argv[1]
host="validator-hoodi-example-remote-signer-direct.validator-operations.svc"
try:
 addresses={x[4][0] for x in socket.getaddrinfo(host,9000,type=socket.SOCK_STREAM)}
 if not addresses or any(ipaddress.ip_address(a) not in ipaddress.ip_network("10.80.0.0/16") for a in addresses): raise ValueError()
 try:
  connection=socket.create_connection((host,9000),timeout=5);connection.close()
 except TimeoutError:
  if mode!="negative": raise
  print(json.dumps({"result":"NETWORK_DENIED_TIMEOUT"}));sys.exit(0)
 if mode!="positive": raise ValueError()
 print(json.dumps({"result":"TCP_CONTROL_SUCCESS"}))
except Exception:
 print(json.dumps({"result":"INCONCLUSIVE"}));sys.exit(1)
'''

class ProbeError(RuntimeError):
    pass

def utc():
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")

def tcp_manifest(mode, run):
    if mode not in ("positive", "negative"):
        raise ProbeError("unsupported network case")
    component = "validator-client" if mode == "negative" else "validator-signing-fence"
    return {"apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": "uc5-tcp-" + mode + "-" + run, "namespace": NS,
                         "labels": {"app.kubernetes.io/component": component, "node-operator.io/validator-set": "hoodi-example"},
                         "annotations": {"node-operator.io/probe-owner": run}},
            "spec": {"restartPolicy": "Never", "activeDeadlineSeconds": 40,
                     "automountServiceAccountToken": False, "enableServiceLinks": False,
                     "readinessGates": [{"conditionType": "node-operator.io/never-ready-runtime-diagnostic"}],
                     "securityContext": {"runAsNonRoot": True, "runAsUser": 1000, "runAsGroup": 1000,
                                         "seccompProfile": {"type": "RuntimeDefault"}},
                     "containers": [{"name": "tcp-probe", "image": TCP_IMAGE,
                                     "command": ["python3", "-c"], "args": [TCP_CODE, mode],
                                     "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                                         "privileged": False, "capabilities": {"drop": ["ALL"]}},
                                     "resources": {"requests": {"cpu": "10m", "memory": "32Mi"},
                                                   "limits": {"cpu": "100m", "memory": "64Mi"}}}]}}

class ProbeService:
    def __init__(self, control, public_key, evidence_directory, *, runner=CONTROL.kubectl,
                 audit_reader=None, beacon_reader=None, audit_hmac_reader=None,
                 clock=time.monotonic, sleep=time.sleep):
        if not STATE.PUBKEY.fullmatch(public_key): raise ProbeError("public identity invalid")
        self.control, self.key, self.runner = control, public_key, runner
        self.directory = pathlib.Path(evidence_directory)
        info = self.directory.lstat()
        if (not self.directory.is_absolute() or not stat.S_ISDIR(info.st_mode) or
                info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o022):
            raise ProbeError("private operator-owned evidence directory required")
        self.directory_identity = (info.st_dev, info.st_ino)
        self.audit_reader, self.beacon_reader = audit_reader, beacon_reader
        self.audit_hmac_reader = audit_hmac_reader
        self.clock, self.sleep = clock, sleep
        self.baseline = None
        self.absent_at = None

    def _get(self, kind, name):
        return self.runner(["-n", NS, "get", kind, name, "--ignore-not-found", "-o", "json"])

    def _live(self):
        return STATE.collect_live(lambda args: self.runner(list(args)), self.baseline)

    def _wait(self, predicate, seconds=150):
        deadline = self.clock() + seconds
        while True:
            value = predicate()
            if value: return value
            if self.clock() >= deadline: raise ProbeError("bounded observation did not complete")
            self.sleep(2)

    def _save(self, name, value):
        if pathlib.Path(name).name != name: raise ProbeError("evidence filename invalid")
        directory_fd = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            info = os.fstat(directory_fd)
            if (info.st_dev, info.st_ino) != self.directory_identity:
                raise ProbeError("evidence directory identity changed")
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory_fd)
            with os.fdopen(fd, "w") as handle:
                json.dump(value, handle, sort_keys=True)
                handle.write("\n")
        finally:
            os.close(directory_fd)

    def _quiesced(self):
        live = self._live()
        return all(live["controllers"][x]["spec_replicas"] == 0 and
                   live["controllers"][x]["status_replicas"] == 0 and not live["matching_pods"][x]
                   for x in ("client", "fence"))

    def wait_signer_absent(self, baseline):
        self.baseline = baseline
        def absent():
            if self.control.assert_maintenance_lock() is not True:
                raise ProbeError("maintenance lock lost")
            live = self._live()
            signer = live["controllers"]["signer"]
            return (signer["uid"] == baseline["controllers"]["signer"]["uid"] and
                    signer["spec_replicas"] == 0 and signer["status_replicas"] == 0 and
                    not live["matching_pods"]["signer"])
        self._wait(absent)
        self.absent_at = utc()
        return True

    def new_signer_identity(self, baseline, delete_started_at):
        """Bind a newly created, init-blocked Pod through its owning ReplicaSet.

        Init state alone is not a Vault denial. A separate paired audit probe
        must establish that while the role is absent.
        """
        if self.absent_at is None:
            raise ProbeError("prior signer absence not observed")
        deleted = GUARDS._timestamp(delete_started_at)
        self.baseline = baseline
        def observe():
            if self.control.assert_maintenance_lock() is not True:
                raise ProbeError("maintenance lock lost")
            if not self._quiesced(): raise ProbeError("client or Fence resumed")
            deployment = self._get("deployment", "validator-hoodi-example-remote-signer")
            metadata = deployment["metadata"]
            generation = metadata.get("generation")
            if (metadata["uid"] != baseline["controllers"]["signer"]["uid"] or
                    type(generation) is not int or generation < 1 or
                    deployment["spec"].get("replicas") != 1):
                raise ProbeError("signer controller identity changed")
            pods = self.runner(["-n", NS, "get", "pods", "-l",
                                "app.kubernetes.io/component=validator-remote-signer,node-operator.io/validator-set=hoodi-example", "-o", "json"])["items"]
            if not pods: return None
            if len(pods) != 1: raise ProbeError("signer Pod identity is ambiguous")
            pod = pods[0]
            pm, status = pod["metadata"], pod.get("status", {})
            if pm.get("deletionTimestamp"): return None
            created = pm.get("creationTimestamp")
            if not isinstance(created, str) or GUARDS._timestamp(created) < deleted:
                raise ProbeError("signer Pod predates role deletion")
            owners = [x for x in pm.get("ownerReferences", []) if x.get("controller") is True]
            if len(owners) != 1 or owners[0].get("kind") != "ReplicaSet":
                raise ProbeError("signer Pod owner is not a ReplicaSet")
            rs = self._get("replicaset", owners[0]["name"])
            rs_owners = [x for x in rs["metadata"].get("ownerReferences", []) if x.get("controller") is True]
            if (rs["metadata"]["uid"] != owners[0]["uid"] or len(rs_owners) != 1 or
                    rs_owners[0].get("kind") != "Deployment" or rs_owners[0].get("uid") != metadata["uid"]):
                raise ProbeError("signer ReplicaSet owner changed")
            if deployment.get("status", {}).get("observedGeneration", 0) < generation: return None
            address = status.get("podIP")
            if not address: return None
            try: ipaddress.ip_address(address)
            except ValueError: raise ProbeError("signer Pod address malformed") from None
            init = [x for x in status.get("initContainerStatuses", []) if x.get("name") == "vault-agent-init"]
            if len(init) != 1: return None
            if "terminated" in init[0].get("state", {}):
                raise ProbeError("Vault initializer exited instead of remaining blocked")
            if not any(k in init[0].get("state", {}) for k in ("running", "waiting")): return None
            if any(x.get("ready") is True or "running" in x.get("state", {}) for x in status.get("containerStatuses", [])):
                raise ProbeError("signer application started while role absent")
            if any(x.get("type") == "Initialized" and x.get("status") == "True" for x in status.get("conditions", [])):
                raise ProbeError("signer initialization unexpectedly completed")
            return {"pod_uid": pm["uid"], "pod_ip": address, "pod_created_at": created,
                    "deployment_uid": metadata["uid"], "deployment_generation": generation, "init_blocked": True}
        return self._wait(observe)

    def _tls(self, run):
        p = RENDER.tls("prepositive", "hoodi-example", self.key, TLS_IMAGE, run)
        p["metadata"]["annotations"]["node-operator.io/probe-owner"] = run
        return p

    def _admit(self, manifest):
        admitted = self.runner(["create", "--dry-run=server", "-f", "-", "-o", "json"], manifest)
        wanted, actual = manifest["spec"], admitted.get("spec", {})
        if actual.get("readinessGates") != wanted["readinessGates"]:
            raise ProbeError("never-ready gate changed during admission")
        before, after = wanted["containers"][0], actual.get("containers", [{}])[0]
        if any(before.get(k) != after.get(k) for k in ("name", "image", "command", "args")):
            raise ProbeError("probe executable changed during admission")
        if before["image"] == TCP_IMAGE and (actual.get("volumes") or actual.get("initContainers") or actual.get("automountServiceAccountToken") is not False):
            raise ProbeError("TCP diagnostic acquired unexpected credentials")
        if before["image"] == TLS_IMAGE and not any(x.get("name") == "vault-agent-init" and "@sha256:" in x.get("image", "") for x in actual.get("initContainers", [])):
            raise ProbeError("TLS diagnostic Vault initializer not pinned")
        return True

    def preflight(self, baseline):
        self.baseline = baseline
        # Refuse missing concrete integrations before any scale operation.
        if not all(callable(x) for x in (self.audit_reader, self.beacon_reader, self.audit_hmac_reader)):
            raise ProbeError("audit and Beacon read integrations required")
        for p in (self._tls("preflight"), tcp_manifest("positive", "preflight"), tcp_manifest("negative", "preflight")):
            self._admit(p)
        return True

    def audit_preflight(self):
        """Run only after administrator readiness verifies raw logging is off."""
        role_hmac = self.audit_hmac_reader()
        if not isinstance(role_hmac, str) or AUDIT.HMAC.fullmatch(role_hmac) is None:
            raise ProbeError("audit role HMAC unavailable before maintenance")
        def observe():
            end = utc()
            start = (dt.datetime.fromisoformat(end.replace("Z", "+00:00")) - dt.timedelta(seconds=120)).isoformat().replace("+00:00", "Z")
            records = self.audit_reader(start, end)
            try:
                if not records: return None
                pairs = AUDIT._paired(records, AUDIT.timestamp(start), AUDIT.timestamp(end))
                if not pairs: return None
                return {"result": "PASS_AUDIT_READINESS", "collected_at_utc": end,
                        "paired_events_observed": len(pairs), "role_hmac_available": True,
                        "scope": "recent audit ingestion only; not UC-5 denial evidence"}
            finally:
                records.clear()
        result = self._wait(observe, 60)
        self._save("audit-readiness.json", result)
        return True

    def _probe(self, manifest):
        if not self._quiesced(): raise ProbeError("diagnostic requires quiesced client and Fence")
        self.control.assert_maintenance_lock()
        self._admit(manifest)
        name, owner = manifest["metadata"]["name"], manifest["metadata"]["annotations"]["node-operator.io/probe-owner"]
        if self._get("pod", name) is not None: raise ProbeError("diagnostic name already exists")
        uid = None
        try:
            created = self.runner(["create", "-f", "-", "-o", "json"], manifest)
            uid = created["metadata"]["uid"]
            def terminal():
                pod = self._get("pod", name)
                if pod is None or pod["metadata"]["uid"] != uid: raise ProbeError("diagnostic identity changed")
                return pod if pod.get("status", {}).get("phase") in ("Succeeded", "Failed") else None
            pod = self._wait(terminal)
            if pod["status"]["phase"] != "Succeeded": raise ProbeError("diagnostic did not succeed")
            container = manifest["spec"]["containers"][0]["name"]
            result = self.runner(["-n", NS, "logs", name, "-c", container, "--tail=1", "--limit-bytes=4096"])
            return uid, result
        finally:
            pod = self._get("pod", name)
            if pod is not None:
                metadata = pod["metadata"]
                if metadata.get("annotations", {}).get("node-operator.io/probe-owner") != owner or (uid is not None and metadata["uid"] != uid):
                    raise ProbeError("refusing unowned diagnostic cleanup")
                self.runner(["delete", "--raw", f"/api/v1/namespaces/{NS}/pods/{name}", "-f", "-"],
                            {"apiVersion": "v1", "kind": "DeleteOptions", "preconditions": {"uid": metadata["uid"]}})
                self._wait(lambda: self._get("pod", name) is None, 60)

    def fresh_fence(self, baseline):
        self.baseline = baseline
        before = self._live()
        if any(before["controllers"][x]["spec_replicas"] != 1 or before["controllers"][x]["ready_replicas"] != 1 for x in ("client", "fence", "signer", "db")):
            raise ProbeError("running baseline not ready")
        pods = self.runner(["-n", NS, "get", "pods", "-l", "app.kubernetes.io/component=validator-signing-fence,node-operator.io/validator-set=hoodi-example", "-o", "json"])["items"]
        if len(pods) != 1: raise ProbeError("single Fence Pod not established")
        fence_uid = pods[0]["metadata"]["uid"]
        lease = before["lease"]
        now = int(time.time())
        renewed = GUARDS._timestamp(lease["renew_time_utc"])
        if lease["holder_identity"] != fence_uid or not renewed <= now < renewed + lease["duration_seconds"]:
            raise ProbeError("live Fence Lease not fresh")
        for role in ("fence", "client"):
            self.control.set_replicas(role, baseline["controllers"][role]["uid"], 0)
        self._wait(self._quiesced)
        def expired():
            current = self._live()["lease"]
            return (not current["holder_identity"] or
                    GUARDS._timestamp(current["renew_time_utc"]) + current["duration_seconds"] < int(time.time()))
        self._wait(expired, 90)
        run = uuid.uuid4().hex[:12]
        _, tls = self._probe(self._tls(run))
        if tls.get("result") != "PASS" or tls.get("validator_public_key") != self.key or tls.get("layer") != "tls+http":
            raise ProbeError("positive signer identity control failed")
        control_uid, positive = self._probe(tcp_manifest("positive", run))
        direct_uid, negative = self._probe(tcp_manifest("negative", run))
        _, post = self._probe(tcp_manifest("positive", uuid.uuid4().hex[:12]))
        if positive != {"result": "TCP_CONTROL_SUCCESS"} or post != positive or negative != {"result": "NETWORK_DENIED_TIMEOUT"}:
            raise ProbeError("network controls inconclusive")
        if not self._quiesced(): raise ProbeError("quiescence lost after diagnostics")
        proof = {"schema_version": 1, "event_type": "signing-proxy-fence", "collected_at_utc": utc(),
                 "network": "hoodi", "validator_set": "hoodi-example", "validator_public_key": self.key,
                 "source": "signing-proxy-fence", "payload": {
                     "fence_live": True, "lease_enforced": True, "direct_client_to_signer_denied": True,
                     "cached_key_requests_blocked": True, "in_flight_request_bound": True,
                     "fence_live_before_quiesce": True, "client_and_fence_quiesced": True,
                     "direct_probe_pod_uid": direct_uid, "fence_control_probe_pod_uid": control_uid,
                     "fence_pod_uid_before_quiesce": fence_uid, "probe_scope": GUARDS.PROOF_SCOPE}}
        self._save("fresh-fence-proof.json", proof)
        return proof

    def history(self, phase):
        if phase not in ("before", "after") or not self._quiesced(): raise ProbeError("history requires quiescence")
        parts = ["SELECT '" + t + "' AS table_name,count(*) AS row_count,encode(sha256(convert_to(coalesce(jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text)::text,'[]'),'UTF8')),'hex') AS sha256 FROM " + t + " t" for t in TABLES]
        sql = "BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY; SET LOCAL statement_timeout='10s'; SELECT jsonb_agg(x ORDER BY table_name) FROM (" + " UNION ALL ".join(parts) + ") x; COMMIT;"
        rows = self.runner(["-n", NS, "exec", "validator-hoodi-example-slashing-db-0", "-c", "postgres", "--", "psql", "--no-psqlrc", "--quiet", "--username=web3signer", "--dbname=web3signer", "--no-password", "--tuples-only", "--no-align", "--set=ON_ERROR_STOP=1", "--command", sql])
        if not isinstance(rows, list) or len(rows) != 6 or {x.get("table_name") for x in rows} != set(TABLES):
            raise ProbeError("history response malformed")
        for row in rows:
            if set(row) != {"table_name", "row_count", "sha256"} or type(row["row_count"]) is not int or row["row_count"] < 0 or not isinstance(row["sha256"], str) or not __import__("re").fullmatch("[0-9a-f]{64}", row["sha256"]):
                raise ProbeError("history response malformed")
        if not self._quiesced(): raise ProbeError("history quiescence lost")
        self._save("history-" + phase + ".json", rows)
        return rows

    def confirm_denied_start(self, pod_identity, delete_started_at):
        context = {"runtime_role_path": "auth/kubernetes/role/hoodi-hoodi-example-runtime",
                   "role_hmac": self.audit_hmac_reader(),
                   **{k: pod_identity[k] for k in ("pod_uid", "pod_ip", "pod_created_at", "deployment_uid", "deployment_generation")},
                   "delete_after": delete_started_at}
        def observe():
            if self.control.assert_maintenance_lock() is not True or not self._quiesced():
                raise ProbeError("denial observation lost maintenance guard")
            current = self.new_signer_identity(self.baseline, delete_started_at)
            if current != pod_identity: raise ProbeError("denied signer identity changed")
            end = utc()
            records = self.audit_reader(delete_started_at, end)
            try:
                return AUDIT.prove_denial(records, {**context, "observation_before": end})
            except AUDIT.AuditProofError:
                return None
            finally:
                records.clear()
        proof = self._wait(observe, 90)
        self._save("vault-denial-binding.json", proof)
        return True

    def audit_chain(self, context):
        def observe():
            records = self.audit_reader(context["delete_after"], context["restore_before"])
            try:
                return AUDIT.prove(records, context)
            except AUDIT.AuditProofError:
                return None
            finally:
                records.clear()
        proof = self._wait(observe, 90)
        self._save("vault-audit-chain.json", proof)
        return True

    def verify_continuity(self, baseline, before_history):
        """Readiness/identity/history gates only, never a duty-completion claim."""
        self.baseline = baseline
        if self.absent_at is None: raise ProbeError("recovery absence boundary missing")
        def ready():
            if self.control.assert_maintenance_lock() is not True or not self._quiesced():
                raise ProbeError("recovery maintenance guard lost")
            live = self._live()
            for name, original in baseline["controllers"].items():
                current = live["controllers"][name]
                if current["uid"] != original["uid"] or not current["deletion_timestamp_absent"]:
                    raise ProbeError("recovery controller identity changed")
            if any(live[k] != baseline[k] for k in ("service_specs", "network_policy_specs")):
                raise ProbeError("recovery network baseline changed")
            if (live["controllers"]["signer"]["image"] != baseline["controllers"]["signer"]["image"] or
                    live["controllers"]["db"]["pvc_uid"] != baseline["controllers"]["db"]["pvc_uid"] or
                    live["controllers"]["db"]["pvc_phase"] != "Bound"):
                raise ProbeError("recovery image or storage identity changed")
            if live["competing_hpas"] or live["argo"]["active_operations"] or live["argo"]["automated_validator_namespace"]:
                raise ProbeError("competing workload automation present")
            for name in ("signer", "db"):
                controller = live["controllers"][name]
                if (any(controller[k] != 1 for k in ("spec_replicas", "status_replicas", "ready_replicas")) or
                        controller["observed_generation"] < controller["generation"]): return None
            return live
        self._wait(ready)
        self._verify_restored_pod(baseline)
        original_instance = self._restored_instance
        after_history = self.history("after")
        if sorted(after_history, key=lambda x: x["table_name"]) != sorted(before_history, key=lambda x: x["table_name"]):
            raise ProbeError("slashing history changed during maintenance")
        _, tls = self._probe(self._tls(uuid.uuid4().hex[:12]))
        if tls.get("result") != "PASS" or tls.get("validator_public_key") != self.key or tls.get("layer") != "tls+http":
            raise ProbeError("restored signer mTLS identity failed")
        beacon = self.beacon_reader(self.key)
        if not isinstance(beacon, dict) or beacon.get("result") != "PASS_PRIVATE_BEACON_READY" or beacon.get("validator_public_key") != self.key:
            raise ProbeError("private Beacon readiness unverified")
        if ready() is None: raise ProbeError("recovery readiness lost after probes")
        self._verify_restored_pod(baseline)
        if self._restored_instance != original_instance:
            raise ProbeError("signer restarted or changed after continuity probes")
        self._save("continuity-gates.json", {"result": "PASS_CONTINUITY_GATES", "collected_at_utc": utc(),
                    "validator_public_key": self.key, "same_slashing_history": True,
                    "same_pvc_uid": baseline["controllers"]["db"]["pvc_uid"],
                    "signer_absent_observed_at": self.absent_at,
                    "signer_instance": list(original_instance),
                    "mtls_identity_verified": True, "private_beacon_ready": True,
                    "uc5_complete": False, "activation_performed": False})
        self.activation_inputs = {"beacon": beacon, "tls": tls, "observed_at": utc()}
        return True

    def _verify_restored_pod(self, baseline):
        pods = self.runner(["-n", NS, "get", "pods", "-l",
                            "app.kubernetes.io/component=validator-remote-signer,node-operator.io/validator-set=hoodi-example", "-o", "json"])["items"]
        if len(pods) != 1: raise ProbeError("restored signer Pod identity ambiguous")
        pod = pods[0]
        meta, status = pod["metadata"], pod.get("status", {})
        if meta.get("deletionTimestamp") or GUARDS._timestamp(meta.get("creationTimestamp")) < GUARDS._timestamp(self.absent_at):
            raise ProbeError("restored signer Pod predates recovery boundary")
        owners = [x for x in meta.get("ownerReferences", []) if x.get("controller") is True]
        if len(owners) != 1 or owners[0].get("kind") != "ReplicaSet":
            raise ProbeError("restored signer owner unverified")
        rs = self._get("replicaset", owners[0]["name"])
        parents = [x for x in rs["metadata"].get("ownerReferences", []) if x.get("controller") is True]
        if (rs["metadata"]["uid"] != owners[0]["uid"] or len(parents) != 1 or
                parents[0].get("kind") != "Deployment" or parents[0].get("uid") != baseline["controllers"]["signer"]["uid"]):
            raise ProbeError("restored signer deployment changed")
        containers = [x for x in pod["spec"].get("containers", []) if x.get("name") == "web3signer"]
        if len(containers) != 1 or containers[0].get("image") != baseline["controllers"]["signer"]["image"]:
            raise ProbeError("restored signer image changed")
        init = [x for x in status.get("initContainerStatuses", []) if x.get("name") == "vault-agent-init"]
        if len(init) != 1 or init[0].get("state", {}).get("terminated", {}).get("exitCode") != 0:
            raise ProbeError("restored Vault Agent did not complete")
        signer = [x for x in status.get("containerStatuses", []) if x.get("name") == "web3signer"]
        if len(signer) != 1 or signer[0].get("ready") is not True or "running" not in signer[0].get("state", {}):
            raise ProbeError("restored signer container not ready")
        running = signer[0]["state"]["running"]
        image_id, restart_count, started = signer[0].get("imageID"), signer[0].get("restartCount"), running.get("startedAt")
        if not isinstance(image_id, str) or not image_id or type(restart_count) is not int or restart_count < 0 or not isinstance(started, str):
            raise ProbeError("restored signer runtime identity incomplete")
        GUARDS._timestamp(started)
        self._restored_instance = (meta["uid"], image_id, restart_count, started)
        return meta["uid"]
