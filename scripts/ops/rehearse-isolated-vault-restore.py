#!/usr/bin/env python3
"""One-host, deliberately interactive Vault snapshot recovery rehearsal.

The normal mode is a reviewable plan.  ``--execute`` is intentionally hard to
reach: it may only be run as root on the named isolated EC2 instance before the
approved deadline.  This program never accepts secrets on its command line or
from the environment.
"""
import argparse
import base64
import getpass
import hashlib
import http.client
import importlib.util
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
import warnings
import resource
import signal
from datetime import datetime, timezone

BUCKET = "node-operator-baseline-vs-20260907095302548300000001"
KEY = "raft-migration/20260909T111054Z.snap"
VERSION = "LGI_Y8VZQ4.87.kbJPsmjaMY7s3XcTQN"
SHA256 = "d4b3a0d070e5eac66b048526b4cce0ef83961e8dda91c621f427ae49d17798ba"
ACCOUNT, REGION, INSTANCE = "123456789012", "ap-northeast-2", "i-0123456789abcdef0"
KMS = "arn:aws:kms:ap-northeast-2:123456789012:key/3bc15229-161c-4172-8a61-8ba0149f4890"
OLD = "123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/node-operator-baseline-gitops-vault@sha256:268bb80aa9c6d13d65fcfa05c0c268caca068952240a8087291a6ce0b66e3a10"
NEW = "123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/node-operator-baseline-vault-runtime-server@sha256:8fbe048a50769523a577be1fd41fe7f476e1bda4a345cf25874da6426ac25e49"
DEADLINE = datetime(2026, 9, 10, 12, tzinfo=timezone.utc)
PORT, CLUSTER_PORT = 28200, 28201
VAULT_UID, VAULT_GID = 65000, 65000


class CeremonyError(RuntimeError): pass


def xor_decode(encoded, otp):
    """Vault 1.20.4 uses RawStdEncoding (unpadded Base64), then ASCII XOR."""
    try:
        if not isinstance(encoded, str) or not isinstance(otp, str): raise ValueError()
        if not 1 <= len(encoded) <= 4096 or not 1 <= len(otp) <= 4096: raise ValueError()
        if "=" in encoded or not otp.isascii() or not otp.isalnum(): raise ValueError()
        raw = base64.b64decode(encoded + "=" * (-len(encoded) % 4), validate=True)
        if base64.b64encode(raw).decode("ascii").rstrip("=") != encoded: raise ValueError()
        pad = otp.encode("ascii")
        if not raw or len(raw) != len(pad): raise ValueError()
        return bytes(a ^ b for a, b in zip(raw, pad)).decode("utf-8")
    except (ValueError, UnicodeError) as exc:
        raise CeremonyError("invalid generate-root OTP material") from exc


class LocalVault:
    """Fixed-loopback HTTP client: no proxy discovery and no redirects."""
    def __init__(self, port=PORT): self.port = port
    def request(self, method, path, token=None, body=None, binary=False):
        if not path.startswith("/v1/"): raise CeremonyError("unexpected Vault API path")
        headers = {"Content-Type": "application/octet-stream" if binary else "application/json"}
        if token: headers["X-Vault-Token"] = token
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=15)
        try:
            payload = body if isinstance(body, bytes) else (json.dumps(body).encode() if body is not None else None)
            conn.request(method, path, payload, headers)
            response = conn.getresponse()
            data = response.read()
            if response.status not in (200, 204): raise CeremonyError("local Vault request failed: HTTP %s" % response.status)
            return data if binary else (json.loads(data or b"{}"))
        finally: conn.close()


def controlled_env(docker_config=None):
    env = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "HOME": "/root", "AWS_EC2_METADATA_DISABLED": "false"}
    if docker_config: env["DOCKER_CONFIG"] = str(docker_config)
    return env


def command(*args, input=None, env=None):
    result = subprocess.run(args, input=input, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            timeout=120, check=False, env=controlled_env() if env is None else env)
    if result.returncode: raise CeremonyError("host command failed: " + args[0])
    return result.stdout.strip()


def imds(path, method="GET", token=None):
    # Explicit ProxyHandler({}) prevents ambient HTTP(S)_PROXY use.
    req = urllib.request.Request("http://169.254.169.254/latest/" + path, method=method)
    if token: req.add_header("X-aws-ec2-metadata-token", token)
    if method == "PUT": req.add_header("X-aws-ec2-metadata-token-ttl-seconds", "60")
    try:
        return urllib.request.build_opener(urllib.request.ProxyHandler({})).open(req, timeout=2).read().decode()
    except Exception as exc: raise CeremonyError("IMDSv2 preflight failed") from exc


def preflight():
    if os.geteuid() != 0 or sys.platform != "linux": raise CeremonyError("--execute requires root on Linux")
    if datetime.now(timezone.utc) >= DEADLINE: raise CeremonyError("approved execution window has expired")
    if Path("/proc/swaps").read_text().splitlines()[1:]: raise CeremonyError("active swap is not permitted for the ceremony")
    try:
        tty = os.open("/dev/tty", os.O_RDWR | os.O_NOFOLLOW); os.close(tty)
    except OSError as exc: raise CeremonyError("an interactive /dev/tty is required") from exc
    token = imds("api/token", "PUT")
    document = json.loads(imds("dynamic/instance-identity/document", token=token))
    if document.get("instanceId") != INSTANCE or document.get("accountId") != ACCOUNT or document.get("region") != REGION:
        raise CeremonyError("this is not the approved isolated recovery host")
    # A conservative guard: require a crypt mapping; humans still confirm EBS encryption/VPC isolation.
    # Root-volume encryption and VPC routes are attested by the separately
    # reviewed host verifier; do not substitute a meaningless /dev/mapper test.


def ports_are_free():
    for port in (PORT, CLUSTER_PORT):
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try: probe.bind(("127.0.0.1", port))
        except OSError as exc: raise CeremonyError("refusing an existing loopback listener") from exc
        finally: probe.close()


def verify_snapshot(path):
    """Verify the exact downloaded S3 object before its bytes reach Vault."""
    digest = hashlib.sha256()
    with open(path, "rb", buffering=0) as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    if digest.hexdigest() != SHA256: raise CeremonyError("snapshot checksum mismatch")


def audited_configuration(value):
    devices = value.get("data", value)
    required = {
        "validator-file/": ("file", "file_path", "/vault/audit/validator-audit.json"),
        "validator-socket/": ("socket", "address", "/vault/audit/validator-audit.sock"),
    }
    for name, (kind, field, expected) in required.items():
        device = devices.get(name, {})
        options = device.get("options", {})
        if device.get("type") != kind or options.get(field) != expected or str(options.get("log_raw", "")).lower() != "false":
            raise CeremonyError("restored audit device does not match the isolated contract")
        if kind == "socket" and options.get("socket_type") != "unix": raise CeremonyError("restored audit socket is not UNIX-only")


def singleton_raft(value):
    servers = value.get("data", value).get("config", {}).get("servers", [])
    if not isinstance(servers, list) or len(servers) != 1: raise CeremonyError("Raft is not an isolated singleton")
    server = servers[0]
    if server.get("node_id") != "isolated-rehearsal" or server.get("address") != "127.0.0.1:28201" or not server.get("leader") or not server.get("voter"):
        raise CeremonyError("Raft singleton metadata does not match isolated listener")


def raft_fingerprint(value):
    """Ignore Vault's per-request envelope; retain only singleton identity state."""
    singleton_raft(value)
    servers = value.get("data", value)["config"]["servers"]
    return tuple(sorted((server["node_id"], server["address"], bool(server["leader"]), bool(server["voter"])) for server in servers))


def require_version(status, expected):
    version = status.get("version")
    if not isinstance(version, str) or version != expected: raise CeremonyError("Vault image version did not match the pinned review")


def metadata_fingerprint(mounts, policies):
    return hashlib.sha256(json.dumps({"mounts": sorted(mounts.get("data", mounts)), "policies": sorted(policies.get("data", {}).get("keys", []))}, sort_keys=True).encode()).hexdigest()


class AuditSink:
    """Bounded local receiver.  It discards audit records, never forwards or prints them."""
    def __init__(self, directory): self.directory, self.sock, self.count, self.stop = Path(directory), None, 0, threading.Event()
    def start(self):
        self.directory.mkdir(mode=0o700); os.chown(self.directory, VAULT_UID, VAULT_GID)
        (self.directory / "validator-audit.json").touch(mode=0o600); os.chown(self.directory / "validator-audit.json", VAULT_UID, VAULT_GID)
        name = self.directory / "validator-audit.sock"; self.sock = socket.socket(socket.AF_UNIX); self.sock.bind(str(name)); os.chown(name, VAULT_UID, VAULT_GID); self.sock.listen(4)
        def serve():
            while not self.stop.is_set():
                try: c, _ = self.sock.accept()
                except OSError: break
                with c:
                    while c.recv(8192): self.count += 1
        threading.Thread(target=serve, daemon=True).start()
    def close(self):
        self.stop.set()
        if self.sock: self.sock.close()


def config_text():
    return '''disable_mlock = true
api_addr = "http://127.0.0.1:28200"
cluster_addr = "http://127.0.0.1:28201"
listener "tcp" {
  address = "127.0.0.1:28200"
  cluster_address = "127.0.0.1:28201"
  tls_disable = true
}
storage "raft" {
  path = "/vault/data/raft"
  node_id = "isolated-rehearsal"
}
seal "awskms" {
  region = "ap-northeast-2"
  kms_key_id = "3bc15229-161c-4172-8a61-8ba0149f4890"
}
'''


def prepare_raft_directories(scratch):
    # Raft opens its Bolt file inside the configured path; it does not create
    # this missing parent for us. Both directories stay private to Vault.
    for name in ("data", "data/raft"):
        directory = scratch / name
        directory.mkdir(mode=0o700)
        os.chown(directory, VAULT_UID, VAULT_GID)


class Ceremony:
    def __init__(self): self.owner = "isolated-vault-rehearsal-" + os.urandom(6).hex(); self.container = None; self.scratch = None; self.root = None; self.generated = None; self.ceremony_started = False; self.egress = None; self.stage = "preflight"; self.cleanup_state = "not_started"
    def docker(self, *args, input=None): return command("docker", *args, input=input)
    def start(self, image):
        if self.container: raise CeremonyError("refusing to adopt an existing container")
        if self.docker("ps", "-aq", "--filter", "name=^/" + self.owner + "$"): raise CeremonyError("refusing an existing container name")
        # Set ownership before docker run: a failed run can still leave the
        # named container behind, which cleanup then removes by our UUID name.
        self.container = self.owner
        self.docker("run", "-d", "--name", self.owner, "--label", "node-operator.owner=" + self.owner,
          "--network", "host", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--user", "%s:%s" % (VAULT_UID, VAULT_GID), "--pids-limit", "128", "--memory", "1g",
          "--log-driver", "none", "--mount", "type=bind,src=%s,dst=/vault/data" % (self.scratch / "data"),
          "--mount", "type=bind,src=%s,dst=/vault/audit" % (self.scratch / "audit"), "--mount", "type=bind,src=%s,dst=/vault/config.hcl,readonly" % (self.scratch / "config.hcl"),
          "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,uid=65000,gid=65000", "--entrypoint", "/bin/vault", image, "server", "-config=/vault/config.hcl")
    def stop(self):
        if self.container:
            if self.docker("inspect", "--format", "{{index .Config.Labels \"node-operator.owner\"}}", self.container) != self.owner:
                raise CeremonyError("refusing to remove a container not owned by this ceremony")
            self.docker("rm", "-f", self.container); self.container = None
    def wait(self, api, changed=None, initialized=True):
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            try:
                status = api.request("GET", "/v1/sys/health")
                if status.get("initialized") is initialized and (not initialized or not status.get("sealed")) and (changed is None or status.get("cluster_id") != changed): return status
            except Exception: pass
            time.sleep(1)
        raise CeremonyError("Vault did not become initialized and unsealed")
    def pull(self, image, docker_config):
        self.docker("pull", image)
        # The private DOCKER_CONFIG is set only around login/pull by caller.
    def download(self):
        target = self.scratch / "snapshot.snap"
        command("aws", "--endpoint-url", "https://s3.%s.amazonaws.com" % REGION, "s3api", "get-object", "--region", REGION, "--bucket", BUCKET, "--key", KEY, "--version-id", VERSION, str(target))
        verify_snapshot(target)
        return target
    def prompt_share(self):
        # Buffered r+ requires seeking, which terminals do not support.
        # This stream is prompt output only; getpass opens its own secure input.
        with open("/dev/tty", "w", encoding="utf-8", errors="strict") as tty:
            if not tty.isatty(): raise CeremonyError("recovery share input is not an interactive terminal")
            with warnings.catch_warnings():
                warnings.simplefilter("error", getpass.GetPassWarning)
                try: return getpass.getpass("Recovery key share: ", stream=tty)
                except getpass.GetPassWarning as exc: raise CeremonyError("refusing recovery-share echo fallback") from exc
    def begin_root_attempt(self, api):
        # A lost response does not prove the server rejected the attempt.
        self.ceremony_started = True
        return api.request("POST", "/v1/sys/generate-root/attempt", body={})
    def cleanup(self):
        failures = []
        if self.generated:
            try: LocalVault().request("POST", "/v1/auth/token/revoke-self", self.generated)
            except Exception: failures.append("generated root revoke")
            self.generated = None
        if self.ceremony_started:
            try: LocalVault().request("DELETE", "/v1/sys/generate-root/attempt")
            except Exception: failures.append("generate-root cancel")
        if self.root:
            try: LocalVault().request("POST", "/v1/auth/token/revoke-self", self.root)
            except Exception: failures.append("ephemeral root revoke")
        self.root = None
        try: self.stop()
        except Exception: failures.append("container stop")
        if self.egress and not self.container:
            try: self.egress.close()
            except Exception: failures.append("egress guard cleanup")
            self.egress = None
        elif self.egress:
            failures.append("egress guard retained because container did not stop")
        # Never remove a bind-mounted directory until its only container is stopped.
        if self.scratch and not self.container:
            try:
                shutil.rmtree(self.scratch)
                self.scratch = None
            except Exception: failures.append("sensitive scratch cleanup")
        if failures: raise CeremonyError("cleanup failed: " + ", ".join(failures))
    def execute(self):
        # Credentials must never be written to a core image.
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        resource.setrlimit(resource.RLIMIT_NPROC, (128, 128))
        preflight(); api = LocalVault(); prior_cluster = None
        ports_are_free()
        old_handlers = {}
        def interrupted(signum, frame):
            raise CeremonyError("ceremony interrupted")
        for sig in (signal.SIGINT, signal.SIGTERM): old_handlers[sig] = signal.signal(sig, interrupted)
        self.scratch = Path(tempfile.mkdtemp(prefix="vault-isolated-", dir="/var/tmp")); os.chmod(self.scratch, 0o700)
        audit = None
        result = None
        try:
            self.stage = "local_setup"
            prepare_raft_directories(self.scratch)
            (self.scratch / "config.hcl").write_text(config_text()); os.chown(self.scratch / "config.hcl", VAULT_UID, VAULT_GID); os.chmod(self.scratch / "config.hcl", 0o400)
            audit = AuditSink(self.scratch / "audit"); audit.start()
            # ECR password is passed solely on stdin; private config is removed in cleanup.
            with tempfile.TemporaryDirectory(prefix="vault-docker-", dir="/var/tmp") as cfg:
                self.stage = "image_pull"
                os.chmod(cfg, 0o700); password = command("aws", "--endpoint-url", "https://api.ecr.%s.amazonaws.com" % REGION, "ecr", "get-login-password", "--region", REGION)
                subprocess.run(["docker", "login", "--username", "AWS", "--password-stdin", "123456789012.dkr.ecr.ap-northeast-2.amazonaws.com"], input=password, text=True, env=controlled_env(cfg), check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=120)
                for image in (OLD, NEW): subprocess.run(["docker", "pull", image], env=controlled_env(cfg), check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=300)
            self.stage = "snapshot_download"
            snap = self.download()
            # The host-networked container is fenced by a UID-specific,
            # independently tested firewall module before it can start.
            self.stage = "egress_install"
            egress_path = Path(__file__).with_name("lib") / "isolated-recovery-egress.py"
            spec = importlib.util.spec_from_file_location("isolated_recovery_egress", egress_path)
            if not spec or not spec.loader: raise CeremonyError("egress guard module could not be loaded")
            module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
            self.egress = module.EgressGuard(require_root=True)
            self.egress.install()
            self.stage = "old_start"
            self.start(OLD)
            # A fresh server is deliberately uninitialized; reaching its health
            # endpoint is sufficient before sys/init, not an unsealed assertion.
            deadline = time.monotonic() + 90
            while time.monotonic() < deadline:
                try:
                    conn = http.client.HTTPConnection("127.0.0.1", PORT, timeout=2); conn.request("GET", "/v1/sys/health"); conn.getresponse().read(); conn.close(); break
                except OSError: time.sleep(1)
            else: raise CeremonyError("fresh Vault did not become reachable")
            prior_cluster = None
            self.stage = "initialize"
            init = api.request("PUT", "/v1/sys/init", body={"recovery_shares": 1, "recovery_threshold": 1}); self.root = init.pop("root_token")
            # The fresh recovery keys are never displayed or persisted.
            init.clear()
            fresh = self.wait(api); prior_cluster = fresh.get("cluster_id")
            require_version(fresh, "1.20.4")
            if not isinstance(prior_cluster, str) or not prior_cluster: raise CeremonyError("fresh Vault supplied no cluster identity")
            self.stage = "snapshot_restore"
            api.request("POST", "/v1/sys/storage/raft/snapshot-force", self.root, snap.read_bytes(), binary=True)
            restored = self.wait(api, prior_cluster)
            self.root = None
            # On the legacy server this ceremony endpoint is intentionally
            # unauthenticated; never reuse the now-invalid ephemeral root.
            self.stage = "recovery_begin"
            initial = self.begin_root_attempt(api)
            otp = initial["otp"]
            required = initial.get("required")
            if not isinstance(required, int) or not 1 <= required <= 10: raise CeremonyError("unexpected recovery quorum")
            reply = {}
            for _ in range(required):
                self.stage = "recovery_prompt"
                share = self.prompt_share()
                self.stage = "recovery_submit"
                try:
                    reply = api.request("POST", "/v1/sys/generate-root/update", body={"nonce": initial["nonce"], "key": share})
                finally:
                    share = None
                if reply.get("complete"): break
            if not reply.get("complete"): raise CeremonyError("recovery quorum did not complete")
            self.stage = "recovery_decode"
            generated = xor_decode(reply["encoded_token"], otp)
            self.generated = generated
            self.ceremony_started = False
            # Metadata checks only; no mounts' contents or audit records are read.
            self.stage = "restored_verification"
            audited_configuration(api.request("GET", "/v1/sys/audit", generated))
            raft_metadata = api.request("GET", "/v1/sys/storage/raft/configuration", generated)
            raft_evidence = raft_fingerprint(raft_metadata)
            mounts = api.request("GET", "/v1/sys/mounts", generated)
            policies = api.request("GET", "/v1/sys/policies/acl", generated)
            evidence = metadata_fingerprint(mounts, policies)
            # An authenticated harmless lookup must reach both restored audit devices.
            api.request("GET", "/v1/auth/token/lookup-self", generated)
            time.sleep(1)
            if not audit.count or (self.scratch / "audit" / "validator-audit.json").stat().st_size <= 0:
                raise CeremonyError("restored audit devices received no authenticated delivery")
            old_audit_count = audit.count
            self.stage = "candidate_upgrade"
            self.stop(); self.start(NEW); upgraded = self.wait(api)
            require_version(upgraded, "2.1.0")
            if upgraded.get("cluster_id") != restored.get("cluster_id"): raise CeremonyError("candidate cluster identity mismatch")
            if raft_fingerprint(api.request("GET", "/v1/sys/storage/raft/configuration", generated)) != raft_evidence: raise CeremonyError("candidate Raft metadata mismatch")
            audited_configuration(api.request("GET", "/v1/sys/audit", generated))
            if metadata_fingerprint(api.request("GET", "/v1/sys/mounts", generated), api.request("GET", "/v1/sys/policies/acl", generated)) != evidence:
                raise CeremonyError("candidate mount or policy metadata mismatch")
            # The generated token must work after the pinned upgrade before revocation.
            api.request("GET", "/v1/auth/token/lookup-self", generated)
            time.sleep(1)
            if audit.count <= old_audit_count or (self.scratch / "audit" / "validator-audit.json").stat().st_size <= 0:
                raise CeremonyError("candidate audit devices received no authenticated delivery")
            self.stage = "token_revoke"
            api.request("POST", "/v1/auth/token/revoke-self", generated)
            try: api.request("GET", "/v1/auth/token/lookup-self", generated)
            except CeremonyError as exc:
                if "HTTP 403" not in str(exc): raise CeremonyError("generated root lookup did not receive required denial") from exc
            else: raise CeremonyError("generated root token remained valid after revoke")
            self.generated = None
            result = {"result":"passed", "cluster_id": upgraded.get("cluster_id"), "audit_delivery_chunks":audit.count, "metadata_evidence":evidence, "images":"pinned"}
        finally:
            try:
                # Keep the local sink alive through revocation and stop.
                self.cleanup_state = "running"
                self.cleanup()
                self.cleanup_state = "passed"
            except Exception:
                self.cleanup_state = "failed"
                raise
            finally:
                try:
                    if audit: audit.close()
                except Exception:
                    self.cleanup_state = "failed"
                    raise
                finally:
                    for sig, handler in old_handlers.items(): signal.signal(sig, handler)
        print(json.dumps(result, sort_keys=True))


def failure_summary(ceremony, error):
    # Only static labels are reportable. Never interpolate exception messages,
    # subprocess arguments/responses, tokens, paths, or server JSON.
    stages = {"preflight", "local_setup", "image_pull", "snapshot_download", "egress_install", "old_start", "initialize", "snapshot_restore", "recovery_quorum", "restored_verification", "candidate_upgrade", "token_revoke"}
    stages.update({"recovery_begin", "recovery_prompt", "recovery_submit", "recovery_decode"})
    stage = ceremony.stage if ceremony.stage in stages else "unknown"
    cleanup = ceremony.cleanup_state if ceremony.cleanup_state in {"not_started", "running", "passed", "failed"} else "unknown"
    kind = type(error).__name__
    if kind not in {"CeremonyError", "ResponseNotReady", "TimeoutExpired", "PermissionError", "FileNotFoundError", "OSError", "CalledProcessError", "EgressError"}:
        kind = "UnexpectedError"
    return "FAILED: stage=%s error=%s cleanup=%s; details withheld" % (stage, kind, cleanup)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument("--execute", action="store_true")
    args = parser.parse_args(argv)
    if not args.execute:
        print(json.dumps({"result":"plan", "writes":False, "approved_host":INSTANCE, "deadline":DEADLINE.isoformat(), "images":"pinned digests"}, sort_keys=True)); return 0
    ceremony = Ceremony()
    try:
        ceremony.execute()
        return 0
    except Exception as exc:
        print(failure_summary(ceremony, exc), file=sys.stderr)
        return 1

if __name__ == "__main__":
    try: raise SystemExit(main())
    except Exception: print("FAILED: ceremony did not complete safely", file=sys.stderr); raise SystemExit(1)
