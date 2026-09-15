#!/usr/bin/env python3
"""Isolated synthetic Raft upgrade/restore rehearsal; never uses live Vault."""
import json
import os
import re
from pathlib import Path
import subprocess
import tempfile
import time
import uuid

OLD = "sha256:20ff3ed4a4da750d1be0757c82e0a10accc00c26c157bde3a694f2b227300caf"
NEW = os.environ.get("VAULT_RAFT_TEST_NEW_IMAGE", "sha256:5463f9d70fe71b897b165e019dbc1e85aeaa8271130572bd060729dc124ff51f")


def run(*args, allowed=(0,), stdin=None):
    result = subprocess.run(args, input=stdin, capture_output=True, text=True, timeout=120)
    if result.returncode not in allowed:
        # CLI arguments/responses can contain synthetic root/unseal material.
        raise RuntimeError(f"fixture command failed (exit {result.returncode}); output withheld")
    return result.stdout


def main():
    if not re.fullmatch(r"sha256:[a-f0-9]{64}", NEW):
        raise ValueError("VAULT_RAFT_TEST_NEW_IMAGE must be an immutable local image ID")
    owner = "hoodi-raft-test-" + uuid.uuid4().hex[:12]
    volume = None
    containers = []
    current = None
    token = None
    with tempfile.TemporaryDirectory(prefix="hoodi-raft-config-") as scratch:
        config = Path(scratch) / "server.hcl"
        config.write_text('''disable_mlock = true
api_addr = "http://127.0.0.1:8200"
cluster_addr = "https://127.0.0.1:8201"
listener "tcp" {
  address = "127.0.0.1:8200"
  tls_disable = true
}
storage "raft" {
  path = "/data/raft"
  node_id = "synthetic-one"
}
''')
        config.chmod(0o444)

        def cli(*args, allowed=(0,), authenticated=True, auth_token=None, stdin=None):
            env = ["-e", "VAULT_ADDR=http://127.0.0.1:8200"]
            effective_token = token if auth_token is None else auth_token
            if authenticated and effective_token:
                env += ["-e", "VAULT_TOKEN=" + effective_token]
            return run("docker", "exec", "-i", *env, current, "/bin/vault", *args,
                       allowed=allowed, stdin=stdin)

        def start(image):
            nonlocal current
            current = run("docker", "run", "-d", "--platform", "linux/amd64",
                          "--label", "node-operator.test-owner=" + owner,
                          "--network", "none", "--read-only", "--cap-drop", "ALL",
                          "--security-opt", "no-new-privileges", "--user", "100:1000",
                          "--mount", f"type=volume,src={volume},dst=/data",
                          "--mount", f"type=bind,src={config},dst=/fixture/server.hcl,readonly",
                          "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,uid=100,gid=1000",
                          "--entrypoint", "/bin/vault", image,
                          "server", "-config=/fixture/server.hcl").strip()
            containers.append(current)
            for _ in range(40):
                if run("docker", "inspect", "--format", "{{.State.Running}}", current).strip() != "true":
                    break
                try:
                    return json.loads(cli("status", "-format=json", allowed=(0, 2),
                                          authenticated=False))
                except (RuntimeError, json.JSONDecodeError):
                    time.sleep(1)
            diagnostics = run("docker", "inspect", "--format",
                              "status={{.State.Status}} exit={{.State.ExitCode}}", current)
            raise RuntimeError("synthetic Vault did not become reachable; "
                               + diagnostics + "; logs withheld")

        def recovery_preflight(credential="", expected=0):
            # Use the real helper and the actual server CLI, not a simulated
            # authorization response. No host port or secret file is needed.
            library = Path(__file__).resolve().parents[1] / "ops/lib/vault-recovery-auth.sh"
            result = subprocess.run(
                ["bash", "-c", '''
set -euo pipefail
vault() {
  docker exec -i -e VAULT_ADDR=http://127.0.0.1:8200 -e VAULT_TOKEN \
    "$VAULT_TEST_CONTAINER" /bin/vault "$@"
}
source "$1"
vault_recovery_auth_preflight
''', "fixture", str(library)],
                env={**os.environ, "VAULT_TOKEN": credential,
                     "VAULT_TEST_CONTAINER": current},
                stdin=subprocess.DEVNULL, capture_output=True, text=True,
                start_new_session=True, timeout=30)
            if result.returncode != expected:
                raise RuntimeError("actual-server recovery preflight failed; output withheld")
            if credential and credential in result.stdout + result.stderr:
                raise RuntimeError("recovery preflight exposed a synthetic credential; output withheld")

        try:
            for image in (OLD, NEW):
                assert run("docker", "image", "inspect", image,
                           "--format", "{{.Id}}").strip() == image
            volume = run("docker", "volume", "create", "--label",
                         "node-operator.test-owner=" + owner, owner).strip()
            run("docker", "run", "--rm", "--network", "none", "--read-only",
                "--cap-drop", "ALL", "--cap-add", "CHOWN", "--user", "0:0",
                "--security-opt", "no-new-privileges", "--mount",
                f"type=volume,src={volume},dst=/data", "--entrypoint", "/bin/sh",
                NEW, "-ec", "mkdir /data/raft && chown 100:1000 /data /data/raft")
            assert start(OLD)["initialized"] is False
            initialized = json.loads(cli("operator", "init", "-key-shares=1",
                                         "-key-threshold=1", "-format=json"))
            token = initialized["root_token"]
            share = initialized["unseal_keys_b64"][0]
            cli("operator", "unseal", share)
            recovery_preflight()
            cli("secrets", "enable", "-path=synthetic", "kv-v2")
            cli("kv", "put", "synthetic/checkpoint", "value=before-upgrade")
            ceremony_policy = (Path(__file__).resolve().parents[2]
                               / "deploy/vault/operator-recovery-policy.hcl").read_text()
            cli("policy", "write", "synthetic-ceremony", "-", stdin=ceremony_policy)
            ceremony_token = json.loads(cli(
                "token", "create", "-policy=synthetic-ceremony", "-no-default-policy",
                "-ttl=10m", "-explicit-max-ttl=10m", "-format=json"))["auth"]["client_token"]
            cli("operator", "raft", "snapshot", "save", "/data/before.snap")
            run("docker", "stop", "--time", "30", current)
            assert start(NEW)["initialized"] is True
            cli("operator", "unseal", share)
            assert cli("kv", "get", "-field=value", "synthetic/checkpoint").strip() == "before-upgrade"
            recovery_preflight(expected=1)
            recovery_preflight("invalid-synthetic-token", expected=1)
            recovery_preflight(ceremony_token)
            # Do not opt out of Vault2.x endpoint authentication. All material
            # is synthetic and remains in captured subprocess input/output.
            cli("operator", "generate-root", "-status", authenticated=False, allowed=(2,))
            cli("operator", "generate-root", "-status", auth_token="invalid-synthetic-token",
                allowed=(2,))
            cli("kv", "get", "synthetic/checkpoint", auth_token=ceremony_token, allowed=(2,))
            cli("token", "create", auth_token=ceremony_token, allowed=(2,))
            ceremony = json.loads(cli("operator", "generate-root", "-init", "-format=json",
                                      auth_token=ceremony_token))
            generated = json.loads(cli("operator", "generate-root", "-format=json",
                                       "-nonce=" + ceremony["nonce"], "-",
                                       auth_token=ceremony_token, stdin=share + "\n"))
            assert generated["complete"] is True
            recovered = cli("operator", "generate-root", "-decode=" + generated["encoded_token"],
                            "-otp=" + ceremony["otp"], auth_token=ceremony_token).strip()
            assert json.loads(cli("token", "lookup", "-format=json",
                                  auth_token=recovered))["data"]["policies"] == ["root"]
            cli("token", "revoke", "-self", auth_token=recovered)
            cli("token", "lookup", auth_token=recovered, allowed=(2,))
            cli("token", "revoke", "-self", auth_token=ceremony_token)
            cli("operator", "generate-root", "-status", auth_token=ceremony_token, allowed=(2,))
            del ceremony, generated
            cli("kv", "put", "synthetic/checkpoint", "value=after-upgrade")
            cli("operator", "raft", "snapshot", "restore", "/data/before.snap")
            for _ in range(40):
                try:
                    if cli("kv", "get", "-field=value", "synthetic/checkpoint").strip() == "before-upgrade":
                        break
                except RuntimeError:
                    pass
                time.sleep(1)
            else:
                raise RuntimeError("restored synthetic value was not observed")
            # A Raft restore also restores token state captured in the backup.
            # Prove that boundary and revoke the restored scoped credential;
            # the post-snapshot generated root must remain absent.
            cli("operator", "generate-root", "-status", auth_token=ceremony_token)
            cli("token", "lookup", auth_token=recovered, allowed=(2,))
            cli("token", "revoke", "-self", auth_token=ceremony_token)
            cli("operator", "generate-root", "-status", auth_token=ceremony_token, allowed=(2,))
            del ceremony_token, recovered
            print(json.dumps({"result": "passed", "old_image": OLD, "new_image": NEW,
                              "checks": ["fresh Raft initialization", "old-process stopped before new start",
                                         "retained KV after upgrade", "missing and invalid ceremony tokens denied",
                                         "scoped ceremony token denies KV and token creation",
                                         "pre-upgrade scoped token plus share generates root after upgrade",
                                         "generated root and scoped token revoked",
                                         "old snapshot restores pre-mutation KV",
                                         "snapshot restores scoped token; re-revocation verified",
                                         "post-snapshot generated root remains absent after restore"],
                              "wrapper_preflight": "Actual helper against both server versions: legacy success, v2 missing/invalid denial and scoped-token success",
                              "scope": "synthetic single-node Shamir compatibility, not live HA, KMS recovery keys or production operator authentication"}))
        finally:
            for container in reversed(containers):
                run("docker", "rm", "-f", container)
            if volume:
                run("docker", "volume", "rm", volume)


if __name__ == "__main__":
    main()
