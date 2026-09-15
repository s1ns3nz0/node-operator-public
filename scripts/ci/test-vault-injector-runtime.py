#!/usr/bin/env python3
"""Frozen Injector admission behavior with synthetic inputs and no host ports."""
import base64
import json
from pathlib import Path
import subprocess
import tempfile

INJECTOR = "sha256:2937fbc5d368430d089b9b94f82b44baab71524d166358bb8ea48f7b395152d4"
PYTHON = "sha256:fb305627ba331d70f8cc82509a4fae4be858422fd257e170543fbbefcefb9588"
AGENT = "123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/node-operator-baseline-vault-runtime-agent@sha256:33458e87c790b140717f2f4c688d31327292f67677ba004d32838deed8b8f30a"


def run(*args, **kwargs):
    result = subprocess.run(args, text=True, capture_output=True, **kwargs)
    if result.returncode:
        raise RuntimeError(result.stderr[-4000:])
    return result.stdout.strip()


def main():
    for image in (INJECTOR, PYTHON):
        assert run("docker", "image", "inspect", "--format", "{{.Id}}", image) == image
    with tempfile.TemporaryDirectory(prefix="hoodi-injector-fixture-") as directory:
        path = Path(directory)
        path.chmod(0o755)
        run("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
            "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
            "-keyout", str(path / "key.pem"), "-out", str(path / "cert.pem"))
        # Synthetic, task-only key: readable by the unprivileged fixture server.
        (path / "key.pem").chmod(0o644)
        (path / "token").write_text("synthetic-not-a-kubernetes-credential")
        (path / "ca.crt").write_bytes((path / "cert.pem").read_bytes())
        container = run("docker", "run", "-d", "--platform", "linux/amd64", "--network", "none",
                        "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                        "-e", "KUBERNETES_SERVICE_HOST=127.0.0.1", "-e", "KUBERNETES_SERVICE_PORT=8444",
                        "-v", f"{path}:/var/run/secrets/kubernetes.io/serviceaccount:ro",
                        "-v", f"{path}:/fixture:ro", INJECTOR, "agent-inject",
                        "-listen=0.0.0.0:8080", "-tls-cert-file=/fixture/cert.pem",
                        "-tls-ca-cert-file=/fixture/cert.pem",
                        "-tls-key-file=/fixture/key.pem", "-vault-address=https://vault.synthetic:8200",
                        f"-vault-image={AGENT}")
        mock = ""
        try:
            # Even disk TLS waits for the webhook informer cache. This mock
            # supplies only an empty webhook list/watch, never a real cluster.
            mock_code = r'''
import json, ssl, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.headers.get('Authorization') != 'Bearer synthetic-not-a-kubernetes-credential':
            self.send_error(403); return
        if self.path.split('?')[0] != '/apis/admissionregistration.k8s.io/v1/mutatingwebhookconfigurations':
            self.send_error(404); return
        self.send_response(200); self.send_header('Content-Type', 'application/json'); self.end_headers()
        if 'watch=true' in self.path:
            self.wfile.write(json.dumps({'type':'BOOKMARK','object':{
                'apiVersion':'admissionregistration.k8s.io/v1','kind':'MutatingWebhookConfiguration',
                'metadata':{'resourceVersion':'1','annotations':{'k8s.io/initial-events-end':'true'}}}}).encode()+b'\n')
            self.wfile.flush(); time.sleep(30); return
        self.wfile.write(json.dumps({'apiVersion':'admissionregistration.k8s.io/v1',
            'kind':'MutatingWebhookConfigurationList','metadata':{'resourceVersion':'1'},'items':[]}).encode())
    def log_message(self, *_): pass
server = ThreadingHTTPServer(('127.0.0.1',8444), Handler)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain('/fixture/cert.pem','/fixture/key.pem')
server.socket = context.wrap_socket(server.socket,server_side=True)
server.serve_forever()
'''
            mock = run("docker", "run", "-d", "--platform", "linux/amd64", "--network", f"container:{container}",
                       "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                       "-v", f"{path}:/fixture:ro", "--entrypoint", "python3", PYTHON, "-c", mock_code)
            probe = r'''
import json, ssl, sys, time, urllib.request, urllib.error
context = ssl.create_default_context(cafile='/fixture/cert.pem')
payload = sys.stdin.buffer.read()
for attempt in range(30):
    try:
        request = urllib.request.Request('https://localhost:8080/mutate', data=payload,
                                         headers={'Content-Type':'application/json'})
        with urllib.request.urlopen(request, context=context, timeout=2) as response:
            print(response.read().decode()); break
    except urllib.error.HTTPError as error:
        print(json.dumps({'http_error':error.code})); break
    except urllib.error.URLError:
        if attempt == 29: raise
        time.sleep(0.2)
'''

            def admit(pod):
                review = {"apiVersion": "admission.k8s.io/v1", "kind": "AdmissionReview", "request": {
                    "uid": "synthetic-request", "kind": {"group": "", "version": "v1", "kind": "Pod"},
                    "resource": {"group": "", "version": "v1", "resource": "pods"},
                    "namespace": "synthetic", "operation": "CREATE", "object": pod}}
                return json.loads(run("docker", "run", "--rm", "-i", "--platform", "linux/amd64",
                    "--network", f"container:{container}", "--read-only", "--cap-drop", "ALL",
                    "--security-opt", "no-new-privileges", "-v", f"{path}:/fixture:ro",
                    "--entrypoint", "python3", PYTHON, "-c", probe, input=json.dumps(review)))

            pod = {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "synthetic", "namespace": "synthetic"},
                   "spec": {"serviceAccountName": "synthetic", "containers": [{"name": "app", "image": PYTHON}],
                            "volumes": [{"name": "kube-api-access-fixture", "projected": {"sources": [
                                {"serviceAccountToken": {"path": "token", "expirationSeconds": 600}}]}}]}}
            pod["spec"]["containers"][0]["volumeMounts"] = [{"name": "kube-api-access-fixture",
                "mountPath": "/var/run/secrets/kubernetes.io/serviceaccount", "readOnly": True}]
            response = admit(pod)["response"]
            assert response["uid"] == "synthetic-request" and response["allowed"] is True
            assert not response.get("patch"), "unannotated Pod unexpectedly mutated"
            pod["metadata"]["annotations"] = {"vault.hashicorp.com/agent-inject": "true",
                "vault.hashicorp.com/role": "synthetic-role", "vault.hashicorp.com/agent-inject-secret-test": "secret/data/synthetic"}
            response = admit(pod)["response"]
            assert response["allowed"] is True and response["patchType"] == "JSONPatch", response
            patch = json.loads(base64.b64decode(response["patch"]))

            def objects(value):
                if isinstance(value, dict):
                    yield value
                    for child in value.values():
                        yield from objects(child)
                elif isinstance(value, list):
                    for child in value:
                        yield from objects(child)

            agents = [item for item in objects(patch) if item.get("name") in ("vault-agent-init", "vault-agent") and "image" in item]
            assert {item["name"] for item in agents} == {"vault-agent-init", "vault-agent"}
            for agent in agents:
                assert agent["image"] == AGENT
                config = json.loads(base64.b64decode(next(env["value"] for env in agent["env"] if env["name"] == "VAULT_CONFIG")))
                assert config["vault"]["address"] == "https://vault.synthetic:8200"
                assert config["auto_auth"]["method"]["type"] == "kubernetes"
                assert config["auto_auth"]["method"]["config"]["role"] == "synthetic-role"
                assert not config["vault"].get("tls_skip_verify", False)
                assert agent["securityContext"]["runAsNonRoot"] is True
            pod["metadata"]["annotations"]["vault.hashicorp.com/agent-inject"] = "invalid-boolean"
            rejected = admit(pod)
            assert rejected.get("http_error", 0) >= 400 or rejected.get("response", {}).get("allowed") is False
            print(json.dumps({"injector": INJECTOR, "agent": AGENT, "unannotated_unchanged": True,
                              "annotated_patch_generated": True, "patch_operations": len(patch),
                              "exact_agent_config_checked": True, "invalid_annotation_rejected": True,
                              "live_admission_verified": False}))
        except Exception:
            logs = subprocess.run(["docker", "logs", container], text=True, capture_output=True)
            print((logs.stdout + logs.stderr)[-4000:])
            raise
        finally:
            try:
                if mock:
                    run("docker", "rm", "-f", mock)
            finally:
                run("docker", "rm", "-f", container)


if __name__ == "__main__":
    main()
